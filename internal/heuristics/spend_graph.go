package heuristics

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// UTXO Spend-Graph Engine
//
// With a full Bitcoin node, we can query the ENTIRE spending history of any
// address or output. This unlocks forensics capabilities impossible with
// per-transaction analysis alone:
//
//   1. Spending-First Change Detection: "Which output was spent first?
//      The first-spent output is HIGHLY likely to be the payment, not change."
//      (Chainalysis patent US11,188,977 — Section 3.2)
//
//   2. Input Age Disparity: If one input is 3 years old and another is 1 day,
//      they almost certainly belong to the same entity (who would combine them?).
//
//   3. Address Reuse Graph: Build the complete transaction graph for an entity,
//      revealing spending patterns, timing, and counterparties.
//
//   4. Self-Spend Detection: When ALL outputs go to addresses that appeared
//      in the inputs of a PREVIOUS transaction from this entity — it's a
//      self-transfer (consolidation or internal treasury movement).
//
// References:
//   - Ermilov et al., "Automatic Bitcoin Address Clustering" (MDPI 2017)
//   - Nick, "Data-Driven De-Anonymization in Bitcoin" (Master thesis, ETH 2015)
//   - Chainalysis, US Patent 11,188,977 "Systems for identifying illicit actors"

// SpendInfo records when and how an output was spent
type SpendInfo struct {
	SpentInTxid   string    `json:"spentInTxid"`   // Txid that spent this output
	SpentAtBlock  int64     `json:"spentAtBlock"`   // Block height where it was spent
	SpentTime     time.Time `json:"spentTime"`      // Timestamp of spending block
	TimeToSpend   int64     `json:"timeToSpend"`    // Seconds from creation to spending
	IsUnspent     bool      `json:"isUnspent"`      // Still in UTXO set
}

// OutputSpendProfile holds spend analysis for all outputs of a transaction
type OutputSpendProfile struct {
	TxID             string            `json:"txid"`
	Outputs          []OutputSpendInfo `json:"outputs"`
	FirstSpentIndex  int               `json:"firstSpentIndex"`  // Which output was spent first
	LastSpentIndex   int               `json:"lastSpentIndex"`   // Which output was spent last
	SpendOrderReliable bool            `json:"spendOrderReliable"` // True if >1 hour gap between first/second spend
	ChangeCandidate  int               `json:"changeCandidate"`  // Index most likely to be change
	ChangeConfidence float64           `json:"changeConfidence"` // Confidence in change detection
	ChangeMethod     string            `json:"changeMethod"`     // Detection method used
}

// OutputSpendInfo holds spend details for a single output
type OutputSpendInfo struct {
	Index        int        `json:"index"`
	Value        int64      `json:"value"`
	Address      string     `json:"address"`
	SpendInfo    *SpendInfo `json:"spendInfo,omitempty"`
	SpendOrder   int        `json:"spendOrder"` // 1 = first spent, 2 = second, etc.
}

// AnalyzeSpendOrder determines which output was spent first.
// This is the most powerful change detection heuristic:
//   - "First-Spent-First-Payment" (FSFP): The output spent soonest
//     after creation is overwhelmingly likely to be the payment.
//   - The remaining output is the change (kept by the sender).
//
// Requires prevout data from the full node (SpendInfo populated externally).
func AnalyzeSpendOrder(tx models.Transaction, spendData map[int]*SpendInfo) OutputSpendProfile {
	profile := OutputSpendProfile{
		TxID:            tx.Txid,
		ChangeCandidate: -1,
		FirstSpentIndex: -1,
		LastSpentIndex:  -1,
	}

	// Build output spend info list
	type spendEntry struct {
		index   int
		spent   bool
		timeToSpend int64
	}

	var entries []spendEntry
	for i, out := range tx.Outputs {
		osi := OutputSpendInfo{
			Index:   i,
			Value:   out.Value,
			Address: out.Address,
		}

		if info, ok := spendData[i]; ok {
			osi.SpendInfo = info
			if !info.IsUnspent {
				entries = append(entries, spendEntry{
					index: i, spent: true, timeToSpend: info.TimeToSpend,
				})
			}
		}
		profile.Outputs = append(profile.Outputs, osi)
	}

	if len(entries) < 2 {
		return profile
	}

	// Sort by time-to-spend (ascending)
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].timeToSpend < entries[b].timeToSpend
	})

	// Assign spend order
	for rank, entry := range entries {
		profile.Outputs[entry.index].SpendOrder = rank + 1
	}

	profile.FirstSpentIndex = entries[0].index
	profile.LastSpentIndex = entries[len(entries)-1].index

	// FSFP heuristic: first spent = payment, last spent = change
	// Confidence depends on time gap between first and second spend
	if len(entries) >= 2 {
		timeGap := entries[1].timeToSpend - entries[0].timeToSpend
		profile.SpendOrderReliable = timeGap > 3600 // >1 hour gap

		// Change = the output NOT spent first (most likely the last)
		profile.ChangeCandidate = entries[len(entries)-1].index
		profile.ChangeMethod = "first_spent_first_payment"

		// Confidence based on gap magnitude
		switch {
		case timeGap > 86400: // >1 day gap
			profile.ChangeConfidence = 0.95
		case timeGap > 3600: // >1 hour gap
			profile.ChangeConfidence = 0.85
		case timeGap > 600: // >10 min gap
			profile.ChangeConfidence = 0.70
		default:
			profile.ChangeConfidence = 0.50
		}
	}

	return profile
}

// InputAgeDisparity computes the age spread of inputs.
// Large age disparity = strong evidence of same-entity ownership.
// If you mix a 5-year-old UTXO with a 1-day-old UTXO, you DEFINITELY
// own both — nobody else would combine them.
type AgeDisparity struct {
	MinAgeDays    float64 `json:"minAgeDays"`    // Youngest input
	MaxAgeDays    float64 `json:"maxAgeDays"`    // Oldest input
	MedianAgeDays float64 `json:"medianAgeDays"` // Median input age
	SpreadDays    float64 `json:"spreadDays"`    // Max - Min
	Coefficient   float64 `json:"coefficient"`   // Spread / Median (normalized)
	SameEntity    bool    `json:"sameEntity"`    // High confidence same entity?
	Confidence    float64 `json:"confidence"`    // [0, 1]
}

// ComputeAgeDisparity analyzes input age spread for entity resolution.
func ComputeAgeDisparity(inputAges []float64) AgeDisparity {
	result := AgeDisparity{}

	if len(inputAges) < 2 {
		return result
	}

	sorted := make([]float64, len(inputAges))
	copy(sorted, inputAges)
	sort.Float64s(sorted)

	result.MinAgeDays = sorted[0]
	result.MaxAgeDays = sorted[len(sorted)-1]
	result.SpreadDays = result.MaxAgeDays - result.MinAgeDays

	// Median
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		result.MedianAgeDays = (sorted[mid-1] + sorted[mid]) / 2
	} else {
		result.MedianAgeDays = sorted[mid]
	}

	// Coefficient of variation (spread)
	if result.MedianAgeDays > 0 {
		result.Coefficient = result.SpreadDays / result.MedianAgeDays
	}

	// Same-entity detection:
	// If age spread > 30 days, it's extremely unlikely that different entities
	// would combine UTXOs of such different ages in a single transaction.
	switch {
	case result.SpreadDays > 365: // >1 year spread
		result.SameEntity = true
		result.Confidence = 0.98
	case result.SpreadDays > 90: // >3 months spread
		result.SameEntity = true
		result.Confidence = 0.92
	case result.SpreadDays > 30: // >1 month spread
		result.SameEntity = true
		result.Confidence = 0.80
	case result.SpreadDays > 7: // >1 week spread
		result.SameEntity = true
		result.Confidence = 0.65
	default:
		result.SameEntity = false
		result.Confidence = 0.40
	}

	return result
}

// CoinJoinRoundTracker tracks participant behavior across CoinJoin rounds.
// With full node access, we can reconstruct the complete mixing history
// of any output: which rounds it went through, when, and with whom.
type CoinJoinRoundTracker struct {
	mu          sync.RWMutex
	roundIndex  map[string][]RoundParticipation // address → rounds participated in
	denomPools  map[int64][]string              // denomination → txids using it
}

// RoundParticipation records an address's involvement in a CoinJoin round
type RoundParticipation struct {
	TxID          string    `json:"txid"`
	BlockHeight   int64     `json:"blockHeight"`
	Timestamp     time.Time `json:"timestamp"`
	Protocol      string    `json:"protocol"`      // "whirlpool"/"wasabi"/"joinmarket"
	Denomination  int64     `json:"denomination"`   // Pool denomination in sats
	IsRemix       bool      `json:"isRemix"`        // Was this a remix (output of prev round used as input)?
	AnonSetGained int       `json:"anonSetGained"`  // Per-round anonset
	InputIndex    int       `json:"inputIndex"`
	OutputIndex   int       `json:"outputIndex"`
}

// MixingHistory summarizes an address's complete mixing path
type MixingHistory struct {
	Address           string               `json:"address"`
	TotalRounds       int                  `json:"totalRounds"`
	TotalRemixes      int                  `json:"totalRemixes"`
	CumulativeAnonSet int                  `json:"cumulativeAnonSet"`  // Product of per-round anonsets
	EffectiveAnonSet  int                  `json:"effectiveAnonSet"`   // After intersection attack
	FirstSeen         time.Time            `json:"firstSeen"`
	LastSeen          time.Time            `json:"lastSeen"`
	Protocols         []string             `json:"protocols"`          // Which protocols used
	Rounds            []RoundParticipation `json:"rounds"`
	IsVulnerable      bool                 `json:"isVulnerable"`       // Intersection attack eroded anonset significantly
}

var (
	globalRoundTracker *CoinJoinRoundTracker
	roundTrackerOnce   sync.Once
)

// GetGlobalRoundTracker returns the singleton CoinJoin round tracker
func GetGlobalRoundTracker() *CoinJoinRoundTracker {
	roundTrackerOnce.Do(func() {
		globalRoundTracker = &CoinJoinRoundTracker{
			roundIndex: make(map[string][]RoundParticipation),
			denomPools: make(map[int64][]string),
		}
	})
	return globalRoundTracker
}

// RecordRound adds a CoinJoin round participation record
func (rt *CoinJoinRoundTracker) RecordRound(addr string, round RoundParticipation) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.roundIndex[addr] = append(rt.roundIndex[addr], round)
	rt.denomPools[round.Denomination] = append(rt.denomPools[round.Denomination], round.TxID)
}

// GetMixingHistory reconstructs an address's complete mixing history
func (rt *CoinJoinRoundTracker) GetMixingHistory(addr string) MixingHistory {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	rounds := rt.roundIndex[addr]
	if len(rounds) == 0 {
		return MixingHistory{Address: addr}
	}

	history := MixingHistory{
		Address:     addr,
		TotalRounds: len(rounds),
		Rounds:      rounds,
	}

	// Compute cumulative anonset (product of per-round anonsets)
	cumulativeAnonSet := 1.0
	protocolSet := make(map[string]bool)

	for _, round := range rounds {
		if round.AnonSetGained > 0 {
			cumulativeAnonSet *= float64(round.AnonSetGained)
		}
		if round.IsRemix {
			history.TotalRemixes++
		}
		protocolSet[round.Protocol] = true

		if history.FirstSeen.IsZero() || round.Timestamp.Before(history.FirstSeen) {
			history.FirstSeen = round.Timestamp
		}
		if round.Timestamp.After(history.LastSeen) {
			history.LastSeen = round.Timestamp
		}
	}

	// Cap cumulative anonset to prevent overflow
	if cumulativeAnonSet > 1e9 {
		cumulativeAnonSet = 1e9
	}
	history.CumulativeAnonSet = int(cumulativeAnonSet)

	for p := range protocolSet {
		history.Protocols = append(history.Protocols, p)
	}

	// Cross-reference with intersection engine for effective anonset
	registry := GetGlobalIntersectionRegistry()
	effective := registry.GetEffectiveAnonSet(addr)
	if effective > 0 {
		history.EffectiveAnonSet = effective
		if effective <= 3 {
			history.IsVulnerable = true
		}
	} else {
		history.EffectiveAnonSet = history.CumulativeAnonSet
	}

	return history
}

// GetDenominationPoolSize returns how many CoinJoin rounds used a specific denomination
func (rt *CoinJoinRoundTracker) GetDenominationPoolSize(denomination int64) int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.denomPools[denomination])
}

// ConfidenceWeightedScore combines multiple heuristic scores using a
// confidence-weighted geometric mean. This produces more stable scores
// than arithmetic averaging because it penalizes low-confidence signals
// more aggressively.
//
// Used for final privacy score composition when full-node data is available.
func ConfidenceWeightedScore(scores []float64, confidences []float64) float64 {
	if len(scores) == 0 || len(scores) != len(confidences) {
		return 0
	}

	totalWeight := 0.0
	logSum := 0.0

	for i := range scores {
		w := confidences[i]
		if w <= 0 || scores[i] <= 0 {
			continue
		}
		totalWeight += w
		logSum += w * math.Log(scores[i])
	}

	if totalWeight <= 0 {
		return 0
	}

	// Geometric mean: exp(Σ wᵢ·log(sᵢ) / Σ wᵢ)
	return math.Exp(logSum / totalWeight)
}
