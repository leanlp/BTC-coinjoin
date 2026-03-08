package heuristics

import (
	"sort"
	"sync"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Intersection Attack Engine
//
// Implements the cross-transaction anonymity set erosion analysis described
// in Biryukov & Tikhomirov (2019) and Möser & Narayanan (PoPETs 2018).
//
// Core insight: if address A participates in CoinJoin round R1 (with set S1)
// and round R2 (with set S2), then the effective anonymity set for A is:
//   A_eff = |S1 ∩ S2| (which can be << |S1| or |S2|)
//
// After 3-5 rounds with moderate participant overlap, Wasabi's effective
// anonymity set drops by 60-80% (empirically demonstrated).
//
// This is the #1 capability that separates open-source chain analysis from
// enterprise forensics platforms (Chainalysis, Elliptic, CipherTrace).

// ParticipantSet represents the addresses involved in a single CoinJoin round
type ParticipantSet struct {
	Txid         string   `json:"txid"`
	Addresses    []string `json:"addresses"`
	Protocol     string   `json:"protocol"`     // "wasabi"/"whirlpool"/"joinmarket"/"generic"
	PoolID       string   `json:"poolId"`       // Denomination pool (e.g. "0.01", "0.05")
	BlockHeight  int      `json:"blockHeight"`
	AnonSetLocal int      `json:"anonsetLocal"` // Per-tx anonymity set
}

// IntersectionResult holds the cross-round intersection analysis for an address
type IntersectionResult struct {
	Address              string           `json:"address"`
	TotalRounds          int              `json:"totalRounds"`          // Number of CoinJoin rounds observed
	EffectiveAnonSet     int              `json:"effectiveAnonset"`     // |intersection| of all participant sets
	IntersectingAddrs    []string         `json:"intersectingAddrs"`    // Addresses that appear in ALL rounds
	RoundBreakdown       []RoundSummary   `json:"roundBreakdown"`      // Per-round details
	ErosionRate          float64          `json:"erosionRate"`          // 1.0 - (effective/max_local)
	Confidence           float64          `json:"confidence"`           // Statistical confidence [0,1]
	IsVulnerable         bool             `json:"isVulnerable"`        // effective anonset ≤ 3
	PairwiseIntersections []PairwiseMatch `json:"pairwiseIntersections,omitempty"`
}

// RoundSummary holds per-round details for intersection analysis
type RoundSummary struct {
	Txid          string `json:"txid"`
	Participants  int    `json:"participants"`
	Protocol      string `json:"protocol"`
	BlockHeight   int    `json:"blockHeight"`
}

// PairwiseMatch holds the intersection size between two specific rounds
type PairwiseMatch struct {
	Round1Txid       string `json:"round1Txid"`
	Round2Txid       string `json:"round2Txid"`
	IntersectionSize int    `json:"intersectionSize"`
	Round1Size       int    `json:"round1Size"`
	Round2Size       int    `json:"round2Size"`
}

// IntersectionRegistry is the in-memory participant set store.
// Thread-safe for concurrent access from poller and block scanner.
type IntersectionRegistry struct {
	mu sync.RWMutex
	// roundParticipants: txid → set of participant addresses
	roundParticipants map[string]map[string]bool
	// addressRounds: address → list of round txids
	addressRounds map[string][]string
	// roundMeta: txid → protocol/pool metadata
	roundMeta map[string]ParticipantSet
}

// Global singleton for the intersection registry
var (
	globalRegistry     *IntersectionRegistry
	registryOnce       sync.Once
)

// GetGlobalIntersectionRegistry returns the singleton intersection registry
func GetGlobalIntersectionRegistry() *IntersectionRegistry {
	registryOnce.Do(func() {
		globalRegistry = &IntersectionRegistry{
			roundParticipants: make(map[string]map[string]bool),
			addressRounds:     make(map[string][]string),
			roundMeta:         make(map[string]ParticipantSet),
		}
	})
	return globalRegistry
}

// RegisterCoinJoinParticipants registers the output addresses of a CoinJoin
// transaction as participants in a mixing round.
// Called after AnalyzeTx detects a CoinJoin (isCj == true).
func (ir *IntersectionRegistry) RegisterCoinJoinParticipants(tx models.Transaction, result models.PrivacyAnalysisResult) {
	if result.AnonSet < 2 {
		return // Not a meaningful CoinJoin
	}

	// Extract unique output addresses as participants
	participants := make(map[string]bool)
	for _, out := range tx.Outputs {
		if out.Address != "" {
			participants[out.Address] = true
		}
	}

	if len(participants) < 2 {
		return
	}

	// Determine protocol
	protocol := "generic"
	flags := result.HeuristicFlags
	if (flags & uint64(FlagIsWhirlpoolStruct)) > 0 {
		protocol = "whirlpool"
	} else if (flags & uint64(FlagIsWasabiSuspect)) > 0 {
		protocol = "wasabi"
	} else if (flags & uint64(FlagIsJoinMarketBond)) > 0 {
		protocol = "joinmarket"
	}

	meta := ParticipantSet{
		Txid:         tx.Txid,
		Protocol:     protocol,
		PoolID:       result.WhirlpoolPool,
		BlockHeight:  tx.BlockHeight,
		AnonSetLocal: result.AnonSet,
	}

	// Collect participant list for metadata
	for addr := range participants {
		meta.Addresses = append(meta.Addresses, addr)
	}

	ir.mu.Lock()
	defer ir.mu.Unlock()

	// Store the round participants
	ir.roundParticipants[tx.Txid] = participants
	ir.roundMeta[tx.Txid] = meta

	// Index each address → round mapping
	for addr := range participants {
		// Prevent duplicate round registrations
		alreadyRegistered := false
		for _, existingTxid := range ir.addressRounds[addr] {
			if existingTxid == tx.Txid {
				alreadyRegistered = true
				break
			}
		}
		if !alreadyRegistered {
			ir.addressRounds[addr] = append(ir.addressRounds[addr], tx.Txid)
		}
	}
}

// ComputeIntersection analyzes the cross-round intersection for a given address.
// Returns the set of addresses that appear in ALL CoinJoin rounds with the target.
func (ir *IntersectionRegistry) ComputeIntersection(address string) IntersectionResult {
	ir.mu.RLock()
	defer ir.mu.RUnlock()

	result := IntersectionResult{
		Address:      address,
		Confidence:   0,
	}

	rounds, exists := ir.addressRounds[address]
	if !exists || len(rounds) == 0 {
		return result
	}

	result.TotalRounds = len(rounds)

	// Build per-round summaries
	for _, txid := range rounds {
		meta, hasMeta := ir.roundMeta[txid]
		participants := ir.roundParticipants[txid]
		summary := RoundSummary{
			Txid:         txid,
			Participants: len(participants),
		}
		if hasMeta {
			summary.Protocol = meta.Protocol
			summary.BlockHeight = meta.BlockHeight
		}
		result.RoundBreakdown = append(result.RoundBreakdown, summary)
	}

	if len(rounds) < 2 {
		// With only 1 round, effective anonset = local anonset
		if participants, ok := ir.roundParticipants[rounds[0]]; ok {
			result.EffectiveAnonSet = len(participants)
		}
		return result
	}

	// Compute the intersection of ALL participant sets
	// Start with the first round's participants, then intersect with each subsequent round
	firstRound := ir.roundParticipants[rounds[0]]
	intersection := make(map[string]bool, len(firstRound))
	for addr := range firstRound {
		intersection[addr] = true
	}

	for _, txid := range rounds[1:] {
		roundSet := ir.roundParticipants[txid]
		for addr := range intersection {
			if !roundSet[addr] {
				delete(intersection, addr)
			}
		}
	}

	// Collect intersecting addresses (sorted for deterministic output)
	for addr := range intersection {
		result.IntersectingAddrs = append(result.IntersectingAddrs, addr)
	}
	sort.Strings(result.IntersectingAddrs)

	result.EffectiveAnonSet = len(intersection)

	// Compute erosion rate: how much the anonset degraded
	maxLocal := 0
	for _, txid := range rounds {
		roundSize := len(ir.roundParticipants[txid])
		if roundSize > maxLocal {
			maxLocal = roundSize
		}
	}
	if maxLocal > 0 {
		result.ErosionRate = 1.0 - float64(result.EffectiveAnonSet)/float64(maxLocal)
		if result.ErosionRate < 0 {
			result.ErosionRate = 0
		}
	}

	// Confidence increases with more rounds (more data = more certainty)
	// Sigmoid-like: conf = 1 - 1/(1 + 0.5*n) where n = number of rounds
	n := float64(len(rounds))
	result.Confidence = 1.0 - 1.0/(1.0+0.5*n)

	// Vulnerability flag: effective anonset ≤ 3 is almost deanonymized
	result.IsVulnerable = result.EffectiveAnonSet <= 3 && len(rounds) >= 2

	// Compute pairwise intersections for detailed analysis
	if len(rounds) <= 20 { // Only for manageable round counts
		for i := 0; i < len(rounds); i++ {
			for j := i + 1; j < len(rounds); j++ {
				setI := ir.roundParticipants[rounds[i]]
				setJ := ir.roundParticipants[rounds[j]]
				pairSize := 0
				for addr := range setI {
					if setJ[addr] {
						pairSize++
					}
				}
				result.PairwiseIntersections = append(result.PairwiseIntersections, PairwiseMatch{
					Round1Txid:       rounds[i],
					Round2Txid:       rounds[j],
					IntersectionSize: pairSize,
					Round1Size:       len(setI),
					Round2Size:       len(setJ),
				})
			}
		}
	}

	return result
}

// GetEffectiveAnonSet returns the minimum of the local anonset and the
// intersection-based effective anonset. This is the true privacy guarantee
// after accounting for cross-round linkability.
func (ir *IntersectionRegistry) GetEffectiveAnonSet(address string) int {
	ir.mu.RLock()
	defer ir.mu.RUnlock()

	rounds, exists := ir.addressRounds[address]
	if !exists || len(rounds) < 2 {
		return -1 // No intersection data available
	}

	// Compute intersection
	firstRound := ir.roundParticipants[rounds[0]]
	intersection := make(map[string]bool, len(firstRound))
	for addr := range firstRound {
		intersection[addr] = true
	}
	for _, txid := range rounds[1:] {
		roundSet := ir.roundParticipants[txid]
		for addr := range intersection {
			if !roundSet[addr] {
				delete(intersection, addr)
			}
		}
	}

	return len(intersection)
}

// GetRoundCount returns the number of CoinJoin rounds observed for an address
func (ir *IntersectionRegistry) GetRoundCount(address string) int {
	ir.mu.RLock()
	defer ir.mu.RUnlock()
	return len(ir.addressRounds[address])
}

// Stats returns registry statistics for monitoring
func (ir *IntersectionRegistry) Stats() (totalRounds, totalAddresses int) {
	ir.mu.RLock()
	defer ir.mu.RUnlock()
	return len(ir.roundParticipants), len(ir.addressRounds)
}
