package heuristics

import (
	"math"
	"strings"
	"sync"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Cross-Chain Bridge Detection
// ═══════════════════════════════════════════════════════════════════════

// CrossChainBridgeResult detects if a transaction is related to cross-chain activity
type CrossChainBridgeResult struct {
	IsBridgeRelated bool     `json:"isBridgeRelated"`
	BridgeType      string   `json:"bridgeType,omitempty"` // "wbtc_custody", "generic_bridge", "atomic_swap"
	Indicators      []string `json:"indicators,omitempty"`
	Confidence      float64  `json:"confidence"`
}

// Known cross-chain bridge / wrap address patterns (mainnet)
var knownBridgePatterns = map[string]string{
	"bc1qwbtc": "wbtc_custody",
	"3Bridge":  "generic_bridge",
}

// DetectCrossChainBridge checks for bridge/wrap transaction indicators
func DetectCrossChainBridge(tx models.Transaction) CrossChainBridgeResult {
	result := CrossChainBridgeResult{}
	var indicators []string

	// Check 1: OP_RETURN with metadata (bridge protocols embed cross-chain data)
	for _, out := range tx.Outputs {
		if out.Value == 0 && out.ScriptPubKey != "" {
			if strings.Contains(out.ScriptPubKey, "6a") {
				indicators = append(indicators, "op_return_metadata")
			}
		}
	}

	// Check 2: Known bridge address patterns
	for _, out := range tx.Outputs {
		for pattern, bridgeType := range knownBridgePatterns {
			if strings.HasPrefix(out.Address, pattern) {
				result.BridgeType = bridgeType
				indicators = append(indicators, "known_bridge_address")
			}
		}
	}

	// Check 3: Atomic swap structure (1:1 with script hash)
	if len(tx.Inputs) == 1 && len(tx.Outputs) == 1 {
		out := tx.Outputs[0]
		if strings.HasPrefix(out.Address, "3") || strings.HasPrefix(out.Address, "bc1q") {
			indicators = append(indicators, "possible_atomic_swap_structure")
		}
	}

	// Check 4: Block-height based timelock (HTLC pattern)
	if tx.LockTime > 0 && tx.LockTime < 500000000 {
		indicators = append(indicators, "timelock_present")
	}

	if len(indicators) >= 2 {
		result.IsBridgeRelated = true
		result.Indicators = indicators
		result.Confidence = math.Min(float64(len(indicators))*0.25, 0.90)
	}

	return result
}

// ═══════════════════════════════════════════════════════════════════════
// Enhanced Mempool Timing Correlation
// ═══════════════════════════════════════════════════════════════════════

// BroadcastCorrelation tracks broadcast timing for entity linking
type BroadcastCorrelation struct {
	TxID          string   `json:"txid"`
	FirstSeenAt   int64    `json:"firstSeenAt"`
	CorrelatedTxs []string `json:"correlatedTxs"`
}

// MempoolCorrelator groups transactions by broadcast timing
type MempoolCorrelator struct {
	mu          sync.RWMutex
	txTimes     map[string]int64
	batchWindow int64 // ms
}

var (
	globalMempoolCorrelator *MempoolCorrelator
	mempoolCorrelatorOnce   sync.Once
)

// GetGlobalMempoolCorrelator returns the singleton correlator
func GetGlobalMempoolCorrelator() *MempoolCorrelator {
	mempoolCorrelatorOnce.Do(func() {
		globalMempoolCorrelator = &MempoolCorrelator{
			txTimes:     make(map[string]int64),
			batchWindow: 2000, // 2 second window
		}
	})
	return globalMempoolCorrelator
}

// RecordBroadcast records when a tx was first seen in mempool
func (mc *MempoolCorrelator) RecordBroadcast(txid string, timestampMs int64) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.txTimes[txid] = timestampMs
}

// FindCorrelatedBroadcasts finds txs broadcast within the batch window
func (mc *MempoolCorrelator) FindCorrelatedBroadcasts(txid string) []string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	targetTime, exists := mc.txTimes[txid]
	if !exists {
		return nil
	}

	var correlated []string
	for otherTxid, otherTime := range mc.txTimes {
		if otherTxid == txid {
			continue
		}
		delta := otherTime - targetTime
		if delta < 0 {
			delta = -delta
		}
		if delta <= mc.batchWindow {
			correlated = append(correlated, otherTxid)
		}
	}

	return correlated
}

// ═══════════════════════════════════════════════════════════════════════
// Post-Mix Effectiveness Score (combines all signals)
// ═══════════════════════════════════════════════════════════════════════

// ComputePostMixEffectiveness combines all post-mix signals into a
// single 0-1 score for the PrivacyAnalysisResult.PostMixScore field
func ComputePostMixEffectiveness(tx models.Transaction, result *models.PrivacyAnalysisResult) float64 {
	if result == nil {
		return 0
	}

	score := 1.0

	// Factor 1: Privacy score (normalized)
	if result.PrivacyScore < 50 {
		score *= float64(result.PrivacyScore) / 50.0
	}

	// Factor 2: Intersection vulnerability
	if (result.HeuristicFlags & uint64(FlagIntersectionVulnerable)) > 0 {
		score *= 0.5
	}

	// Factor 3: Post-mix leakage
	if (result.HeuristicFlags & uint64(FlagPostMixLeakage)) > 0 {
		score *= 0.3
	}

	// Factor 4: Self-spend (internal movement = no privacy loss)
	if (result.HeuristicFlags & uint64(FlagSelfSpend)) > 0 {
		score *= 1.2
		if score > 1 {
			score = 1
		}
	}

	// Factor 5: Anonset quality
	if result.AnonSet > 0 {
		anonFactor := math.Log2(float64(result.AnonSet+1)) / 10.0
		if anonFactor > 1 {
			anonFactor = 1
		}
		score *= (0.5 + 0.5*anonFactor)
	}

	return math.Max(0, math.Min(score, 1.0))
}
