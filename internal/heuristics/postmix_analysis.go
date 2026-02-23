package heuristics

import (
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Post-Mix Spend Analysis
//
// The single biggest failure mode in CoinJoin privacy: what users do
// AFTER mixing. Even a perfect Whirlpool 5×5 (anonSet=1496) is worthless
// if the user immediately:
//   1. Consolidates multiple mixed UTXOs into one tx (cross-mix linking)
//   2. Sends to a known exchange deposit address
//   3. Reuses an address from before the mix
//   4. Creates a peel chain from the mixed output
//
// Chainalysis has publicly stated that post-mix behavior is their
// primary method for de-anonymizing CoinJoin users.
//
// References:
//   - Möser & Narayanan, "Obfuscation in Bitcoin" (2017)
//   - Kappos et al., "An Empirical Analysis of Anonymity in Zcash" (2018)
//   - OXT Research, "Understanding Whirlpool Post-Mix Spending" (2021)

// PostMixResult holds the analysis of post-mix spending behavior
type PostMixResult struct {
	IsPostMixTx        bool    `json:"isPostMixTx"`        // Transaction spends CoinJoin outputs
	LeakageType        string  `json:"leakageType"`        // "none"/"consolidation"/"address-reuse"/"peel"/"exchange-deposit"
	SeverityScore      float64 `json:"severityScore"`      // 0.0 (no leakage) to 1.0 (total deanonymization)
	MixedInputCount    int     `json:"mixedInputCount"`    // How many inputs come from CoinJoin outputs
	NonMixedInputCount int     `json:"nonMixedInputCount"` // How many inputs are NOT from CoinJoins
	PrivacyDestroyed   bool    `json:"privacyDestroyed"`   // True if the mix benefit is completely negated
	Recommendation     string  `json:"recommendation"`     // "safe"/"caution"/"unsafe"/"critical"
}

// AnalyzePostMixBehavior examines a transaction for privacy-destroying
// patterns that negate the benefits of a prior CoinJoin.
func AnalyzePostMixBehavior(tx models.Transaction, inputFromCoinJoin []bool) PostMixResult {
	result := PostMixResult{
		LeakageType:    "none",
		Recommendation: "safe",
	}

	if len(inputFromCoinJoin) != len(tx.Inputs) {
		return result
	}

	// Count mixed vs non-mixed inputs
	for _, isMixed := range inputFromCoinJoin {
		if isMixed {
			result.MixedInputCount++
		} else {
			result.NonMixedInputCount++
		}
	}

	if result.MixedInputCount == 0 {
		return result // Not a post-mix transaction
	}

	result.IsPostMixTx = true

	// ─── Check for Cross-Mix Consolidation ────────────────────────────
	// If multiple mixed inputs are spent together, they are linked
	if result.MixedInputCount >= 2 {
		result.LeakageType = "consolidation"
		result.SeverityScore = 0.9
		result.PrivacyDestroyed = true
		result.Recommendation = "critical"
		return result
	}

	// ─── Check for Toxic Change (Mixed + Non-Mixed Inputs) ────────────
	// Spending a mixed input alongside a non-mixed input links them
	if result.MixedInputCount >= 1 && result.NonMixedInputCount >= 1 {
		result.LeakageType = "consolidation"
		result.SeverityScore = 0.95
		result.PrivacyDestroyed = true
		result.Recommendation = "critical"
		return result
	}

	// ─── Check for Peel Chain from Mixed Output ──────────────────────
	// Single mixed input → 2 outputs = potential peel (trackable)
	if result.MixedInputCount == 1 && len(tx.Outputs) == 2 {
		result.LeakageType = "peel"
		result.SeverityScore = 0.5
		result.Recommendation = "caution"
		return result
	}

	// ─── Check for Address Reuse ─────────────────────────────────────
	// Check if any output goes to an address that was used as input
	inputAddrs := make(map[string]bool)
	for _, in := range tx.Inputs {
		inputAddrs[in.Address] = true
	}
	for _, out := range tx.Outputs {
		if inputAddrs[out.Address] {
			result.LeakageType = "address-reuse"
			result.SeverityScore = 0.8
			result.PrivacyDestroyed = true
			result.Recommendation = "critical"
			return result
		}
	}

	// ─── Single Mixed → Single Output (Sweep to Exchange?) ───────────
	if result.MixedInputCount == 1 && len(tx.Outputs) == 1 {
		result.LeakageType = "exchange-deposit"
		result.SeverityScore = 0.6
		result.Recommendation = "unsafe"
		return result
	}

	return result
}

// DetectPrematureConsolidation identifies the worst post-mix behavior:
// spending multiple CoinJoin outputs in a single transaction.
// This is an instant deanonymization — it links all mixed UTXOs.
func DetectPrematureConsolidation(tx models.Transaction, inputFromCoinJoin []bool) bool {
	if len(inputFromCoinJoin) != len(tx.Inputs) {
		return false
	}

	mixedCount := 0
	for _, isMixed := range inputFromCoinJoin {
		if isMixed {
			mixedCount++
		}
	}

	return mixedCount >= 2
}

// ComputePostMixAnonSetErosion calculates how much an anonSet
// degrades due to post-mix behavior.
// originalAnonSet: the anonSet from the CoinJoin
// leakageSeverity: 0.0 to 1.0 from PostMixResult
// Returns the effective anonSet after leakage
func ComputePostMixAnonSetErosion(originalAnonSet int, leakageSeverity float64) int {
	if leakageSeverity <= 0 {
		return originalAnonSet
	}
	if leakageSeverity >= 1.0 {
		return 1
	}

	effective := float64(originalAnonSet) * (1.0 - leakageSeverity)
	if effective < 1 {
		return 1
	}
	return int(effective)
}
