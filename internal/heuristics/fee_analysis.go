package heuristics

import (
	"math"
	"sort"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Fee-Rate Intelligence Module
//
// Fee patterns are the strongest wallet fingerprinting signal after BIP69.
// Different wallet implementations use fundamentally different fee estimation
// strategies, fee rounding behaviors, and UTXO selection algorithms.
//
// Known wallet fee signatures:
//   - Bitcoin Core: rounds to 1 sat/vB boundaries, uses anti-fee-sniping nLockTime
//   - Electrum: precise coin-per-byte estimation, often fractional
//   - Wasabi 2.x (WabiSabi): coordinator sets fee, systematically overpays 10-30%
//   - Samourai (Whirlpool): fixed fee tiers per pool (5k/50k/100k/500k sats)
//   - Exchanges: fixed fee schedules (often 10 sat/vB or 20 sat/vB)
//   - Lightning: minimal fees (1-2 sat/vB for channel opens/closes)
//
// References:
//   - Möser & Narayanan, "Effective Crypto-Ransomware Detection" (NDSS 2022)
//   - Harrigan & Fretter, "The Unreasonable Effectiveness of Address Clustering" (IEEE 2016)
//   - Erdin et al., "How to Not Get Caught" (ESORICS 2023)

// AnalyzeFeePattern performs comprehensive fee-rate analysis on a transaction.
// It computes the fee rate, detects rounding patterns, identifies unnecessary
// inputs (revealing UTXO selection strategy), and infers the wallet family.
func AnalyzeFeePattern(tx models.Transaction) models.FeeAnalysisResult {
	result := models.FeeAnalysisResult{
		FeeRateClass:    "unknown",
		RoundingPattern: "none",
		WalletHint:      "unknown",
	}

	// 1. Compute fee rate (sat/vB)
	if tx.Vsize > 0 {
		result.FeeRate = math.Round(float64(tx.Fee)*100/float64(tx.Vsize)) / 100
	} else if tx.Weight > 0 {
		// Fallback: estimate vsize from weight
		vsize := (tx.Weight + 3) / 4
		result.FeeRate = math.Round(float64(tx.Fee)*100/float64(vsize)) / 100
	}

	// 2. Classify fee rate tier
	result.FeeRateClass = classifyFeeRate(result.FeeRate)

	// 3. Detect fee rounding pattern
	result.RoundingPattern = detectFeeRounding(result.FeeRate)

	// 4. Detect unnecessary inputs (UTXO selection intelligence)
	result.UnnecessaryInputs = detectUnnecessaryInputs(tx)

	// 5. Compute overpay ratio (how much above minimum necessary fee)
	result.OverpayRatio = computeOverpayRatio(tx)

	// 6. Infer wallet family from fee pattern
	result.WalletHint = inferWalletFromFee(result)

	return result
}

// classifyFeeRate maps sat/vB to a priority tier
func classifyFeeRate(feeRate float64) string {
	switch {
	case feeRate <= 1.0:
		return "minimal" // 1 sat/vB minimum relay
	case feeRate <= 3.0:
		return "economic" // Low priority, may wait hours
	case feeRate <= 15.0:
		return "normal" // Standard confirmation in 1-3 blocks
	case feeRate <= 50.0:
		return "priority" // Fast confirmation, next block likely
	default:
		return "urgent" // Extreme urgency or misconfiguration
	}
}

// detectFeeRounding identifies wallet-specific fee rounding behaviors.
//
// Bitcoin Core: rounds to whole sat/vB (1.0, 2.0, 3.0, ...)
// Exchanges: round to 5 or 10 sat/vB tiers
// Precise wallets (Electrum): fractional rates like 2.37 sat/vB
func detectFeeRounding(feeRate float64) string {
	if feeRate <= 0 {
		return "none"
	}

	// Check if fee rate is a whole number (1 sat/vB rounding = Bitcoin Core)
	if math.Abs(feeRate-math.Round(feeRate)) < 0.05 {
		rounded := int(math.Round(feeRate))
		// Check for 10 sat/vB multiples (exchange pattern)
		if rounded%10 == 0 && rounded > 0 {
			return "10sat"
		}
		// Check for 5 sat/vB multiples (exchange/batch pattern)
		if rounded%5 == 0 && rounded > 0 {
			return "5sat"
		}
		// Whole number rounding (Core pattern)
		return "1sat"
	}

	// Fractional fee rate = precise estimation (Electrum, Sparrow)
	return "precise"
}

// detectUnnecessaryInputs identifies when a wallet selected more inputs
// than strictly needed to cover the outputs + fee. This reveals the
// UTXO selection algorithm: Branch & Bound (Core), Knapsack, or Random.
//
// An "unnecessary input" is one where removing it would still leave
// enough value to cover all outputs plus the fee.
func detectUnnecessaryInputs(tx models.Transaction) int {
	if len(tx.Inputs) <= 1 {
		return 0
	}

	// Total output value + fee
	totalNeeded := tx.Fee
	for _, out := range tx.Outputs {
		totalNeeded += out.Value
	}

	// Sort inputs by value ascending
	type indexedInput struct {
		value int64
		index int
	}
	sortedInputs := make([]indexedInput, len(tx.Inputs))
	for i, in := range tx.Inputs {
		sortedInputs[i] = indexedInput{value: in.Value, index: i}
	}
	sort.Slice(sortedInputs, func(a, b int) bool {
		return sortedInputs[a].value < sortedInputs[b].value
	})

	// Find the minimum number of inputs needed (greedy from largest)
	totalAvailable := int64(0)
	for _, in := range tx.Inputs {
		totalAvailable += in.Value
	}

	unnecessary := 0
	cumulative := totalAvailable
	for _, si := range sortedInputs {
		remaining := cumulative - si.value
		if remaining >= totalNeeded {
			unnecessary++
			cumulative = remaining
		}
	}

	return unnecessary
}

// computeOverpayRatio estimates how much the transaction overpays relative
// to the minimum possible fee. A ratio of 1.0 means exactly optimal,
// >1.5 suggests intentional overpayment (coordinator fee padding).
func computeOverpayRatio(tx models.Transaction) float64 {
	if tx.Fee <= 0 || tx.Vsize <= 0 {
		return 1.0
	}

	// Minimum relay fee is 1 sat/vB
	minFee := int64(tx.Vsize)
	if minFee <= 0 {
		return 1.0
	}

	ratio := float64(tx.Fee) / float64(minFee)
	return math.Round(ratio*100) / 100
}

// inferWalletFromFee combines fee signals to infer wallet software.
//
// Decision matrix:
//
//	Bitcoin Core:  1sat rounding + nLockTime=height + economic/normal rate
//	Electrum:      precise rates + no nLockTime + normal rate
//	Wasabi:        overpay ratio > 1.5 + large I/O count
//	Exchange:      5sat/10sat rounding + priority/urgent rate
//	Lightning:     minimal rate + 2-in-2-out or 1-in-1-out
func inferWalletFromFee(result models.FeeAnalysisResult) string {
	switch {
	case result.RoundingPattern == "10sat" || result.RoundingPattern == "5sat":
		return "exchange/custodial"
	case result.OverpayRatio > 2.0:
		return "coordinator/wasabi"
	case result.RoundingPattern == "1sat" && result.FeeRateClass == "economic":
		return "bitcoin-core"
	case result.RoundingPattern == "1sat" && result.FeeRateClass == "normal":
		return "bitcoin-core"
	case result.RoundingPattern == "precise" && result.FeeRateClass == "normal":
		return "electrum/sparrow"
	case result.FeeRateClass == "minimal" && result.UnnecessaryInputs == 0:
		return "lightning"
	default:
		return "unknown"
	}
}

// IsSuspiciousFeePattern returns true if the fee pattern suggests anomalous
// behavior worth flagging: excessive overpay, or extreme rounding that
// strongly fingerprints the sender's wallet.
func IsSuspiciousFeePattern(result models.FeeAnalysisResult) bool {
	// Overpaying by >3x is suspicious (coordinator fee padding or misconfiguration)
	if result.OverpayRatio > 3.0 {
		return true
	}

	// Fee rate > 100 sat/vB is almost always misconfiguration or urgency overpay
	if result.FeeRate > 100.0 {
		return true
	}

	// 3+ unnecessary inputs reveals significant UTXO management strategy
	if result.UnnecessaryInputs >= 3 {
		return true
	}

	return false
}
