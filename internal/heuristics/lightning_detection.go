package heuristics

import (
	"strings"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Lightning Network Channel Detection
//
// LN channels leave distinctive on-chain footprints at each lifecycle stage:
//
//   FUNDING (channel open):
//   - 2-of-2 P2WSH multisig output
//   - Typical values: round mBTC (100k, 500k, 1M, 5M, 10M, 16M sats)
//   - Funded from 1-2 inputs
//
//   COOPERATIVE CLOSE:
//   - Spends the 2-of-2 funding output
//   - 2 outputs splitting the channel balance
//   - No timelocks (mutual agreement)
//
//   FORCE CLOSE:
//   - Reveals HTLC scripts with timelocks
//   - `to_local` output: CSV-locked (OP_CHECKSEQUENCEVERIFY)
//   - `to_remote` output: immediately spendable
//   - Anchor outputs (since LN spec v1.1)
//
//   PENALTY (breach remedy):
//   - Sweeps ALL funds to one party
//   - 1 output (confiscation of entire channel)
//
// References:
//   - BOLT #3: "Bitcoin Transaction and Script Formats"
//   - Tikhomirov et al., "A Quantitative Analysis of the LN" (FC 2020)
//   - Kappos et al., "An Empirical Analysis of Privacy in the LN" (FC 2021)

// LightningResult holds Lightning Network detection results
type LightningResult struct {
	IsLightningTx     bool   `json:"isLightningTx"`
	ChannelType       string `json:"channelType"`       // "funding"/"cooperative-close"/"force-close"/"penalty"/"none"
	EstimatedCapacity int64  `json:"estimatedCapacity"` // Channel capacity in sats
	HasAnchorOutputs  bool   `json:"hasAnchorOutputs"`  // Modern anchor commitment
}

// Common Lightning channel capacities (sats)
var lightningChannelSizes = []int64{
	100000,    // 0.001 BTC (minimum practical)
	200000,    // 0.002 BTC
	500000,    // 0.005 BTC
	1000000,   // 0.01 BTC
	2000000,   // 0.02 BTC
	5000000,   // 0.05 BTC
	10000000,  // 0.1 BTC
	16777215,  // 0.16 BTC (legacy maximum)
	50000000,  // 0.5 BTC
	100000000, // 1.0 BTC
}

// DetectLightningChannel analyzes a transaction for LN channel signatures
func DetectLightningChannel(tx models.Transaction) LightningResult {
	result := LightningResult{ChannelType: "none"}

	// Check for funding transaction pattern
	if detectLNFunding(tx) {
		result.IsLightningTx = true
		result.ChannelType = "funding"
		result.EstimatedCapacity = findChannelOutput(tx)
		return result
	}

	// Check for cooperative close
	if detectCooperativeClose(tx) {
		result.IsLightningTx = true
		result.ChannelType = "cooperative-close"
		result.EstimatedCapacity = sumInputValues(tx)
		return result
	}

	// Check for force close
	if detectForceClose(tx) {
		result.IsLightningTx = true
		result.ChannelType = "force-close"
		result.EstimatedCapacity = sumInputValues(tx)
		result.HasAnchorOutputs = detectAnchorOutputs(tx)
		return result
	}

	// Check for penalty transaction
	if detectPenaltyTx(tx) {
		result.IsLightningTx = true
		result.ChannelType = "penalty"
		result.EstimatedCapacity = sumInputValues(tx)
		return result
	}

	return result
}

// detectLNFunding checks for channel open pattern:
// - 1-2 inputs
// - One output is P2WSH (2-of-2 funding)
// - Output value matches common channel sizes
func detectLNFunding(tx models.Transaction) bool {
	if len(tx.Inputs) > 3 || len(tx.Outputs) < 1 || len(tx.Outputs) > 3 {
		return false
	}

	hasP2WSH := false
	hasChannelSizeOutput := false

	for _, out := range tx.Outputs {
		addrType := detectAddressType(out.Address)
		if addrType == "segwit" && len(out.ScriptPubKey) == 68 {
			// P2WSH = 0x0020 + 32-byte hash = 68 hex chars
			hasP2WSH = true
		}
		if isChannelSize(out.Value) {
			hasChannelSizeOutput = true
		}
	}

	return hasP2WSH && hasChannelSizeOutput
}

// detectCooperativeClose checks for mutual close pattern:
// - 1 input (the funding output)
// - 2 outputs (balance split)
// - No timelock scripts
func detectCooperativeClose(tx models.Transaction) bool {
	if len(tx.Inputs) != 1 || len(tx.Outputs) != 2 {
		return false
	}

	// Both outputs should be simple P2WPKH (no complex scripts)
	for _, out := range tx.Outputs {
		addrType := detectAddressType(out.Address)
		if addrType != "segwit" && addrType != "taproot" {
			return false
		}
	}

	// Input should be a P2WSH spend (multisig)
	if len(tx.Inputs[0].ScriptSig) > 0 {
		return false // SegWit inputs have empty scriptSig
	}

	return true
}

// detectForceClose checks for unilateral close pattern:
// - 1 input
// - Contains CSV-locked output (OP_CHECKSEQUENCEVERIFY)
// - May have HTLC outputs
func detectForceClose(tx models.Transaction) bool {
	if len(tx.Inputs) != 1 {
		return false
	}

	hasCSVOutput := false
	for _, out := range tx.Outputs {
		lower := strings.ToLower(out.ScriptPubKey)
		// OP_CHECKSEQUENCEVERIFY = 0xb2
		if strings.Contains(lower, "b2") {
			hasCSVOutput = true
		}
	}

	return hasCSVOutput
}

// detectPenaltyTx checks for breach remedy:
// - Spends from a commitment tx
// - ALL value goes to 1 output (confiscation)
func detectPenaltyTx(tx models.Transaction) bool {
	return len(tx.Inputs) >= 1 && len(tx.Outputs) == 1
}

// detectAnchorOutputs checks for modern anchor commitment outputs
// Anchor outputs are exactly 330 sats (dust limit for P2WSH)
func detectAnchorOutputs(tx models.Transaction) bool {
	for _, out := range tx.Outputs {
		if out.Value == 330 {
			return true
		}
	}
	return false
}

// isChannelSize checks if a value matches a common LN channel capacity
func isChannelSize(value int64) bool {
	for _, size := range lightningChannelSizes {
		if value == size {
			return true
		}
		// Allow ±1% for fee deduction during funding
		tolerance := size / 100
		if value >= size-tolerance && value <= size+tolerance {
			return true
		}
	}
	return false
}

// findChannelOutput returns the value of the likely funding output
func findChannelOutput(tx models.Transaction) int64 {
	for _, out := range tx.Outputs {
		if isChannelSize(out.Value) {
			return out.Value
		}
	}
	// Fallback: return largest output
	largest := int64(0)
	for _, out := range tx.Outputs {
		if out.Value > largest {
			largest = out.Value
		}
	}
	return largest
}

// sumInputValues sums all input values
func sumInputValues(tx models.Transaction) int64 {
	total := int64(0)
	for _, in := range tx.Inputs {
		total += in.Value
	}
	return total
}
