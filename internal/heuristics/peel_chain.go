package heuristics

import (
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Peel Chain Detection Module
//
// Peel chains are the single most exploited pattern by Chainalysis and Elliptic
// for tracing payment flows. They occur when a wallet makes serial payments:
//
//   Tx₁: [UTXO_A] → [Payment₁, Change₁]
//   Tx₂: [Change₁] → [Payment₂, Change₂]
//   Tx₃: [Change₂] → [Payment₃, Change₃]
//   ...
//
// Each step "peels" off a payment and passes the change to the next transaction,
// creating a deterministic chain of custody that is trivially traceable.
//
// Detection signals:
//   - 1-in-2-out topology (canonical peel step)
//   - The input is a previously identified change output
//   - Value flows monotonically downward (each change < previous)
//   - Script types are consistent across the chain
//
// References:
//   - Meiklejohn et al., "A Fistful of Bitcoins" (IMC 2013)
//   - Harrigan & Fretter, "The Unreasonable Effectiveness of Address Clustering" (IEEE 2016)
//   - Ron & Shamir, "Quantitative Analysis of the Bitcoin Transaction Graph" (FC 2013)

// PeelChainCandidate captures the signals used to identify a peel chain step
type PeelChainCandidate struct {
	IsPeelStep    bool    // This tx looks like a peel step
	Confidence    float64 // 0.0 - 1.0
	ChangeIndex   int     // Which output is the change (smaller value)
	PaymentIndex  int     // Which output is the payment
	ChangeValue   int64   // Value of the change output
	PaymentValue  int64   // Value of the payment output
	InputIsSingle bool    // True if exactly 1 input
}

// DetectPeelChainStep analyzes a single transaction to determine if it
// represents a step in a peel chain. This is the per-transaction check;
// actual chain linking requires cross-transaction state.
//
// A peel step has these characteristics:
//  1. Exactly 1 input, exactly 2 outputs (canonical form)
//     OR 1-2 inputs, exactly 2 outputs (relaxed form)
//  2. One output is significantly smaller than the input (change)
//  3. The change output has the same script type as the input
//  4. No CoinJoin signals present
func DetectPeelChainStep(tx models.Transaction, isCoinJoin bool) PeelChainCandidate {
	result := PeelChainCandidate{
		ChangeIndex:  -1,
		PaymentIndex: -1,
	}

	// CoinJoins are never peel chains
	if isCoinJoin {
		return result
	}

	// Must have exactly 2 outputs
	if len(tx.Outputs) != 2 {
		return result
	}

	// Must have 1-2 inputs (canonical peel is 1-in-2-out)
	if len(tx.Inputs) < 1 || len(tx.Inputs) > 2 {
		return result
	}

	result.InputIsSingle = len(tx.Inputs) == 1

	// Identify change vs payment by value
	// Change is typically the smaller output in peel chains
	out0 := tx.Outputs[0].Value
	out1 := tx.Outputs[1].Value

	if out0 <= out1 {
		result.ChangeIndex = 0
		result.PaymentIndex = 1
		result.ChangeValue = out0
		result.PaymentValue = out1
	} else {
		result.ChangeIndex = 1
		result.PaymentIndex = 0
		result.ChangeValue = out1
		result.PaymentValue = out0
	}

	// Build confidence from multiple signals
	confidence := 0.0

	// Signal 1: Single input (strongest peel signal)
	if result.InputIsSingle {
		confidence += 0.30
	} else {
		confidence += 0.10
	}

	// Signal 2: Change is significantly smaller than input total
	totalInput := int64(0)
	for _, in := range tx.Inputs {
		totalInput += in.Value
	}
	if totalInput > 0 {
		changeRatio := float64(result.ChangeValue) / float64(totalInput)
		if changeRatio < 0.3 {
			confidence += 0.25 // Change < 30% of input = strong peel signal
		} else if changeRatio < 0.5 {
			confidence += 0.15
		}
	}

	// Signal 3: Script type consistency (change type matches input type)
	if len(tx.Inputs) > 0 {
		inputType := detectAddressType(tx.Inputs[0].Address)
		changeType := detectAddressType(tx.Outputs[result.ChangeIndex].Address)
		if inputType == changeType && inputType != "unknown" {
			confidence += 0.20
		}
	}

	// Signal 4: Payment is a round amount (human-initiated payment)
	if isRoundAmount(result.PaymentValue) {
		confidence += 0.15
	}

	// Signal 5: Fee is reasonable (not a consolidation or sweep)
	if tx.Fee > 0 && tx.Vsize > 0 {
		feeRate := float64(tx.Fee) / float64(tx.Vsize)
		if feeRate >= 1.0 && feeRate <= 50.0 {
			confidence += 0.10
		}
	}

	// Cap confidence at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	// Must meet minimum threshold to be considered a peel step
	if confidence >= 0.4 {
		result.IsPeelStep = true
		result.Confidence = confidence
	}

	return result
}

// BuildPeelChainResult converts a peel chain candidate into the
// PrivacyAnalysisResult field. For full chain linking, the scanner
// would need to maintain a state map of previous change outputs.
func BuildPeelChainResult(candidate PeelChainCandidate) *models.PeelChainResult {
	if !candidate.IsPeelStep {
		return nil
	}

	return &models.PeelChainResult{
		IsChain:     true,
		ChainLength: 1, // Single step detected; scanner upgrades this for multi-step chains
		Direction:   "forward",
		Confidence:  candidate.Confidence,
		ChangeIndex: candidate.ChangeIndex,
	}
}

// ScorePeelChainLLR converts the peel chain confidence into an LLR score
// for the evidence graph. Longer chains have exponentially stronger evidence.
func ScorePeelChainLLR(chainLength int, confidence float64) float64 {
	// Base LLR from confidence
	baseLLR := ProbToLLR(confidence)

	// Longer chains are exponentially more certain
	// Each additional step multiplies evidence by 1.5x
	lengthBonus := 1.0
	if chainLength > 1 {
		lengthBonus = 1.0 + 0.5*float64(chainLength-1)
		if lengthBonus > 5.0 {
			lengthBonus = 5.0 // Cap at 5x
		}
	}

	return baseLLR * lengthBonus
}
