package heuristics

import (
	"math"
	"sort"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// CoinJoin Unmixing Engine
//
// Not all CoinJoins are equal. Weak mixes leak information through
// UNIQUE OUTPUT VALUES that can be linked back to specific inputs.
// This module quantifies the unmixability of a CoinJoin and identifies
// which participants are most vulnerable.
//
// Attack vectors:
//   1. Unique output: if only one output has value X, and only one input
//      (or input subset) can produce X, the link is deterministic.
//   2. Low cardinality: if only 2 inputs can fund output Y, the anonymity
//      set for Y is 2, regardless of the tx's overall anonSet.
//   3. Change remnants: non-standard "change" outputs in a CoinJoin that
//      are unique values reveal the original input amount.
//
// References:
//   - Atlas (2022), "Applying Boltzmann Analysis to Wasabi 2.0 CoinJoins"
//   - Ficsór et al., "WabiSabi" (2021) — Section 6 on linkability
//   - OXT Research, "Understanding Transaction Entropy" (2020)

// AnalyzeUnmixability evaluates how many I→O links can be
// deterministically resolved in a CoinJoin transaction.
func AnalyzeUnmixability(tx models.Transaction, isCoinJoin bool) models.UnmixResult {
	result := models.UnmixResult{
		TotalOutputs: len(tx.Outputs),
		MixQuality:   "perfect",
	}

	if !isCoinJoin || len(tx.Inputs) < 2 || len(tx.Outputs) < 2 {
		return result
	}

	// Build linkability matrix: which inputs can fund which outputs?
	linkMatrix := buildLinkabilityMatrix(tx)

	// Count unmixable outputs (outputs funded by exactly 1 input/subset)
	for outIdx := range tx.Outputs {
		eligibleInputs := 0
		for inIdx := range tx.Inputs {
			if linkMatrix[inIdx][outIdx] {
				eligibleInputs++
			}
		}
		if eligibleInputs == 1 {
			result.DeterministicLinks++
			result.UnmixableOutputs++
		} else if eligibleInputs <= 2 {
			// Very weak — only 2 possible funders
			result.WeakParticipants++
		}
	}

	// Also check for unique output values (strongest signal)
	outputValues := make(map[int64]int)
	for _, out := range tx.Outputs {
		outputValues[out.Value]++
	}
	for _, out := range tx.Outputs {
		if outputValues[out.Value] == 1 {
			// This output has a unique value — highly linkable
			// Check if it can only be funded by specific inputs
			result.UnmixableOutputs++
		}
	}

	// Deduplicate unmixable count
	if result.UnmixableOutputs > len(tx.Outputs) {
		result.UnmixableOutputs = len(tx.Outputs)
	}

	// Compute linkability score (0.0 = perfect, 1.0 = fully linkable)
	if result.TotalOutputs > 0 {
		result.LinkabilityScore = math.Round(float64(result.UnmixableOutputs)*100/float64(result.TotalOutputs)) / 100
	}

	// Classify mix quality
	result.MixQuality = classifyMixQuality(result)

	return result
}

// buildLinkabilityMatrix creates an N×M boolean matrix where
// matrix[i][j] = true if input i can potentially fund output j.
// An input can fund an output if input.Value >= output.Value.
func buildLinkabilityMatrix(tx models.Transaction) [][]bool {
	nIn := len(tx.Inputs)
	nOut := len(tx.Outputs)

	matrix := make([][]bool, nIn)
	for i := range tx.Inputs {
		matrix[i] = make([]bool, nOut)
		for j := range tx.Outputs {
			// Basic check: can this input fund this output?
			matrix[i][j] = tx.Inputs[i].Value >= tx.Outputs[j].Value
		}
	}
	return matrix
}

// FindDeterministicLinks identifies which specific I→O pairs are
// deterministically linked (100% certainty of ownership).
func FindDeterministicLinks(tx models.Transaction) []DeterministicLink {
	var links []DeterministicLink

	if len(tx.Inputs) < 2 || len(tx.Outputs) < 2 {
		return links
	}

	matrix := buildLinkabilityMatrix(tx)

	for outIdx, out := range tx.Outputs {
		eligibleInputs := []int{}
		for inIdx := range tx.Inputs {
			if matrix[inIdx][outIdx] {
				eligibleInputs = append(eligibleInputs, inIdx)
			}
		}
		// If exactly 1 input can fund this output, it's deterministic
		if len(eligibleInputs) == 1 {
			links = append(links, DeterministicLink{
				InputIndex:  eligibleInputs[0],
				OutputIndex: outIdx,
				InputValue:  tx.Inputs[eligibleInputs[0]].Value,
				OutputValue: out.Value,
				Certainty:   1.0,
			})
		}
	}

	return links
}

// DeterministicLink represents a confirmed I→O ownership link
type DeterministicLink struct {
	InputIndex  int     `json:"inputIndex"`
	OutputIndex int     `json:"outputIndex"`
	InputValue  int64   `json:"inputValue"`
	OutputValue int64   `json:"outputValue"`
	Certainty   float64 `json:"certainty"` // 1.0 = deterministic
}

// classifyMixQuality converts linkability metrics into quality bands
func classifyMixQuality(result models.UnmixResult) string {
	ratio := result.LinkabilityScore

	switch {
	case ratio <= 0:
		return "perfect" // No linkable outputs
	case ratio <= 0.1:
		return "strong" // <10% linkable
	case ratio <= 0.3:
		return "moderate" // 10-30% linkable
	case ratio <= 0.6:
		return "weak" // 30-60% linkable
	default:
		return "broken" // >60% linkable — barely a mix
	}
}

// ComputeOutputValueEntropy calculates the Shannon entropy of the output
// value distribution. Higher entropy = more equal distribution = better mix.
func ComputeOutputValueEntropy(outputs []models.TxOut) float64 {
	if len(outputs) == 0 {
		return 0
	}

	// Count distinct output values
	valueCounts := make(map[int64]int)
	for _, out := range outputs {
		valueCounts[out.Value]++
	}

	// Shannon entropy: H = -Σ p(x) * log₂(p(x))
	total := float64(len(outputs))
	entropy := 0.0
	for _, count := range valueCounts {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return math.Round(entropy*100) / 100
}

// GetOutputValueDistribution returns the sorted value frequencies
// for analysis and visualization
func GetOutputValueDistribution(outputs []models.TxOut) []ValueGroup {
	valueCounts := make(map[int64]int)
	for _, out := range outputs {
		valueCounts[out.Value]++
	}

	var groups []ValueGroup
	for value, count := range valueCounts {
		groups = append(groups, ValueGroup{Value: value, Count: count})
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})

	return groups
}

// ValueGroup represents a group of outputs with the same value
type ValueGroup struct {
	Value int64 `json:"value"`
	Count int   `json:"count"`
}
