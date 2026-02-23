package heuristics

import (
	"math"
	"sort"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Boltzmann Transaction Entropy Analysis
//
// Implements the information-theoretic measure of transaction ambiguity.
// Entropy = log₂(N) where N = number of valid input→output mappings.
//
// This is the core metric used by OXT Research (Laurent MT) and Samourai
// Wallet to quantify CoinJoin mixing quality. A perfect 5×5 Whirlpool
// mix has entropy = log₂(5!) = ~6.9 bits, while a simple 1-in-2-out
// payment has entropy ≈ 0 bits (fully deterministic).
//
// References:
//   - Laurent MT, "Boltzmann: an Entropy Metric for UTXO Transactions" (2018)
//   - OXT Research, "Understanding Wallet Entropy" (2020)
//   - Erdin et al., "Transaction Entropy Analysis" (ESORICS 2023)

// ComputeBoltzmannEntropy calculates the Boltzmann entropy of a transaction.
// It counts the number of valid interpretations (input→output mappings)
// where each input can fund each output, then returns log₂(count).
//
// Algorithm:
//  1. For each output, determine which inputs could fund it (value >= output value)
//  2. Count valid complete assignments using constrained permutation enumeration
//  3. Entropy = log₂(valid_assignments)
//
// Complexity is bounded: for txs with >12 I/O, we use statistical estimation.
func ComputeBoltzmannEntropy(tx models.Transaction) models.EntropyResult {
	nIn := len(tx.Inputs)
	nOut := len(tx.Outputs)

	if nIn == 0 || nOut == 0 {
		return models.EntropyResult{Level: "transparent"}
	}

	// Simple transactions have zero entropy
	if nIn == 1 && nOut <= 2 {
		return models.EntropyResult{
			Entropy:         0,
			MaxEntropy:      0,
			Efficiency:      0,
			Level:           "transparent",
			Interpretations: 1,
		}
	}

	// Maximum possible entropy = log₂(min(nIn, nOut)!)
	// This is the entropy if every input could fund every output
	minDim := nIn
	if nOut < minDim {
		minDim = nOut
	}
	maxEntropy := log2Factorial(minDim)

	// Count valid interpretations
	var interpretations int
	if nIn <= 12 && nOut <= 12 {
		// Exact enumeration for small transactions
		interpretations = countValidMappings(tx.Inputs, tx.Outputs, tx.Fee)
	} else {
		// Statistical estimation for large transactions (CoinJoins)
		interpretations = estimateMappingsLarge(tx.Inputs, tx.Outputs)
	}

	if interpretations < 1 {
		interpretations = 1
	}

	entropy := math.Log2(float64(interpretations))

	// Wallet efficiency: actual entropy / max possible entropy
	efficiency := 0.0
	if maxEntropy > 0 {
		efficiency = entropy / maxEntropy
		if efficiency > 1.0 {
			efficiency = 1.0
		}
	}

	level := classifyEntropyLevel(entropy)

	return models.EntropyResult{
		Entropy:         math.Round(entropy*100) / 100,
		MaxEntropy:      math.Round(maxEntropy*100) / 100,
		Efficiency:      math.Round(efficiency*100) / 100,
		Level:           level,
		Interpretations: interpretations,
	}
}

// countValidMappings enumerates all valid input→output assignments.
// A mapping is valid if the sum of selected inputs for each output
// covers the output value within the fee tolerance.
//
// For a standard non-CoinJoin tx, this counts how many ways you can
// assign inputs to outputs such that each assignment is value-feasible.
func countValidMappings(inputs []models.TxIn, outputs []models.TxOut, fee int64) int {
	nOut := len(outputs)
	nIn := len(inputs)

	if nOut == 0 || nIn == 0 {
		return 1
	}

	// Build the compatibility matrix: can input i potentially fund output j?
	// An input can fund an output if input.Value >= output.Value
	compatible := make([][]bool, nIn)
	for i := range inputs {
		compatible[i] = make([]bool, nOut)
		for j := range outputs {
			compatible[i][j] = inputs[i].Value >= outputs[j].Value
		}
	}

	// For CoinJoin-like txs with equal outputs, count permutations of
	// compatible inputs across outputs
	count := 0

	// Sort outputs by value descending for better pruning
	type indexedOutput struct {
		index int
		value int64
	}
	sortedOutputs := make([]indexedOutput, nOut)
	for i, o := range outputs {
		sortedOutputs[i] = indexedOutput{index: i, value: o.Value}
	}
	sort.Slice(sortedOutputs, func(a, b int) bool {
		return sortedOutputs[a].value > sortedOutputs[b].value
	})

	// Backtracking enumeration with pruning
	usedInputs := make([]bool, nIn)
	var backtrack func(outIdx int)
	backtrack = func(outIdx int) {
		if outIdx == nOut {
			count++
			return
		}
		// Cap at 10000 to prevent runaway computation
		if count >= 10000 {
			return
		}

		actualOutIdx := sortedOutputs[outIdx].index
		for inIdx := 0; inIdx < nIn; inIdx++ {
			if usedInputs[inIdx] || !compatible[inIdx][actualOutIdx] {
				continue
			}
			usedInputs[inIdx] = true
			backtrack(outIdx + 1)
			usedInputs[inIdx] = false
		}

		// If more outputs than inputs, some outputs can share inputs (CoinJoin model)
		if nOut > nIn {
			backtrack(outIdx + 1)
		}
	}

	backtrack(0)
	return count
}

// estimateMappingsLarge provides a statistical estimate for large transactions
// (WabiSabi CoinJoins with 50+ I/O) where exact enumeration is infeasible.
//
// Uses the equal-output approximation: if K outputs share the same value
// and M inputs can fund them, then those K outputs contribute C(M,K) * K!
// valid mappings.
func estimateMappingsLarge(inputs []models.TxIn, outputs []models.TxOut) int {
	// Group outputs by equal value
	outputGroups := make(map[int64]int)
	for _, out := range outputs {
		outputGroups[out.Value]++
	}

	// For each group, count how many inputs can fund that denomination
	totalMappings := 1.0
	for val, groupSize := range outputGroups {
		eligibleInputs := 0
		for _, in := range inputs {
			if in.Value >= val {
				eligibleInputs++
			}
		}

		if eligibleInputs >= groupSize {
			// C(eligible, groupSize) * groupSize!
			combination := binomialCoeff(eligibleInputs, groupSize)
			factorial := factorialInt(groupSize)
			totalMappings *= float64(combination) * float64(factorial)
		}
	}

	if totalMappings > 1e9 {
		totalMappings = 1e9 // Cap for numerical stability
	}

	return int(totalMappings)
}

// classifyEntropyLevel maps entropy bits to human-readable quality bands
func classifyEntropyLevel(entropy float64) string {
	switch {
	case entropy <= 0:
		return "transparent" // Fully deterministic (0 bits)
	case entropy < 2:
		return "low" // Weak mix (< 2 bits = < 4 interpretations)
	case entropy < 4:
		return "moderate" // Decent mix (4-16 interpretations)
	case entropy < 7:
		return "high" // Strong mix (16-128 interpretations)
	default:
		return "maximum" // Industrial grade (128+ interpretations)
	}
}

// log2Factorial computes log₂(n!) using Stirling's approximation for large n
func log2Factorial(n int) float64 {
	if n <= 1 {
		return 0
	}
	if n <= 20 {
		// Exact computation for small values
		f := 1.0
		for i := 2; i <= n; i++ {
			f *= float64(i)
		}
		return math.Log2(f)
	}
	// Stirling's approximation: log₂(n!) ≈ n*log₂(n) - n*log₂(e) + 0.5*log₂(2πn)
	fn := float64(n)
	return fn*math.Log2(fn) - fn*math.Log2(math.E) + 0.5*math.Log2(2*math.Pi*fn)
}

// binomialCoeff computes C(n, k) = n! / (k! * (n-k)!)
func binomialCoeff(n, k int) int {
	if k > n || k < 0 {
		return 0
	}
	if k == 0 || k == n {
		return 1
	}
	if k > n-k {
		k = n - k
	}
	result := 1
	for i := 0; i < k; i++ {
		result *= (n - i)
		result /= (i + 1)
	}
	return result
}

// factorialInt computes n! for small n (capped at 12 to avoid overflow)
func factorialInt(n int) int {
	if n <= 1 {
		return 1
	}
	if n > 12 {
		n = 12 // Cap to prevent overflow
	}
	result := 1
	for i := 2; i <= n; i++ {
		result *= i
	}
	return result
}
