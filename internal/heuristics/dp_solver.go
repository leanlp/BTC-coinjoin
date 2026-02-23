package heuristics

import "log"

// SolveDPBitset implements a Pseudo-Polynomial Dynamic Programming solver
// (utilizing bitset-like arrays) for bounded-value sum subproblems.
// This lane is highly competitive when values are constrained or quantized
// (e.g., verifying small structured constraints like coordinator fee patterns).
func SolveDPBitset(inputs []int64, outputs []int64, tau int64) int {
	if len(inputs) == 0 || len(outputs) == 0 {
		return 0
	}

	// Calculate maximum possible sum (all outputs combined)
	var maxSum int64 = 0
	for _, out := range outputs {
		maxSum += out
	}

	// Guardrail: This is pseudo-polynomial in maxSum. If it's too large, Refuse to run.
	// We're looking for constrained small problems (e.g., max 500,000 Satoshis).
	if maxSum > 500_000 {
		log.Printf("[DP-Solver] Values too large for pseudo-polynomial lane (MaxSum: %d). Bailing out.", maxSum)
		return 0
	}

	// Convert outputs to DP array
	// dp[s] holds the max number of inputs that can be successfully mapped using sum `s`
	// Actually, an easier DP formulation for subset sum:
	// Find if there is a subset of outputs summing to exactly the target (within tau).

	// Fast track for single-input mapping testing to establish AnonSet
	maxValidSets := 0

	for _, targetInput := range inputs {
		// Can we form targetInput within tau using a subset of outputs?
		// target = targetInput. We allow sums from targetInput - tau to targetInput + tau.
		if isSubsetSumDP(outputs, targetInput, tau, maxSum) {
			maxValidSets++
		}
	}

	// This is a naive heuristic bound. True SSMP requires non-overlapping sets.
	// For production we combine this bound with the MitM/CP-SAT constraints.
	return maxValidSets
}

// isSubsetSumDP solves the basic subset sum problem up to a bounded maximum using DP.
func isSubsetSumDP(values []int64, target int64, tau int64, maxSum int64) bool {
	if target-tau > maxSum {
		return false
	}

	dp := make([]bool, maxSum+1)
	dp[0] = true

	for _, val := range values {
		for s := maxSum; s >= val; s-- {
			if dp[s-val] {
				dp[s] = true
			}
		}
	}

	// Check if any sum within [target-tau, target+tau] is possible
	lowerBound := target - tau
	if lowerBound < 0 {
		lowerBound = 0
	}
	upperBound := target + tau
	if upperBound > maxSum {
		upperBound = maxSum
	}

	for s := lowerBound; s <= upperBound; s++ {
		if dp[s] {
			return true
		}
	}

	return false
}
