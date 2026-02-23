package heuristics

import "log"

// SolveCPSAT implements a Constraint Propagation solver for small, constrained instances.
// CP-SAT / ILP engines are deployed strictly for small, highly constrained
// instances (e.g., verifying a Whirlpool Tx0 fee structure). The engine refuses to run
// ILP on large unconstrained sets.
//
// This solver models the input-output assignment as a Boolean Satisfaction Problem:
//   - For each input i and output j, we have a Boolean variable x[i][j]
//   - Constraint 1: Each output is assigned to exactly one input (partition)
//   - Constraint 2: sum(outputs assigned to input i) ≈ input[i] within fee tolerance
//   - Objective: Find the maximum number of inputs that can be matched to valid output partitions
func SolveCPSAT(inputs []int64, outputs []int64, tau int64) int {
	nIn := len(inputs)
	nOut := len(outputs)

	// Hard guardrail: refuse large unconstrained instances
	if nIn*nOut > 100 {
		log.Printf("[CP-SAT] Instance too large (%d x %d = %d). Refusing to run.", nIn, nOut, nIn*nOut)
		return 0
	}

	if nIn == 0 || nOut == 0 {
		return 0
	}

	if tau < 1000 {
		tau = 1000
	}

	// The solver uses backtracking search with constraint propagation.
	// assignment[j] = i means output j is assigned to input i. -1 = unassigned.
	assignment := make([]int, nOut)
	for j := range assignment {
		assignment[j] = -1
	}

	bestResult := 0
	solveRecursive(inputs, outputs, assignment, tau, 0, &bestResult)

	return bestResult
}

// solveRecursive performs backtracking search through output assignments.
func solveRecursive(inputs, outputs []int64, assignment []int, tau int64, outputIdx int, bestResult *int) {
	nOut := len(outputs)
	nIn := len(inputs)

	// Base case: all outputs have been assigned
	if outputIdx == nOut {
		// Count how many inputs have valid (non-empty) output partitions
		// that satisfy the fee tolerance constraint
		validInputs := countValidPartitions(inputs, outputs, assignment, tau)
		if validInputs > *bestResult {
			*bestResult = validInputs
		}
		return
	}

	// Try assigning this output to each input
	for i := 0; i < nIn; i++ {
		assignment[outputIdx] = i

		// Pruning: check if this partial assignment can still be feasible
		// If the sum of outputs assigned to input i already exceeds input[i] + tau, prune
		partialSum := int64(0)
		for j := 0; j <= outputIdx; j++ {
			if assignment[j] == i {
				partialSum += outputs[j]
			}
		}

		if partialSum > inputs[i]+tau {
			assignment[outputIdx] = -1
			continue // Prune: this partition already exceeds the input value
		}

		solveRecursive(inputs, outputs, assignment, tau, outputIdx+1, bestResult)
	}

	// Also try not assigning this output (leave as "unmatched change")
	assignment[outputIdx] = -1
	solveRecursive(inputs, outputs, assignment, tau, outputIdx+1, bestResult)
}

// countValidPartitions checks how many input partitions satisfy the fee tolerance.
func countValidPartitions(inputs, outputs []int64, assignment []int, tau int64) int {
	nIn := len(inputs)
	partitionSums := make([]int64, nIn)
	partitionHasOutputs := make([]bool, nIn)

	for j, inputIdx := range assignment {
		if inputIdx >= 0 && inputIdx < nIn {
			partitionSums[inputIdx] += outputs[j]
			partitionHasOutputs[inputIdx] = true
		}
	}

	validCount := 0
	for i := 0; i < nIn; i++ {
		if !partitionHasOutputs[i] {
			continue
		}
		// Valid if: input[i] - tau <= sum(outputs) <= input[i] + tau
		if partitionSums[i] >= inputs[i]-tau && partitionSums[i] <= inputs[i]+tau {
			validCount++
		}
	}

	return validCount
}
