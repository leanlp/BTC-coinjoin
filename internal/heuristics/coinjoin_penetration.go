package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// CoinJoin Penetration Module
//
// The hardest challenge in fund tracing: maintaining tracking THROUGH
// a CoinJoin mixer. While perfect CoinJoins (equal-output Whirlpool)
// provide strong anonymity, many mixes have exploitable weaknesses:
//
//   1. Unique output values: if only one output matches the tracked
//      input's denomination, it's deterministically linked
//   2. Change outputs: the change from a CoinJoin often reuses the
//      same address type, revealing the entity
//   3. Post-mix consolidation: if the target consolidates mixed UTXOs
//      immediately after, they're linked (from postmix_analysis.go)
//   4. Timing correlation: if the target spends their mixed output
//      within the same block, timing links them
//   5. Value fingerprinting: tracked entity's fee patterns carry
//      through the mix (from fee_analysis.go)
//
// This module composes all available signals to estimate which
// CoinJoin outputs belong to the tracked entity.
//
// References:
//   - Goldfeder et al., "When the Cookie Meets the Blockchain" (IEEE S&P 2018)
//   - Biryukov et al., "Deanonymisation of Clients in Bitcoin P2P Network" (CCS 2014)
//   - OXT Research, "CoinJoin Sudoku" (2019)

// PenetrationResult holds the analysis of CoinJoin penetration attempts
type PenetrationResult struct {
	TxID              string          `json:"txid"`
	IsPenetrated      bool            `json:"isPenetrated"`      // Could we trace through?
	TrackedOutputs    []TrackedOutput `json:"trackedOutputs"`    // Outputs likely belonging to tracked entity
	OverallConfidence float64         `json:"overallConfidence"` // Combined confidence
	Methods           []string        `json:"methods"`           // Which methods succeeded
	LeakagePoints     []string        `json:"leakagePoints"`     // What weaknesses were exploited
}

// TrackedOutput is a CoinJoin output believed to belong to the tracked entity
type TrackedOutput struct {
	OutputIndex int     `json:"outputIndex"`
	Address     string  `json:"address"`
	Value       int64   `json:"value"`
	Confidence  float64 `json:"confidence"` // 0-1 confidence this belongs to tracked entity
	Method      string  `json:"method"`     // How it was identified
}

// PenetrateCoinjoin attempts to trace specific inputs through a CoinJoin
// transaction to determine which outputs likely belong to the tracked entity.
//
// trackedInputIndices: indices of inputs known to belong to the tracked entity
func PenetrateCoinjoin(tx models.Transaction, trackedInputIndices []int) PenetrationResult {
	result := PenetrationResult{
		TxID: tx.Txid,
	}

	if len(trackedInputIndices) == 0 || len(tx.Outputs) == 0 {
		return result
	}

	// Calculate the tracked entity's total input value
	trackedValue := int64(0)
	for _, idx := range trackedInputIndices {
		if idx < len(tx.Inputs) {
			trackedValue += tx.Inputs[idx].Value
		}
	}

	// ─── Method 1: Unique Value Analysis ─────────────────────────────
	// If only one output's value matches what the tracked entity put in
	// (minus fee share), it's deterministically theirs
	uniqueMatches := findUniqueValueMatches(tx, trackedValue)
	for _, m := range uniqueMatches {
		result.TrackedOutputs = append(result.TrackedOutputs, m)
		result.Methods = appendUnique(result.Methods, "unique_value")
		result.LeakagePoints = appendUnique(result.LeakagePoints, "non-uniform output values")
	}

	// ─── Method 2: Address Type Consistency ──────────────────────────
	// If the tracked inputs use SegWit and only one output is SegWit
	// while others are legacy, the SegWit output is likely theirs
	typeMatches := findAddressTypeMatches(tx, trackedInputIndices)
	for _, m := range typeMatches {
		result.TrackedOutputs = mergeTrackedOutput(result.TrackedOutputs, m)
		result.Methods = appendUnique(result.Methods, "address_type")
		result.LeakagePoints = appendUnique(result.LeakagePoints, "inconsistent address types")
	}

	// ─── Method 3: Change Output Detection ───────────────────────────
	// CoinJoin change outputs are often identifiable because they don't
	// match the mix denomination
	changeMatches := findChangeOutputs(tx, trackedValue)
	for _, m := range changeMatches {
		result.TrackedOutputs = mergeTrackedOutput(result.TrackedOutputs, m)
		result.Methods = appendUnique(result.Methods, "change_detection")
		result.LeakagePoints = appendUnique(result.LeakagePoints, "identifiable change output")
	}

	// ─── Method 4: Subset Sum Analysis ───────────────────────────────
	// Check if any subset of outputs sums to the tracked input value
	subsetMatches := findSubsetSumOutputs(tx.Outputs, trackedValue)
	for _, m := range subsetMatches {
		result.TrackedOutputs = mergeTrackedOutput(result.TrackedOutputs, m)
		result.Methods = appendUnique(result.Methods, "subset_sum")
		result.LeakagePoints = appendUnique(result.LeakagePoints, "subset sum linkage")
	}

	// Compute overall confidence
	if len(result.TrackedOutputs) > 0 {
		result.IsPenetrated = true
		maxConf := 0.0
		for _, out := range result.TrackedOutputs {
			if out.Confidence > maxConf {
				maxConf = out.Confidence
			}
		}
		result.OverallConfidence = maxConf
	}

	return result
}

// findUniqueValueMatches finds outputs with unique values that could
// match the tracked entity's input (after accounting for fee share)
func findUniqueValueMatches(tx models.Transaction, trackedValue int64) []TrackedOutput {
	var matches []TrackedOutput

	// Count how many times each output value appears
	valueCounts := make(map[int64]int)
	for _, out := range tx.Outputs {
		valueCounts[out.Value]++
	}

	// Fee per participant (estimated)
	feePerParticipant := int64(0)
	if tx.Fee > 0 && len(tx.Inputs) > 0 {
		feePerParticipant = tx.Fee / int64(len(tx.Inputs))
	}

	expectedOutput := trackedValue - feePerParticipant

	for i, out := range tx.Outputs {
		// If this output value is unique (appears only once)
		// AND it's close to the tracked value minus fee
		if valueCounts[out.Value] == 1 {
			tolerance := expectedOutput / 100 // 1% tolerance
			if out.Value >= expectedOutput-tolerance && out.Value <= expectedOutput+tolerance {
				matches = append(matches, TrackedOutput{
					OutputIndex: i,
					Address:     out.Address,
					Value:       out.Value,
					Confidence:  0.8,
					Method:      "unique_value",
				})
			}
		}
	}

	return matches
}

// findAddressTypeMatches finds outputs matching the tracked entity's address type
func findAddressTypeMatches(tx models.Transaction, trackedInputIndices []int) []TrackedOutput {
	var matches []TrackedOutput

	// Determine the tracked entity's address type
	trackedType := ""
	for _, idx := range trackedInputIndices {
		if idx < len(tx.Inputs) {
			trackedType = detectAddressType(tx.Inputs[idx].Address)
			break
		}
	}

	if trackedType == "" || trackedType == "unknown" {
		return matches
	}

	// Count outputs by address type
	typeCounts := make(map[string]int)
	for _, out := range tx.Outputs {
		typeCounts[detectAddressType(out.Address)]++
	}

	// If the tracked type is rare among outputs, it's a signal
	totalOutputs := len(tx.Outputs)
	trackedTypeCount := typeCounts[trackedType]

	if trackedTypeCount <= 2 && totalOutputs > 3 {
		for i, out := range tx.Outputs {
			if detectAddressType(out.Address) == trackedType {
				confidence := 0.5
				if trackedTypeCount == 1 {
					confidence = 0.7
				}
				matches = append(matches, TrackedOutput{
					OutputIndex: i,
					Address:     out.Address,
					Value:       out.Value,
					Confidence:  confidence,
					Method:      "address_type",
				})
			}
		}
	}

	return matches
}

// findChangeOutputs identifies change outputs from the CoinJoin
func findChangeOutputs(tx models.Transaction, trackedValue int64) []TrackedOutput {
	var matches []TrackedOutput

	if len(tx.Outputs) < 2 {
		return matches
	}

	// Find the modal (most common) output value — this is the mix denomination
	valueCounts := make(map[int64]int)
	for _, out := range tx.Outputs {
		valueCounts[out.Value]++
	}

	modalValue := int64(0)
	modalCount := 0
	for val, count := range valueCounts {
		if count > modalCount {
			modalValue = val
			modalCount = count
		}
	}

	// Change outputs are those NOT matching the mix denomination
	// AND smaller than the mix denomination
	for i, out := range tx.Outputs {
		if out.Value != modalValue && out.Value < modalValue {
			// This is likely change. Is it the tracked entity's change?
			expectedChange := trackedValue - modalValue
			if expectedChange > 0 {
				tolerance := expectedChange / 10 // 10% tolerance
				if out.Value >= expectedChange-tolerance && out.Value <= expectedChange+tolerance {
					matches = append(matches, TrackedOutput{
						OutputIndex: i,
						Address:     out.Address,
						Value:       out.Value,
						Confidence:  0.6,
						Method:      "change_detection",
					})
				}
			}
		}
	}

	return matches
}

// findSubsetSumOutputs checks if any single output or pair of outputs
// sums to approximately the tracked input value
func findSubsetSumOutputs(outputs []models.TxOut, targetValue int64) []TrackedOutput {
	var matches []TrackedOutput

	if len(outputs) > 20 {
		return matches // Too many outputs, combinatorial explosion
	}

	tolerance := targetValue / 50 // 2% tolerance

	// Check single outputs
	for i, out := range outputs {
		if math.Abs(float64(out.Value-targetValue)) <= float64(tolerance) {
			matches = append(matches, TrackedOutput{
				OutputIndex: i,
				Address:     out.Address,
				Value:       out.Value,
				Confidence:  0.55,
				Method:      "subset_sum",
			})
		}
	}

	// Check pairs of outputs
	for i := 0; i < len(outputs)-1; i++ {
		for j := i + 1; j < len(outputs); j++ {
			pairSum := outputs[i].Value + outputs[j].Value
			if math.Abs(float64(pairSum-targetValue)) <= float64(tolerance) {
				matches = append(matches, TrackedOutput{
					OutputIndex: i,
					Address:     outputs[i].Address,
					Value:       outputs[i].Value,
					Confidence:  0.45,
					Method:      "subset_sum_pair",
				})
				matches = append(matches, TrackedOutput{
					OutputIndex: j,
					Address:     outputs[j].Address,
					Value:       outputs[j].Value,
					Confidence:  0.45,
					Method:      "subset_sum_pair",
				})
			}
		}
	}

	return matches
}

// mergeTrackedOutput adds or updates a tracked output, boosting confidence
// when multiple methods agree
func mergeTrackedOutput(existing []TrackedOutput, new TrackedOutput) []TrackedOutput {
	for i, e := range existing {
		if e.OutputIndex == new.OutputIndex {
			// Multiple methods agree → boost confidence
			existing[i].Confidence = math.Min(1.0, e.Confidence+new.Confidence*0.3)
			existing[i].Method += "+" + new.Method
			return existing
		}
	}
	return append(existing, new)
}

// appendUnique adds a string to a slice only if not already present
func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}
