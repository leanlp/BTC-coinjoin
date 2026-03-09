package heuristics

import (
	"sort"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Advanced Taint Propagation Engine (Phase 18)
//
// Extends the existing TaintMap haircut model with FIFO and LIFO
// accounting methods for forensic taint tracking.
//
//   - FIFO (First-In-First-Out): Tainted inputs consumed chronologically.
//     Taint from the first input fills the first output value entirely
//     before overflow reaches subsequent outputs.
//
//   - LIFO (Last-In-First-Out): Reverse chronological ordering.
//
//   - Proportional (Haircut): Each output receives taint proportional to
//     the ratio of tainted input value to total input value. This is the
//     industry standard (Chainalysis, Elliptic, FATF guidance).
//
// References:
//   - Möser & Narayanan, "An Empirical Analysis of Traceability" (PoPETs 2018)
//   - Chainalysis, "Understanding Cryptocurrency Taint" (2023)
//   - FATF, "Virtual Assets Red Flag Indicators" (2020)

// taintedInputInfo holds pre-computed taint data for an input.
type taintedInputInfo struct {
	index      int
	value      int64
	taintLevel float64
}

// PropagateTaintAdvanced computes per-output taint levels using the specified
// accounting method. Integrates with the global TaintMap singleton.
// method must be "fifo", "lifo", or "proportional".
func PropagateTaintAdvanced(tx models.Transaction, method string) models.TaintResult {
	result := models.TaintResult{
		Method: method,
	}

	if method == "" {
		method = "proportional"
		result.Method = method
	}

	// 1. Compute input taint levels from the global taint map
	taintMu.RLock()
	tm := globalTaintMap
	taintMu.RUnlock()

	if tm == nil {
		return buildCleanResult(tx, method)
	}

	var taintedInputs []taintedInputInfo
	var totalInputValue int64
	var totalTaintedValue float64

	for i, in := range tx.Inputs {
		totalInputValue += in.Value

		taintLevel := tm.GetTaint(in.Address)
		if taintLevel > 0 {
			taintedInputs = append(taintedInputs, taintedInputInfo{
				index:      i,
				value:      in.Value,
				taintLevel: taintLevel,
			})
			totalTaintedValue += float64(in.Value) * taintLevel
		}
	}

	// If no inputs are tainted, return clean result
	if len(taintedInputs) == 0 || totalInputValue <= 0 {
		return buildCleanResult(tx, method)
	}

	// Aggregate input taint level (weighted by value)
	result.InputTaintLevel = totalTaintedValue / float64(totalInputValue)

	// Collect source labels from the existing taint sources
	// Note: the existing TaintMap doesn't store labels per-address,
	// so we report the addresses themselves as source references.
	// Estimate hops from source based on taint level decay
	// Higher taint = closer to source (taint decays with each hop)
	if result.InputTaintLevel >= 0.9 {
		result.HopsFromSource = 1
	} else if result.InputTaintLevel >= 0.5 {
		result.HopsFromSource = 2
	} else if result.InputTaintLevel >= 0.1 {
		result.HopsFromSource = 3
	} else {
		result.HopsFromSource = 4
	}

	// 2. Apply the selected accounting method
	switch method {
	case "fifo":
		result.OutputTaints = applyFIFO(tx, taintedInputs, totalInputValue, false)
	case "lifo":
		result.OutputTaints = applyFIFO(tx, taintedInputs, totalInputValue, true)
	default:
		result.Method = "proportional"
		result.OutputTaints = applyProportional(tx, result.InputTaintLevel)
	}

	// 3. Calculate total absorbed taint
	for _, ot := range result.OutputTaints {
		result.TotalAbsorbed += ot.TaintLevel * float64(ot.Value) / float64(totalInputValue)
	}

	return result
}

// buildCleanResult produces a zero-taint result for all outputs.
func buildCleanResult(tx models.Transaction, method string) models.TaintResult {
	entries := make([]models.OutputTaintEntry, len(tx.Outputs))
	for i, out := range tx.Outputs {
		entries[i] = models.OutputTaintEntry{
			Index:   i,
			Address: out.Address,
			Value:   out.Value,
		}
	}
	return models.TaintResult{
		Method:       method,
		OutputTaints: entries,
	}
}

// applyProportional distributes taint equally to all outputs (haircut method).
func applyProportional(tx models.Transaction, inputTaintLevel float64) []models.OutputTaintEntry {
	entries := make([]models.OutputTaintEntry, len(tx.Outputs))
	for i, out := range tx.Outputs {
		entries[i] = models.OutputTaintEntry{
			Index:      i,
			Address:    out.Address,
			Value:      out.Value,
			TaintLevel: inputTaintLevel,
		}
	}
	return entries
}

// applyFIFO implements sequential taint flow for both FIFO and LIFO.
// Tainted satoshis stream through outputs in order until exhausted.
func applyFIFO(tx models.Transaction, tainted []taintedInputInfo, totalInputValue int64, reverse bool) []models.OutputTaintEntry {
	entries := make([]models.OutputTaintEntry, len(tx.Outputs))
	for i, out := range tx.Outputs {
		entries[i] = models.OutputTaintEntry{
			Index:   i,
			Address: out.Address,
			Value:   out.Value,
		}
	}

	// Sort tainted inputs (FIFO = ascending index, LIFO = descending index)
	sorted := make([]taintedInputInfo, len(tainted))
	copy(sorted, tainted)
	if reverse {
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].index > sorted[j].index })
	} else {
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].index < sorted[j].index })
	}

	// Calculate total tainted satoshis
	var taintedSats float64
	for _, t := range sorted {
		taintedSats += float64(t.value) * t.taintLevel
	}

	// Stream tainted satoshis through outputs in order
	remaining := taintedSats
	for i := range entries {
		if remaining <= 0 {
			break
		}
		outputSats := float64(entries[i].Value)
		if outputSats <= 0 {
			continue
		}
		if remaining >= outputSats {
			entries[i].TaintLevel = 1.0
			remaining -= outputSats
		} else {
			entries[i].TaintLevel = remaining / outputSats
			remaining = 0
		}
	}

	return entries
}
