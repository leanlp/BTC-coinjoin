package heuristics

import (
	"math"
	"sort"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// UTXO Graph Topology Analysis Module
//
// The shape of a transaction reveals its purpose. Different entity types
// produce characteristically different topologies:
//
//   - Simple payment:  1-in-2-out (or 1-in-1-out)
//   - Peel chain:      1-in-2-out repeating
//   - Consolidation:   N-in-1-out (UTXO hygiene)
//   - Batch payout:    1-in-M-out (exchange withdrawal)
//   - Mixing:          N-in-N-out symmetric (CoinJoin)
//   - Hub:             High fan-in AND fan-out (service/exchange hot wallet)
//
// Graph metrics computed:
//   - Fan-in / Fan-out ratio
//   - I/O Symmetry (|I-O|/max(I,O))
//   - Gini coefficient of output values (value concentration)
//   - Shape classification
//
// References:
//   - Ron & Shamir, "Quantitative Analysis of the Full Bitcoin Transaction Graph" (FC 2013)
//   - Harrigan & Fretter, "The Unreasonable Effectiveness of Address Clustering" (2016)
//   - Meiklejohn et al., "A Fistful of Bitcoins" (IMC 2013)

// AnalyzeTopology computes graph-theoretic metrics for a transaction
// and classifies its shape.
func AnalyzeTopology(tx models.Transaction) models.TopologyResult {
	result := models.TopologyResult{
		FanIn:  len(tx.Inputs),
		FanOut: len(tx.Outputs),
	}

	// 1. I/O Symmetry: 0 = perfectly symmetric, 1 = maximally asymmetric
	maxIO := math.Max(float64(result.FanIn), float64(result.FanOut))
	if maxIO > 0 {
		result.IOSymmetry = math.Round(math.Abs(float64(result.FanIn)-float64(result.FanOut))*100/maxIO) / 100
	}

	// 2. Gini Coefficient of output values
	result.GiniCoefficient = computeGiniCoefficient(tx.Outputs)

	// 3. Value concentration classification
	result.ValueConcentration = classifyValueConcentration(result.GiniCoefficient)

	// 4. Hub detection: high fan-in OR high fan-out indicates service/exchange
	result.IsHub = result.FanIn >= 10 || result.FanOut >= 10

	// 5. Shape classification
	result.Shape = classifyTxShape(result, tx)

	return result
}

// computeGiniCoefficient calculates the Gini coefficient for output values.
// Gini = 0 → all outputs have equal value (perfect mix)
// Gini = 1 → all value concentrated in one output
//
// Algorithm: G = (2 * Σᵢ i*yᵢ) / (n * Σᵢ yᵢ) - (n+1)/n
// where y is sorted in ascending order.
func computeGiniCoefficient(outputs []models.TxOut) float64 {
	n := len(outputs)
	if n <= 1 {
		return 0
	}

	// Extract and sort values
	values := make([]float64, n)
	totalValue := 0.0
	for i, out := range outputs {
		values[i] = float64(out.Value)
		totalValue += float64(out.Value)
	}

	if totalValue <= 0 {
		return 0
	}

	sort.Float64s(values)

	// Compute Gini
	weightedSum := 0.0
	for i, v := range values {
		weightedSum += float64(i+1) * v
	}

	gini := (2*weightedSum)/(float64(n)*totalValue) - float64(n+1)/float64(n)

	// Clamp to [0, 1]
	if gini < 0 {
		gini = 0
	}
	if gini > 1 {
		gini = 1
	}

	return math.Round(gini*100) / 100
}

// classifyValueConcentration maps Gini to human-readable bands
func classifyValueConcentration(gini float64) string {
	switch {
	case gini <= 0.2:
		return "dispersed" // Very equal outputs (mixing)
	case gini <= 0.5:
		return "moderate" // Normal payment distribution
	default:
		return "concentrated" // One output dominates (consolidation)
	}
}

// classifyTxShape determines the transaction topology pattern
func classifyTxShape(topo models.TopologyResult, tx models.Transaction) string {
	fanIn := topo.FanIn
	fanOut := topo.FanOut

	// Simple payment: 1-2 inputs, 1-2 outputs
	if fanIn <= 2 && fanOut <= 2 {
		if fanIn == 1 && fanOut == 2 {
			return "peel-step"
		}
		return "simple-payment"
	}

	// Consolidation: many inputs, 1 output
	if fanIn >= 3 && fanOut == 1 {
		return "consolidation"
	}

	// Batch payout: 1-3 inputs, many outputs
	if fanIn <= 3 && fanOut >= 5 {
		return "batch-payout"
	}

	// Mixing: symmetric I/O with equal output values
	if topo.IOSymmetry <= 0.2 && fanIn >= 5 && fanOut >= 5 {
		return "mixing"
	}

	// Hub: very high fan-in or fan-out
	if fanIn >= 10 || fanOut >= 10 {
		return "hub"
	}

	// Multi-output payment (2-4 outputs from multiple inputs)
	if fanIn >= 2 && fanOut >= 3 && fanOut <= 5 {
		return "multi-payment"
	}

	return "complex"
}

// ComputeFanRatio returns the fan-out/fan-in ratio.
// > 1.0 = fan-out dominant (batch payout pattern)
// < 1.0 = fan-in dominant (consolidation pattern)
// ≈ 1.0 = symmetric (mixing pattern)
func ComputeFanRatio(tx models.Transaction) float64 {
	if len(tx.Inputs) == 0 {
		return 0
	}
	ratio := float64(len(tx.Outputs)) / float64(len(tx.Inputs))
	return math.Round(ratio*100) / 100
}

// ComputeValueFlow analyzes how value moves through the transaction.
// Returns the largest output as a fraction of total input value.
func ComputeValueFlow(tx models.Transaction) float64 {
	totalInput := int64(0)
	for _, in := range tx.Inputs {
		totalInput += in.Value
	}
	if totalInput <= 0 {
		return 0
	}

	maxOutput := int64(0)
	for _, out := range tx.Outputs {
		if out.Value > maxOutput {
			maxOutput = out.Value
		}
	}

	return math.Round(float64(maxOutput)*100/float64(totalInput)) / 100
}
