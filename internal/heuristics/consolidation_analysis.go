package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Consolidation Intelligence
//
// How an entity manages UTXOs reveals its identity with high reliability:
//
//   Exchanges: consolidate during low-fee weekends/nights, massive fan-in
//   Services:  batch-consolidate weekly, moderate fan-in
//   Privacy:   avoid consolidation entirely (spend individual UTXOs)
//   Miners:    consolidate coinbase outputs after 100-block maturity
//
// Consolidation efficiency metrics:
//   - Input reduction ratio: (inputs - outputs) / inputs
//   - Fee rate timing: low fee = strategic, high fee = urgent
//   - Value preservation: total output / total input (higher = more efficient)
//
// References:
//   - Erdin et al., "How to Not Get Caught" (ESORICS 2023)
//   - Karame et al., "Misbehavior in Bitcoin" (CCS 2012)

// ConsolidationResult holds UTXO consolidation analysis
type ConsolidationResult struct {
	IsConsolidation   bool    `json:"isConsolidation"`   // Transaction is a UTXO consolidation
	ConsolidationType string  `json:"consolidationType"` // "exchange-sweep"/"service-batch"/"user-cleanup"/"miner-maturity"/"privacy-aware"
	InputReduction    float64 `json:"inputReduction"`    // (inputs - outputs) / inputs → 1.0 = maximum consolidation
	FeeEfficiency     float64 `json:"feeEfficiency"`     // Output value / input value → higher = better
	IsStrategicTiming bool    `json:"isStrategicTiming"` // Low fee rate suggests planned consolidation
	EstimatedSavings  int64   `json:"estimatedSavings"`  // Estimated future fee savings (sats)
}

// AnalyzeConsolidation detects and classifies UTXO consolidation patterns
func AnalyzeConsolidation(tx models.Transaction) ConsolidationResult {
	result := ConsolidationResult{
		ConsolidationType: "none",
	}

	nIn := len(tx.Inputs)
	nOut := len(tx.Outputs)

	// Consolidation: many inputs → few outputs (typically 1)
	if nIn < 3 || nOut > 2 {
		return result
	}

	result.IsConsolidation = true

	// Input reduction ratio
	if nIn > 0 {
		result.InputReduction = math.Round(float64(nIn-nOut)*100/float64(nIn)) / 100
	}

	// Fee efficiency (value preservation)
	totalInput := int64(0)
	for _, in := range tx.Inputs {
		totalInput += in.Value
	}
	totalOutput := int64(0)
	for _, out := range tx.Outputs {
		totalOutput += out.Value
	}
	if totalInput > 0 {
		result.FeeEfficiency = math.Round(float64(totalOutput)*10000/float64(totalInput)) / 10000
	}

	// Strategic timing: low fee rate indicates planned consolidation
	if tx.Fee > 0 && tx.Vsize > 0 {
		feeRate := float64(tx.Fee) / float64(tx.Vsize)
		result.IsStrategicTiming = feeRate < 5.0 // < 5 sat/vB = low-fee environment
	}

	// Estimate future fee savings from consolidation
	// Each UTXO spent costs ~68 vbytes (P2WPKH input)
	// By consolidating N UTXOs now, we save (N-1) × 68 vbytes in future txs
	savedInputs := nIn - 1
	result.EstimatedSavings = int64(savedInputs * 68 * 10) // Assume 10 sat/vB future fee

	// Classify consolidation type
	result.ConsolidationType = classifyConsolidationType(tx, result)

	return result
}

// classifyConsolidationType determines the entity type from consolidation pattern
func classifyConsolidationType(tx models.Transaction, cr ConsolidationResult) string {
	nIn := len(tx.Inputs)
	nOut := len(tx.Outputs)

	switch {
	case nIn >= 50 && nOut == 1 && cr.IsStrategicTiming:
		return "exchange-sweep" // Massive sweep during low fees

	case nIn >= 20 && nOut == 1:
		return "exchange-sweep" // Large sweep regardless of timing

	case nIn >= 10 && nOut <= 2 && cr.IsStrategicTiming:
		return "service-batch" // Service consolidating during low fees

	case nIn >= 5 && nOut == 1:
		return "user-cleanup" // User cleaning up dust/small UTXOs

	case nIn >= 3 && nOut == 1 && hasEqualInputValues(tx):
		return "miner-maturity" // Consolidating coinbase outputs (equal block rewards)

	case nIn >= 3 && nOut <= 2:
		return "user-cleanup" // General UTXO hygiene

	default:
		return "generic"
	}
}

// hasEqualInputValues checks if most inputs have similar values
// (indicator of coinbase or pool payout consolidation)
func hasEqualInputValues(tx models.Transaction) bool {
	if len(tx.Inputs) < 3 {
		return false
	}

	// Check if >50% of inputs have the same value (±5%)
	valueBuckets := make(map[int64]int)
	for _, in := range tx.Inputs {
		// Round to nearest 1000 sats for bucketing
		bucket := in.Value / 1000 * 1000
		valueBuckets[bucket]++
	}

	threshold := len(tx.Inputs) / 2
	for _, count := range valueBuckets {
		if count >= threshold {
			return true
		}
	}

	return false
}

// ComputeConsolidationEfficiency calculates how much the entity
// saves in future fees by consolidating now.
// Returns the break-even fee rate: if future fees exceed this rate,
// consolidating now was profitable.
func ComputeConsolidationEfficiency(inputCount int, feesPaid int64) float64 {
	if inputCount <= 1 || feesPaid <= 0 {
		return 0
	}

	// Future savings: (inputCount - 1) inputs × ~68 vbytes each
	futureVbytes := float64(inputCount-1) * 68

	// Break-even: feesPaid / futureVbytes = fee_rate at which this consolidation pays off
	breakEven := float64(feesPaid) / futureVbytes

	return math.Round(breakEven*100) / 100
}
