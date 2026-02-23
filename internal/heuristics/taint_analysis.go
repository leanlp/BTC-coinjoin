package heuristics

import (
	"math"
)

// Taint Propagation & Risk Scoring
//
// Traces the flow of funds from known illicit sources through the
// transaction graph. Uses a FIFO (First-In-First-Out) model:
//
//   Poison model:     ANY input from a tainted source → ALL outputs tainted
//   Haircut model:    Taint proportionally distributed by output value
//   FIFO model:       Taint follows value through first-in-first-out ordering
//
// We implement the haircut model (proportional allocation) which is the
// standard used by FATF and most regulatory frameworks.
//
// Risk levels:
//   clean:     No taint exposure
//   low:       < 10% tainted value
//   medium:    10-25% tainted value
//   high:      25-50% tainted value
//   critical:  > 50% tainted value
//
// References:
//   - FATF, "Virtual Assets Red Flag Indicators" (2020)
//   - FinCEN, "Advisory on Illicit Activity Involving Convertible Virtual Currency"
//   - Möser et al., "An Empirical Analysis of Traceability" (USENIX 2013)

// TaintSource represents a known source of illicit funds
type TaintSource struct {
	Address    string  `json:"address"`
	Category   string  `json:"category"`   // "darknet"/"ransomware"/"theft"/"fraud"/"sanctions"/"mixer"
	TaintLevel float64 `json:"taintLevel"` // 0.0 to 1.0
	Label      string  `json:"label"`      // "Hydra Market"/"Lazarus Group"/etc
}

// TaintResult holds the risk assessment for an address or transaction
type TaintResult struct {
	RiskScore      float64       `json:"riskScore"`      // 0.0 (clean) to 1.0 (fully tainted)
	RiskLevel      string        `json:"riskLevel"`      // "clean"/"low"/"medium"/"high"/"critical"
	TaintSources   []TaintSource `json:"taintSources"`   // Contributing taint sources
	HopsFromSource int           `json:"hopsFromSource"` // Shortest path to tainted source
	TaintedRatio   float64       `json:"taintedRatio"`   // Fraction of tx value from tainted sources
}

// TaintMap is a mapping from address to accumulated taint level
type TaintMap map[string]float64

// NewTaintMap creates a new empty taint map
func NewTaintMap() TaintMap {
	return make(TaintMap)
}

// SeedTaint initializes taint for known illicit addresses
func (tm TaintMap) SeedTaint(sources []TaintSource) {
	for _, src := range sources {
		current, exists := tm[src.Address]
		if !exists || src.TaintLevel > current {
			tm[src.Address] = src.TaintLevel
		}
	}
}

// PropagateTaintHaircut spreads taint through a transaction using the
// haircut (proportional) model. Each output receives a share of taint
// proportional to its value relative to total output value.
//
// If input addresses carry taint T_total, each output j receives:
//
//	T_j = T_total × (value_j / Σvalue_all_outputs)
func (tm TaintMap) PropagateTaintHaircut(inputAddrs []string, inputValues []int64,
	outputAddrs []string, outputValues []int64) {

	if len(inputAddrs) != len(inputValues) || len(outputAddrs) != len(outputValues) {
		return
	}

	// Compute total tainted value coming in
	totalTaint := 0.0
	totalInputValue := int64(0)
	for i, addr := range inputAddrs {
		if taint, exists := tm[addr]; exists && taint > 0 {
			totalTaint += taint * float64(inputValues[i])
		}
		totalInputValue += inputValues[i]
	}

	if totalTaint <= 0 || totalInputValue <= 0 {
		return
	}

	// Weighted taint level across all inputs
	weightedTaint := totalTaint / float64(totalInputValue)

	// Distribute proportionally to outputs
	totalOutputValue := int64(0)
	for _, v := range outputValues {
		totalOutputValue += v
	}
	if totalOutputValue <= 0 {
		return
	}

	for i, addr := range outputAddrs {
		outputShare := float64(outputValues[i]) / float64(totalOutputValue)
		outputTaint := weightedTaint * outputShare

		// Taint accumulates (never decreases, worst-case model)
		if current, exists := tm[addr]; !exists || outputTaint > current {
			tm[addr] = math.Min(1.0, outputTaint)
		}
	}
}

// GetTaint returns the taint level for an address
func (tm TaintMap) GetTaint(addr string) float64 {
	return tm[addr]
}

// AssessRisk computes a risk assessment for a given taint level
func AssessRisk(taintLevel float64, hops int) TaintResult {
	result := TaintResult{
		RiskScore:      math.Round(taintLevel*1000) / 1000,
		HopsFromSource: hops,
		TaintedRatio:   math.Round(taintLevel*100) / 100,
	}

	// Apply hop decay to risk score (farther = less risky)
	if hops > 0 {
		decayFactor := math.Pow(0.85, float64(hops-1))
		result.RiskScore = math.Round(taintLevel*decayFactor*1000) / 1000
	}

	// Classify risk level
	result.RiskLevel = classifyRisk(result.RiskScore)

	return result
}

// classifyRisk maps a risk score to a risk level
func classifyRisk(score float64) string {
	switch {
	case score <= 0.01:
		return "clean"
	case score <= 0.10:
		return "low"
	case score <= 0.25:
		return "medium"
	case score <= 0.50:
		return "high"
	default:
		return "critical"
	}
}

// ComputeTransactionRisk assesses the overall risk of a transaction
// based on the taint levels of its inputs.
func ComputeTransactionRisk(tm TaintMap, inputAddrs []string, inputValues []int64) TaintResult {
	if len(inputAddrs) != len(inputValues) {
		return TaintResult{RiskLevel: "clean"}
	}

	totalValue := int64(0)
	taintedValue := float64(0)
	var sources []TaintSource

	for i, addr := range inputAddrs {
		totalValue += inputValues[i]
		if taint, exists := tm[addr]; exists && taint > 0 {
			taintedValue += taint * float64(inputValues[i])
			sources = append(sources, TaintSource{
				Address:    addr,
				TaintLevel: taint,
			})
		}
	}

	if totalValue <= 0 {
		return TaintResult{RiskLevel: "clean"}
	}

	overallTaint := taintedValue / float64(totalValue)

	result := TaintResult{
		RiskScore:    math.Round(overallTaint*1000) / 1000,
		TaintedRatio: math.Round(overallTaint*100) / 100,
		TaintSources: sources,
	}
	result.RiskLevel = classifyRisk(result.RiskScore)

	return result
}

// IsTainted checks if an address has any taint exposure
func (tm TaintMap) IsTainted(addr string) bool {
	return tm[addr] > 0.01
}

// GetTaintedAddresses returns all addresses with taint above threshold
func (tm TaintMap) GetTaintedAddresses(threshold float64) []string {
	var addrs []string
	for addr, taint := range tm {
		if taint >= threshold {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}
