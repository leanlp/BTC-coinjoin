package heuristics

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Scammer Behavior Analysis Engine
//
// Implements three critical scammer-tracking techniques from forensics research:
//
//   T1. UTXO Consolidation Timing Attack
//       The single most detectable moment in a scammer's lifecycle is when
//       they consolidate stolen funds. All those separate UTXOs must merge
//       before cashing out — and the merger links everything.
//
//   T2. Velocity Pattern Detection
//       Different scam types produce different transaction velocity profiles:
//       rug pulls (spike→drain), pig butchering (slow→burst), ransomware
//       (single→peel), Ponzi (steady→steady).
//
//   T10. Self-Spend Detection
//       Detect when ALL outputs go to addresses in the same cluster as inputs.
//       Eliminates false positives by marking internal treasury movements.
//
// References:
//   - Chainalysis, "2024 Crypto Crime Report"
//   - FATF, "Virtual Assets Red Flag Indicators" (2020)
//   - Meiklejohn et al., "A Fistful of Bitcoins" (IMC 2013)

// ═══════════════════════════════════════════════════════════════════════
// T1: UTXO Consolidation Timing Attack
// ═══════════════════════════════════════════════════════════════════════

// ConsolidationEvent records a detected consolidation
type ConsolidationEvent struct {
	TxID             string    `json:"txid"`
	InputCount       int       `json:"inputCount"`
	TotalInputValue  int64     `json:"totalInputValue"`
	OutputCount      int       `json:"outputCount"`
	TaintedInputs    int       `json:"taintedInputs"`    // How many inputs trace to flagged addresses
	TaintedRatio     float64   `json:"taintedRatio"`     // taintedInputs / inputCount
	IsSuspicious     bool      `json:"isSuspicious"`
	RiskScore        float64   `json:"riskScore"`        // [0, 1]
	DetectedAt       time.Time `json:"detectedAt"`
	Reason           string    `json:"reason"`           // Why it's suspicious
}

// DetectConsolidation identifies consolidation patterns in a transaction.
// A consolidation is: many inputs → few outputs (typically 1-2).
// Scammers consolidate before exchange deposits.
func DetectConsolidation(tx models.Transaction, taintExposure float64) *ConsolidationEvent {
	nIn := len(tx.Inputs)
	nOut := len(tx.Outputs)

	// Minimum 5 inputs and ≤2 outputs to flag as consolidation
	if nIn < 5 || nOut > 2 {
		return nil
	}

	// Compute total input value
	totalInputValue := int64(0)
	for _, in := range tx.Inputs {
		totalInputValue += in.Value
	}

	event := &ConsolidationEvent{
		TxID:            tx.Txid,
		InputCount:      nIn,
		TotalInputValue: totalInputValue,
		OutputCount:     nOut,
		DetectedAt:      time.Now(),
	}

	// Fan-in ratio: higher = more suspicious
	fanInRatio := float64(nIn) / float64(nOut)

	// Risk scoring:
	// 1. High fan-in ratio (>10:1) = very suspicious
	// 2. Tainted inputs = critical
	// 3. Large total value = more concerning
	risk := 0.0

	if fanInRatio > 20 {
		risk += 0.35
	} else if fanInRatio > 10 {
		risk += 0.25
	} else if fanInRatio > 5 {
		risk += 0.15
	}

	// Taint factor
	if taintExposure > 0 {
		event.TaintedRatio = taintExposure
		risk += taintExposure * 0.40 // Taint is the strongest signal
	}

	// Value factor: >1 BTC consolidation gets attention
	if totalInputValue > 100000000 { // >1 BTC
		risk += 0.15
	} else if totalInputValue > 10000000 { // >0.1 BTC
		risk += 0.08
	}

	// All inputs same value = likely CoinJoin outputs being consolidated (red flag)
	if allInputsSameValue(tx.Inputs) && nIn > 5 {
		risk += 0.20
		event.Reason = "consolidation of equal-value CoinJoin outputs"
	} else if taintExposure > 0.5 {
		event.Reason = "consolidation of tainted UTXOs"
	} else {
		event.Reason = "high fan-in consolidation pattern"
	}

	event.RiskScore = math.Min(risk, 1.0)
	event.IsSuspicious = risk > 0.4

	return event
}

func allInputsSameValue(inputs []models.TxIn) bool {
	if len(inputs) < 2 {
		return false
	}
	for i := 1; i < len(inputs); i++ {
		if inputs[i].Value != inputs[0].Value {
			return false
		}
	}
	return true
}

// ═══════════════════════════════════════════════════════════════════════
// T2: Velocity Pattern Detection
// ═══════════════════════════════════════════════════════════════════════

// ScamType classifies the type of scam based on velocity patterns
type ScamType string

const (
	ScamTypeRugPull       ScamType = "rug_pull"        // Massive inflow → immediate drainage
	ScamTypePigButchering ScamType = "pig_butchering"  // Slow accumulation → sudden cash-out
	ScamTypeRansomware    ScamType = "ransomware"      // Single large payment → peel chain
	ScamTypePonzi         ScamType = "ponzi"           // Steady inflows → matching outflows
	ScamTypeExitScam      ScamType = "exit_scam"       // Long buildup → vanish
	ScamTypeUnknown       ScamType = "unknown"
)

// VelocityProfile captures the temporal flow pattern of an address/cluster
type VelocityProfile struct {
	Address          string        `json:"address"`
	AnalysisPeriod   time.Duration `json:"analysisPeriod"`
	TotalInflow      int64         `json:"totalInflow"`
	TotalOutflow     int64         `json:"totalOutflow"`
	InTxCount        int           `json:"inTxCount"`
	OutTxCount       int           `json:"outTxCount"`
	AvgInflowRate    float64       `json:"avgInflowRate"`    // sats/hour
	AvgOutflowRate   float64       `json:"avgOutflowRate"`   // sats/hour
	PeakInflowRate   float64       `json:"peakInflowRate"`   // sats/hour (highest window)
	PeakOutflowRate  float64       `json:"peakOutflowRate"`  // sats/hour (highest window)
	AvgHoldingTime   float64       `json:"avgHoldingTime"`   // hours between receive and spend
	FlowRatio        float64       `json:"flowRatio"`        // outflow/inflow
	BurstFactor      float64       `json:"burstFactor"`      // peak/avg ratio (higher = more bursty)
	ClassifiedAs     ScamType      `json:"classifiedAs"`
	Confidence       float64       `json:"confidence"`
}

// TxFlowEntry is a single inflow or outflow event for velocity analysis
type TxFlowEntry struct {
	Timestamp time.Time
	Value     int64
	IsInflow  bool
	TxID      string
}

// ClassifyVelocity analyzes temporal flow patterns and classifies scam type
func ClassifyVelocity(flows []TxFlowEntry) VelocityProfile {
	profile := VelocityProfile{
		ClassifiedAs: ScamTypeUnknown,
	}

	if len(flows) < 3 {
		return profile
	}

	// Sort by timestamp
	sorted := make([]TxFlowEntry, len(flows))
	copy(sorted, flows)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	// Compute basic metrics
	firstTime := sorted[0].Timestamp
	lastTime := sorted[len(sorted)-1].Timestamp
	duration := lastTime.Sub(firstTime)
	profile.AnalysisPeriod = duration

	if duration < time.Minute {
		return profile
	}

	durationHours := duration.Hours()

	for _, flow := range sorted {
		if flow.IsInflow {
			profile.TotalInflow += flow.Value
			profile.InTxCount++
		} else {
			profile.TotalOutflow += flow.Value
			profile.OutTxCount++
		}
	}

	if durationHours > 0 {
		profile.AvgInflowRate = float64(profile.TotalInflow) / durationHours
		profile.AvgOutflowRate = float64(profile.TotalOutflow) / durationHours
	}

	if profile.TotalInflow > 0 {
		profile.FlowRatio = float64(profile.TotalOutflow) / float64(profile.TotalInflow)
	}

	// Compute holding time: average time between receiving and spending
	var holdingTimes []float64
	inflowTimes := make([]time.Time, 0)
	outflowTimes := make([]time.Time, 0)

	for _, flow := range sorted {
		if flow.IsInflow {
			inflowTimes = append(inflowTimes, flow.Timestamp)
		} else {
			outflowTimes = append(outflowTimes, flow.Timestamp)
		}
	}

	// Match inflows to outflows (FIFO) to estimate holding time
	for i := 0; i < len(inflowTimes) && i < len(outflowTimes); i++ {
		ht := outflowTimes[i].Sub(inflowTimes[i]).Hours()
		if ht >= 0 {
			holdingTimes = append(holdingTimes, ht)
		}
	}

	if len(holdingTimes) > 0 {
		sum := 0.0
		for _, ht := range holdingTimes {
			sum += ht
		}
		profile.AvgHoldingTime = sum / float64(len(holdingTimes))
	}

	// Compute burst factor: peak 1-hour rate vs. average rate
	peakIn, peakOut := computePeakRates(sorted, time.Hour)
	profile.PeakInflowRate = peakIn
	profile.PeakOutflowRate = peakOut

	if profile.AvgOutflowRate > 0 {
		profile.BurstFactor = profile.PeakOutflowRate / profile.AvgOutflowRate
	}

	// ═══ Classification Logic ════════════════════════════════════════
	// Based on: holding time, burst factor, flow ratio, temporal pattern

	switch {
	case profile.AvgHoldingTime < 2 && profile.BurstFactor > 10 && profile.FlowRatio > 0.9:
		// Very short holding + extreme burst + drain almost everything
		profile.ClassifiedAs = ScamTypeRugPull
		profile.Confidence = 0.85

	case profile.AvgHoldingTime > 168 && profile.BurstFactor > 5 && profile.FlowRatio > 0.8:
		// Long accumulation (>1 week) then sudden drain
		profile.ClassifiedAs = ScamTypePigButchering
		profile.Confidence = 0.80

	case profile.InTxCount <= 3 && profile.OutTxCount > 5 && profile.AvgHoldingTime < 24:
		// Few large inputs → many small outputs (peeling)
		profile.ClassifiedAs = ScamTypeRansomware
		profile.Confidence = 0.75

	case profile.InTxCount > 10 && profile.OutTxCount > 10 &&
		math.Abs(profile.FlowRatio-1.0) < 0.2 && profile.AvgHoldingTime < 48:
		// Steady in/out with similar volumes — Ponzi recycling
		profile.ClassifiedAs = ScamTypePonzi
		profile.Confidence = 0.70

	case profile.AvgHoldingTime > 720 && profile.FlowRatio > 0.95:
		// Very long buildup (>1 month) then full drain
		profile.ClassifiedAs = ScamTypeExitScam
		profile.Confidence = 0.75
	}

	return profile
}

// computePeakRates finds the maximum inflow and outflow in any window of `windowSize`
func computePeakRates(flows []TxFlowEntry, windowSize time.Duration) (peakInflow, peakOutflow float64) {
	if len(flows) == 0 {
		return 0, 0
	}

	windowHours := windowSize.Hours()
	if windowHours == 0 {
		windowHours = 1
	}

	for i, startFlow := range flows {
		windowEnd := startFlow.Timestamp.Add(windowSize)
		var inSum, outSum int64

		for j := i; j < len(flows); j++ {
			if flows[j].Timestamp.After(windowEnd) {
				break
			}
			if flows[j].IsInflow {
				inSum += flows[j].Value
			} else {
				outSum += flows[j].Value
			}
		}

		inRate := float64(inSum) / windowHours
		outRate := float64(outSum) / windowHours

		if inRate > peakInflow {
			peakInflow = inRate
		}
		if outRate > peakOutflow {
			peakOutflow = outRate
		}
	}

	return
}

// ═══════════════════════════════════════════════════════════════════════
// T10: Self-Spend Detection
// ═══════════════════════════════════════════════════════════════════════

// SelfSpendResult holds the analysis of whether a tx is a self-transfer
type SelfSpendResult struct {
	IsSelfSpend     bool    `json:"isSelfSpend"`
	Confidence      float64 `json:"confidence"`
	Reason          string  `json:"reason"`
	OutputsInCluster int    `json:"outputsInCluster"` // How many outputs belong to input cluster
	TotalOutputs    int     `json:"totalOutputs"`
}

// DetectSelfSpend checks if all outputs belong to the same entity as the inputs.
// Uses the cluster engine (Union-Find CIOH) to check membership.
func DetectSelfSpend(tx models.Transaction) SelfSpendResult {
	result := SelfSpendResult{
		TotalOutputs: len(tx.Outputs),
	}

	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return result
	}

	clusterEngine := GetGlobalClusterEngine()
	if clusterEngine == nil {
		return result
	}

	// Get the cluster root for the first input address
	inputAddr := tx.Inputs[0].Address
	if inputAddr == "" {
		return result
	}

	inputCluster := clusterEngine.GetCluster(inputAddr)
	if len(inputCluster) == 0 {
		return result
	}

	// Build a set for fast lookup
	clusterSet := make(map[string]bool, len(inputCluster))
	for _, addr := range inputCluster {
		clusterSet[addr] = true
	}

	// Check how many outputs go to addresses in the same cluster
	for _, out := range tx.Outputs {
		if clusterSet[out.Address] {
			result.OutputsInCluster++
		}
	}

	ratio := float64(result.OutputsInCluster) / float64(result.TotalOutputs)

	if ratio >= 1.0 {
		result.IsSelfSpend = true
		result.Confidence = 0.95
		result.Reason = "all outputs belong to same cluster as inputs"
	} else if ratio >= 0.5 {
		result.IsSelfSpend = false // Partial self-spend (change + payment)
		result.Confidence = ratio
		result.Reason = "partial self-spend: some outputs in same cluster"
	}

	return result
}

// ═══════════════════════════════════════════════════════════════════════
// Consolidation Monitor (Persistent)
// ═══════════════════════════════════════════════════════════════════════

// ConsolidationMonitor watches for consolidation events across the mempool
type ConsolidationMonitor struct {
	mu     sync.RWMutex
	events []ConsolidationEvent
	// Track per-address consolidation history
	addrHistory map[string][]ConsolidationEvent
}

var (
	globalConsolidationMonitor *ConsolidationMonitor
	consolidationMonitorOnce   sync.Once
)

// GetGlobalConsolidationMonitor returns the singleton consolidation monitor
func GetGlobalConsolidationMonitor() *ConsolidationMonitor {
	consolidationMonitorOnce.Do(func() {
		globalConsolidationMonitor = &ConsolidationMonitor{
			addrHistory: make(map[string][]ConsolidationEvent),
		}
	})
	return globalConsolidationMonitor
}

// Record stores a consolidation event
func (cm *ConsolidationMonitor) Record(event ConsolidationEvent) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.events = append(cm.events, event)
}

// GetSuspicious returns all suspicious consolidation events
func (cm *ConsolidationMonitor) GetSuspicious() []ConsolidationEvent {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var suspicious []ConsolidationEvent
	for _, e := range cm.events {
		if e.IsSuspicious {
			suspicious = append(suspicious, e)
		}
	}
	return suspicious
}
