package heuristics

import (
	"sync"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// CPFP (Child-Pays-For-Parent) Forensics Engine
//
// When a CPFP transaction is detected, it provides critical forensic intelligence:
//
//   1. It CONFIRMS the child creator controls the output address
//      (only the owner can create a valid spending transaction)
//   2. It reveals the receiver's wallet software through fee estimation strategy
//   3. If the child consolidates other inputs alongside the accelerated UTXO,
//      those inputs are now CIOH-linked to the receiver
//   4. The urgency of the CPFP reveals time-sensitivity (possible scam exit)
//
// Detection: A transaction spending an UNCONFIRMED output with a significantly
// higher fee rate than the parent is a CPFP transaction.
//
// References:
//   - Bitcoin Core CPFP documentation
//   - Murch, "An Evaluation of Coin Selection Strategies" (2017)

// CPFPEvent records a Child-Pays-For-Parent event
type CPFPEvent struct {
	ParentTxID      string  `json:"parentTxid"`
	ChildTxID       string  `json:"childTxid"`
	ParentFeeRate   float64 `json:"parentFeeRate"`   // sat/vB
	ChildFeeRate    float64 `json:"childFeeRate"`    // sat/vB
	EffectiveFeeRate float64 `json:"effectiveFeeRate"` // Combined package rate
	SpentOutputIdx  int     `json:"spentOutputIdx"`  // Which parent output was spent
	ConfirmedOwner  string  `json:"confirmedOwner"`  // Address confirmed as owner
	AdditionalInputs int    `json:"additionalInputs"` // Extra inputs in child (CIOH link)
	LinkedAddresses []string `json:"linkedAddresses"` // All addresses linked via CIOH in child
	IsAccelerating  bool    `json:"isAccelerating"`  // Child fee >> parent fee
}

// DetectCPFP checks if a transaction is a CPFP child accelerating an unconfirmed parent.
// This confirms ownership: only the address owner can create a spending transaction.
func DetectCPFP(childTx models.Transaction, parentTx *models.Transaction) *CPFPEvent {
	if parentTx == nil || len(childTx.Inputs) == 0 {
		return nil
	}

	// Find which child input spends a parent output
	spentIdx := -1
	for _, in := range childTx.Inputs {
		if in.Txid == parentTx.Txid {
			spentIdx = int(in.Vout)
			break
		}
	}

	if spentIdx < 0 {
		return nil // Child doesn't spend parent
	}

	// Calculate fee rates
	parentFeeRate := 0.0
	childFeeRate := 0.0

	if parentTx.Vsize > 0 {
		parentFeeRate = float64(parentTx.Fee) / float64(parentTx.Vsize)
	}
	if childTx.Vsize > 0 {
		childFeeRate = float64(childTx.Fee) / float64(childTx.Vsize)
	}

	// CPFP: child fee rate should be significantly higher than parent
	isAccelerating := childFeeRate > parentFeeRate*1.5

	if !isAccelerating && childFeeRate <= parentFeeRate {
		return nil // Not a CPFP pattern
	}

	// Effective package fee rate
	totalFee := parentTx.Fee + childTx.Fee
	totalSize := parentTx.Vsize + childTx.Vsize
	effectiveRate := 0.0
	if totalSize > 0 {
		effectiveRate = float64(totalFee) / float64(totalSize)
	}

	event := &CPFPEvent{
		ParentTxID:       parentTx.Txid,
		ChildTxID:        childTx.Txid,
		ParentFeeRate:    parentFeeRate,
		ChildFeeRate:     childFeeRate,
		EffectiveFeeRate: effectiveRate,
		SpentOutputIdx:   spentIdx,
		IsAccelerating:   isAccelerating,
		AdditionalInputs: len(childTx.Inputs) - 1,
	}

	// Confirm owner: the address of the spent parent output
	if spentIdx < len(parentTx.Outputs) {
		event.ConfirmedOwner = parentTx.Outputs[spentIdx].Address
	}

	// Collect all linked addresses from child inputs (CIOH)
	for _, in := range childTx.Inputs {
		if in.Address != "" {
			event.LinkedAddresses = append(event.LinkedAddresses, in.Address)
		}
	}

	return event
}

// ═══════════════════════════════════════════════════════════════════════
// Money Laundering Pattern Detection
// ═══════════════════════════════════════════════════════════════════════

// LaunderingPattern identifies the type of money laundering structure
type LaunderingPattern string

const (
	PatternFanOut      LaunderingPattern = "fan_out"       // 1 input → many outputs (distribution)
	PatternFanIn       LaunderingPattern = "fan_in"        // Many inputs → 1 output (collection)
	PatternLayering    LaunderingPattern = "layering"      // Chain of 1:1 transfers
	PatternStructuring LaunderingPattern = "structuring"   // Amounts just below threshold
	PatternRoundTrip   LaunderingPattern = "round_trip"    // Funds return to origin
	PatternRapidMove   LaunderingPattern = "rapid_movement" // Very fast in→out
	PatternNone        LaunderingPattern = "none"
)

// LaunderingDetection holds the result of pattern analysis
type LaunderingDetection struct {
	Pattern     LaunderingPattern `json:"pattern"`
	Confidence  float64           `json:"confidence"`
	Details     string            `json:"details"`
	RiskScore   float64           `json:"riskScore"` // [0, 1]
	Indicators  []string          `json:"indicators"` // Specific red flags triggered
}

// Common structuring thresholds (in sats) - amounts just below reporting limits
var structuringThresholds = []int64{
	999999999,  // Just below 10 BTC (some exchange threshold)
	99999999,   // Just below 1 BTC
	49999999,   // Just below 0.5 BTC
	9999999,    // Just below 0.1 BTC
}

// DetectLaunderingPattern analyzes a transaction for money laundering indicators
func DetectLaunderingPattern(tx models.Transaction) LaunderingDetection {
	result := LaunderingDetection{
		Pattern: PatternNone,
	}

	nIn := len(tx.Inputs)
	nOut := len(tx.Outputs)

	if nIn == 0 || nOut == 0 {
		return result
	}

	var indicators []string

	// ═══ Fan-Out Detection ════════════════════════════════════════════
	// 1-2 inputs → 10+ outputs = distribution/structuring
	if nIn <= 2 && nOut >= 10 {
		result.Pattern = PatternFanOut
		result.Confidence = 0.70
		result.Details = "distribution pattern: few inputs, many outputs"
		indicators = append(indicators, "high_output_count")

		// Check if outputs are of similar size (more suspicious)
		if outputsAreSimilar(tx.Outputs, 0.2) {
			result.Confidence += 0.15
			indicators = append(indicators, "similar_output_amounts")
		}
	}

	// ═══ Fan-In Detection ═════════════════════════════════════════════
	// 10+ inputs → 1-2 outputs = collection/consolidation
	if nIn >= 10 && nOut <= 2 && result.Pattern == PatternNone {
		result.Pattern = PatternFanIn
		result.Confidence = 0.65
		result.Details = "collection pattern: many inputs, few outputs"
		indicators = append(indicators, "high_input_count")
	}

	// ═══ Layering Detection ═══════════════════════════════════════════
	// 1 input → 2 outputs (payment + change) in a chain
	if nIn == 1 && nOut == 2 && result.Pattern == PatternNone {
		// Check for layering: one output roughly matches input
		for _, out := range tx.Outputs {
			ratio := float64(out.Value) / float64(tx.Inputs[0].Value)
			if ratio > 0.90 {
				result.Pattern = PatternLayering
				result.Confidence = 0.50
				result.Details = "potential layering: single-hop pass-through"
				indicators = append(indicators, "high_pass_through_ratio")
				break
			}
		}
	}

	// ═══ Structuring Detection ════════════════════════════════════════
	// Outputs just below common thresholds
	for _, out := range tx.Outputs {
		for _, threshold := range structuringThresholds {
			margin := float64(threshold) * 0.05 // 5% margin
			if out.Value > 0 && float64(out.Value) > float64(threshold)-margin &&
				float64(out.Value) <= float64(threshold) {
				if result.Pattern == PatternNone || result.Pattern == PatternStructuring {
					result.Pattern = PatternStructuring
					result.Confidence = 0.75
					result.Details = "amounts just below reporting threshold"
					indicators = append(indicators, "below_threshold_amount")
				}
				break
			}
		}
	}

	// ═══ Rapid Movement Detection ════════════════════════════════════
	// If we have timing data: funds in and out within minutes
	// (This is checked at a higher level via velocity profiling)

	result.Indicators = indicators

	// Calculate risk score
	switch result.Pattern {
	case PatternStructuring:
		result.RiskScore = 0.85
	case PatternFanOut:
		result.RiskScore = 0.70
	case PatternFanIn:
		result.RiskScore = 0.65
	case PatternLayering:
		result.RiskScore = 0.55
	default:
		result.RiskScore = 0.0
	}

	return result
}

// outputsAreSimilar checks if outputs have similar values within tolerance
func outputsAreSimilar(outputs []models.TxOut, tolerance float64) bool {
	if len(outputs) < 2 {
		return false
	}

	// Find median value
	values := make([]int64, len(outputs))
	for i, out := range outputs {
		values[i] = out.Value
	}

	median := values[len(values)/2]
	if median == 0 {
		return false
	}

	// Check how many are within tolerance of median
	similar := 0
	for _, v := range values {
		diff := float64(v-median) / float64(median)
		if diff < 0 {
			diff = -diff
		}
		if diff <= tolerance {
			similar++
		}
	}

	return float64(similar)/float64(len(values)) > 0.7
}

// ═══════════════════════════════════════════════════════════════════════
// Value Fingerprint Registry
// ═══════════════════════════════════════════════════════════════════════

// ValueFingerprint tracks unique transaction values for cross-tx linking.
// If a scammer receives 1.23456789 BTC and later sends 1.23456789 BTC,
// the unique decimal precision links them even through intermediaries.
type ValueFingerprint struct {
	Value   int64  `json:"value"`   // Value in sats
	TxID    string `json:"txid"`    // Transaction containing this value
	Address string `json:"address"` // Output address
	IsInput bool   `json:"isInput"` // Was this an input or output?
}

// ValueRegistry maintains a global index of notable values for cross-tx linking
type ValueRegistry struct {
	mu       sync.RWMutex
	// Map of value → all occurrences (limited to values with high specificity)
	values   map[int64][]ValueFingerprint
	// Track "common" values to exclude (round numbers, CoinJoin denoms)
	excluded map[int64]bool
}

var (
	globalValueRegistry *ValueRegistry
	valueRegistryOnce   sync.Once
)

// GetGlobalValueRegistry returns the singleton value registry
func GetGlobalValueRegistry() *ValueRegistry {
	valueRegistryOnce.Do(func() {
		vr := &ValueRegistry{
			values:   make(map[int64][]ValueFingerprint),
			excluded: make(map[int64]bool),
		}
		// Exclude common round values (not useful for fingerprinting)
		for _, v := range []int64{
			100000, 500000, 1000000, 5000000, 10000000, // 0.001-0.1 BTC
			50000000, 100000000, 500000000, 1000000000,  // 0.5-10 BTC
			546, 1000, 10000, // Dust and minimum values
		} {
			vr.excluded[v] = true
		}
		globalValueRegistry = vr
	})
	return globalValueRegistry
}

// RecordValue indexes a transaction value for future cross-referencing
func (vr *ValueRegistry) RecordValue(value int64, txid, address string, isInput bool) {
	if vr.excluded[value] || !isSpecificValue(value) {
		return
	}

	vr.mu.Lock()
	defer vr.mu.Unlock()

	fp := ValueFingerprint{
		Value:   value,
		TxID:    txid,
		Address: address,
		IsInput: isInput,
	}

	vr.values[value] = append(vr.values[value], fp)
}

// FindMatches returns all transactions with the same specific value
func (vr *ValueRegistry) FindMatches(value int64) []ValueFingerprint {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return vr.values[value]
}

// FindLinkedTransactions returns pairs of (output, input) with matching values.
// These are potential cross-tx links where the same entity received and then sent.
func (vr *ValueRegistry) FindLinkedTransactions(value int64) (outputs, inputs []ValueFingerprint) {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	for _, fp := range vr.values[value] {
		if fp.IsInput {
			inputs = append(inputs, fp)
		} else {
			outputs = append(outputs, fp)
		}
	}
	return
}

// isSpecificValue checks if a value has high enough precision to be useful.
// Values like 123456789 (1.23456789 BTC) are specific. Values like 100000000 are not.
func isSpecificValue(value int64) bool {
	if value <= 0 {
		return false
	}

	// Count trailing zeros — fewer = more specific
	trailingZeros := 0
	v := value
	for v > 0 && v%10 == 0 {
		trailingZeros++
		v /= 10
	}

	// Values with 4+ trailing zeros are "round" and not specific
	return trailingZeros < 4
}

// ═══════════════════════════════════════════════════════════════════════
// Address Poisoning Detection
// ═══════════════════════════════════════════════════════════════════════

// AddressPoisoningEvent records when an attacker sends a small tx from
// a lookalike address, hoping the victim will copy it from history
type AddressPoisoningEvent struct {
	TargetAddress   string `json:"targetAddress"`   // Victim's real address
	PoisonAddress   string `json:"poisonAddress"`   // Attacker's lookalike address
	SimilarityScore float64 `json:"similarityScore"` // How similar (0-1)
	PoisonTxID      string `json:"poisonTxid"`      // Transaction used for poisoning
	PoisonValue     int64  `json:"poisonValue"`     // Amount sent (usually tiny)
}

// DetectAddressPoisoning checks if any output addresses are suspiciously
// similar to input addresses (prefix/suffix match attacks)
func DetectAddressPoisoning(tx models.Transaction) []AddressPoisoningEvent {
	var events []AddressPoisoningEvent

	inputAddrs := make(map[string]bool)
	for _, in := range tx.Inputs {
		if in.Address != "" {
			inputAddrs[in.Address] = true
		}
	}

	for _, out := range tx.Outputs {
		if out.Address == "" || inputAddrs[out.Address] {
			continue
		}

		// Check output against all inputs for suspicious similarity
		for inputAddr := range inputAddrs {
			score := addressSimilarity(inputAddr, out.Address)
			if score > 0.6 && score < 1.0 && out.Value < 10000 {
				events = append(events, AddressPoisoningEvent{
					TargetAddress:   inputAddr,
					PoisonAddress:   out.Address,
					SimilarityScore: score,
					PoisonTxID:      tx.Txid,
					PoisonValue:     out.Value,
				})
			}
		}
	}

	return events
}

// addressSimilarity computes similarity between two addresses.
// Focuses on prefix and suffix match (how poisoning attacks work).
func addressSimilarity(a, b string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}

	// Check prefix match length
	prefixLen := 0
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		if a[i] == b[i] {
			prefixLen++
		} else {
			break
		}
	}

	// Check suffix match length
	suffixLen := 0
	for i := 0; i < minLen; i++ {
		if a[len(a)-1-i] == b[len(b)-1-i] {
			suffixLen++
		} else {
			break
		}
	}

	// Score: weighted combination of prefix and suffix match
	// Prefix matters more for human visual comparison
	score := (float64(prefixLen)*0.6 + float64(suffixLen)*0.4) / float64(minLen)
	return score
}
