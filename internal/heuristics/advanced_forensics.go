package heuristics

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Peeling Chain Graph Reconstruction Engine
//
// A peeling chain is the #1 obfuscation technique for scammers:
//
//   Theft → Addr1 (peel 0.1 BTC) → Addr2 (peel 0.05 BTC) → Addr3 → ... → Exchange
//
// At each hop, a small amount is "peeled off" (sent to an accomplice,
// converted to another crypto, or cashed out), and the large change
// output continues the chain.
//
// This module performs BFS/DFS from a starting address, following the
// "large change" output at each hop, building a complete peeling DAG.
//
// Key insight: The change output is almost always:
//   1. The LARGER of two outputs
//   2. Going to a NEW address (not previously seen)
//   3. Of a similar address type as the input
//
// References:
//   - Möser & Narayanan, "Empirical Analysis of Traceability" (PoPETs 2018)
//   - Meiklejohn et al., "A Fistful of Bitcoins" (IMC 2013)

// PeelHop represents a single step in a peeling chain
type PeelHop struct {
	HopIndex     int     `json:"hopIndex"`     // 0 = start, 1 = first peel, etc.
	TxID         string  `json:"txid"`
	InputValue   int64   `json:"inputValue"`   // Value entering this hop
	PeelValue    int64   `json:"peelValue"`    // Amount "peeled off" (sent to recipient)
	ChangeValue  int64   `json:"changeValue"`  // Amount continuing the chain
	PeelAddress  string  `json:"peelAddress"`  // Where the peel went
	ChangeAddress string `json:"changeAddress"` // Where the chain continues
	PeelRatio    float64 `json:"peelRatio"`    // peelValue / inputValue
	FeesPaid     int64   `json:"feesPaid"`     // Transaction fee at this hop
	Timestamp    time.Time `json:"timestamp,omitempty"`
}

// PeelingChainResult holds the complete peeling chain analysis
type PeelingChainResult struct {
	StartTxID       string     `json:"startTxid"`
	StartAddress    string     `json:"startAddress"`
	TotalHops       int        `json:"totalHops"`
	TotalPeeled     int64      `json:"totalPeeled"`     // Sum of all peel values
	TotalFees       int64      `json:"totalFees"`        // Sum of all fees
	RemainingValue  int64      `json:"remainingValue"`   // Value at chain end
	Hops            []PeelHop  `json:"hops"`
	TerminalAddress string     `json:"terminalAddress"`  // Where the chain ended
	TerminalReason  string     `json:"terminalReason"`   // Why the chain stopped
	IsComplete      bool       `json:"isComplete"`       // True if we reached the end
	PeelAddresses   []string   `json:"peelAddresses"`    // All peel-off addresses
	Confidence      float64    `json:"confidence"`       // Confidence in chain detection
}

// AnalyzePeelingChain reconstructs a peeling chain from transaction data.
// This method works on pre-fetched transaction data (no RPC calls needed).
// For full-node recursive tracing, use the Bitcoin RPC client directly.
//
// Parameters:
//   - startValue: initial output value to trace
//   - hopData: pre-fetched transaction data for each hop
//     Each hop has: txid, output values, output addresses
func AnalyzePeelingChain(startAddr string, hopData []PeelHopData) PeelingChainResult {
	result := PeelingChainResult{
		StartAddress: startAddr,
		Confidence:   1.0,
	}

	if len(hopData) == 0 {
		result.TerminalReason = "no_data"
		return result
	}

	result.StartTxID = hopData[0].TxID
	seenAddresses := make(map[string]bool)
	seenAddresses[startAddr] = true

	for i, hop := range hopData {
		if len(hop.OutputValues) < 1 {
			result.TerminalReason = "no_outputs"
			break
		}

		ph := PeelHop{
			HopIndex:   i,
			TxID:       hop.TxID,
			InputValue: hop.InputValue,
			FeesPaid:   hop.Fee,
			Timestamp:  hop.Timestamp,
		}

		// Identify peel vs. change output
		// Heuristic: change = largest output going to a new address
		changeIdx := -1
		var maxChangeValue int64

		for j, val := range hop.OutputValues {
			addr := ""
			if j < len(hop.OutputAddresses) {
				addr = hop.OutputAddresses[j]
			}

			if val > maxChangeValue && !seenAddresses[addr] {
				maxChangeValue = val
				changeIdx = j
			}
		}

		if changeIdx == -1 {
			result.TerminalReason = "no_change_detected"
			break
		}

		ph.ChangeValue = hop.OutputValues[changeIdx]
		if changeIdx < len(hop.OutputAddresses) {
			ph.ChangeAddress = hop.OutputAddresses[changeIdx]
		}

		// Sum all non-change outputs as "peeled"
		for j, val := range hop.OutputValues {
			if j != changeIdx {
				ph.PeelValue += val
				if j < len(hop.OutputAddresses) {
					ph.PeelAddress = hop.OutputAddresses[j] // Last peel addr
					result.PeelAddresses = append(result.PeelAddresses, hop.OutputAddresses[j])
				}
			}
		}

		if ph.InputValue > 0 {
			ph.PeelRatio = float64(ph.PeelValue) / float64(ph.InputValue)
		}

		result.Hops = append(result.Hops, ph)
		result.TotalPeeled += ph.PeelValue
		result.TotalFees += ph.FeesPaid

		if ph.ChangeAddress != "" {
			seenAddresses[ph.ChangeAddress] = true
		}

		// Decay confidence at each hop
		result.Confidence *= 0.95

		// Stop if change is too small to continue
		if ph.ChangeValue < 10000 { // < 10k sats
			result.TerminalReason = "change_exhausted"
			break
		}

		// Stop if peel ratio is unusual (>50% = probably not a peel)
		if ph.PeelRatio > 0.5 {
			result.TerminalReason = "peel_ratio_too_high"
			result.Confidence *= 0.7
			break
		}
	}

	result.TotalHops = len(result.Hops)
	if result.TotalHops > 0 {
		lastHop := result.Hops[result.TotalHops-1]
		result.RemainingValue = lastHop.ChangeValue
		result.TerminalAddress = lastHop.ChangeAddress
	}

	if result.TerminalReason == "" {
		result.TerminalReason = "max_hops_reached"
	}

	result.IsComplete = result.TerminalReason == "change_exhausted"

	return result
}

// PeelHopData is pre-fetched transaction data for one hop
type PeelHopData struct {
	TxID            string
	InputValue      int64
	OutputValues    []int64
	OutputAddresses []string
	Fee             int64
	Timestamp       time.Time
}

// IsPeelingPattern checks if a transaction matches the peeling chain pattern:
//   - Exactly 1 input (or inputs from same cluster)
//   - Exactly 2 outputs
//   - One output significantly larger than the other
//   - The large output is the "change" continuing the chain
func IsPeelingPattern(inputValue int64, outputs []int64) (isPeel bool, peelIdx int, changeIdx int) {
	if len(outputs) != 2 {
		return false, -1, -1
	}

	// The larger output is change, smaller is peel
	if outputs[0] > outputs[1] {
		changeIdx = 0
		peelIdx = 1
	} else {
		changeIdx = 1
		peelIdx = 0
	}

	// Peel should be <45% of input (reject close-to-equal splits)
	if inputValue > 0 && float64(outputs[peelIdx])/float64(inputValue) >= 0.45 {
		return false, -1, -1
	}

	// Change should be >50% of input (dominant output)
	if inputValue > 0 && float64(outputs[changeIdx])/float64(inputValue) < 0.50 {
		return false, -1, -1
	}

	return true, peelIdx, changeIdx
}

// ═══════════════════════════════════════════════════════════════════════
// T8: Time-Zone Profiling
// ═══════════════════════════════════════════════════════════════════════

// TimezoneProfile infers an entity's timezone from transaction broadcast hours
type TimezoneProfile struct {
	Address         string    `json:"address"`
	TxCount         int       `json:"txCount"`
	HourHistogram   [24]int   `json:"hourHistogram"`   // UTC hours 0-23
	QuietWindowStart int      `json:"quietWindowStart"` // Hour when activity drops (UTC)
	QuietWindowEnd  int       `json:"quietWindowEnd"`   // Hour when activity resumes (UTC)
	QuietWindowLen  int       `json:"quietWindowLen"`   // Hours of quiet window
	EstimatedOffset int       `json:"estimatedOffset"`  // Estimated UTC offset (-12 to +14)
	EstimatedTZ     string    `json:"estimatedTZ"`      // e.g., "UTC+8", "UTC-5"
	Confidence      float64   `json:"confidence"`       // [0, 1]
	PeakHour        int       `json:"peakHour"`         // Most active hour (UTC)
}

// ProfileTimezone analyzes transaction timestamps to infer the entity's timezone.
// The key insight: humans sleep ~6-8 hours. The "quiet window" in the tx histogram
// corresponds to nighttime → the center of the quiet window = ~3AM local time.
func ProfileTimezone(txTimestamps []time.Time) TimezoneProfile {
	profile := TimezoneProfile{
		TxCount: len(txTimestamps),
	}

	if len(txTimestamps) < 10 {
		// Need at least 10 transactions for reliable profiling
		return profile
	}

	// Build hour histogram (UTC)
	for _, ts := range txTimestamps {
		hour := ts.UTC().Hour()
		profile.HourHistogram[hour]++
	}

	// Find peak hour
	maxCount := 0
	for h, count := range profile.HourHistogram {
		if count > maxCount {
			maxCount = count
			profile.PeakHour = h
		}
	}

	// Find the longest quiet window (consecutive hours with minimal activity)
	// Threshold: hour has ≤5% of total transactions
	threshold := float64(len(txTimestamps)) * 0.05
	if threshold < 1 {
		threshold = 1
	}

	bestStart, bestLen := findQuietWindow(profile.HourHistogram[:], int(threshold))
	profile.QuietWindowStart = bestStart
	profile.QuietWindowLen = bestLen
	profile.QuietWindowEnd = (bestStart + bestLen) % 24

	// Estimate timezone: center of quiet window ≈ 3AM local time
	if bestLen >= 4 {
		quietCenter := (bestStart + bestLen/2) % 24

		// If quiet center is at UTC hour X, and we assume it's 3AM local,
		// then local_time = UTC + offset → 3 = X + offset → offset = 3 - X
		offset := 3 - quietCenter
		if offset < -12 {
			offset += 24
		}
		if offset > 14 {
			offset -= 24
		}

		profile.EstimatedOffset = offset
		if offset >= 0 {
			profile.EstimatedTZ = fmt.Sprintf("UTC+%d", offset)
		} else {
			profile.EstimatedTZ = fmt.Sprintf("UTC%d", offset)
		}

		// Confidence based on quiet window clarity
		switch {
		case bestLen >= 8:
			profile.Confidence = 0.90			
		case bestLen >= 6:
			profile.Confidence = 0.80
		case bestLen >= 4:
			profile.Confidence = 0.60
		default:
			profile.Confidence = 0.30
		}
	}

	return profile
}

// findQuietWindow finds the longest consecutive quiet period in the histogram.
// Uses circular wraparound (23→0) since hours are circular.
func findQuietWindow(histogram []int, threshold int) (startHour int, length int) {
	bestStart := 0
	bestLen := 0

	// Check all 24 possible starting positions
	for start := 0; start < 24; start++ {
		currentLen := 0
		for i := 0; i < 24; i++ {
			hour := (start + i) % 24
			if histogram[hour] <= threshold {
				currentLen++
			} else {
				break
			}
		}

		if currentLen > bestLen {
			bestLen = currentLen
			bestStart = start
		}
	}

	return bestStart, bestLen
}

// ═══════════════════════════════════════════════════════════════════════
// T9: RBF Fee Bump Forensics
// ═══════════════════════════════════════════════════════════════════════

// RBFEvent records a Replace-By-Fee event for forensic analysis
type RBFEvent struct {
	OriginalTxID    string    `json:"originalTxid"`
	ReplacementTxID string    `json:"replacementTxid"`
	OriginalFee     int64     `json:"originalFee"`     // sats
	ReplacementFee  int64     `json:"replacementFee"`  // sats
	FeeDelta        int64     `json:"feeDelta"`        // replacement - original
	FeeMultiplier   float64   `json:"feeMultiplier"`   // replacement / original
	TimeDelta       int64     `json:"timeDelta"`       // seconds between original and replacement
	UrgencyScore    float64   `json:"urgencyScore"`    // [0, 1] — higher = more urgent
	RecipientChanged bool    `json:"recipientChanged"` // Did the recipient address change? (double-spend!)
	OutputsChanged  bool     `json:"outputsChanged"`   // Any output values changed?
	IsDoubleSpend   bool     `json:"isDoubleSpend"`    // Recipient changed = likely double-spend
	WalletEvidence  string   `json:"walletEvidence"`   // Fee strategy reveals wallet software
	DetectedAt      time.Time `json:"detectedAt"`
}

// AnalyzeRBFEvent compares an original and replacement transaction
// to extract forensic intelligence.
func AnalyzeRBFEvent(original, replacement RBFTxData) RBFEvent {
	event := RBFEvent{
		OriginalTxID:    original.TxID,
		ReplacementTxID: replacement.TxID,
		OriginalFee:     original.Fee,
		ReplacementFee:  replacement.Fee,
		FeeDelta:        replacement.Fee - original.Fee,
		TimeDelta:       replacement.Timestamp - original.Timestamp,
		DetectedAt:      time.Now(),
	}

	if original.Fee > 0 {
		event.FeeMultiplier = float64(replacement.Fee) / float64(original.Fee)
	}

	// Urgency scoring: how quickly and aggressively did they bump?
	urgency := 0.0

	// Time factor: faster bump = more urgent
	if event.TimeDelta < 60 { // < 1 minute
		urgency += 0.40
	} else if event.TimeDelta < 300 { // < 5 minutes
		urgency += 0.25
	} else if event.TimeDelta < 3600 { // < 1 hour
		urgency += 0.10
	}

	// Fee multiplier factor: higher bump = more desperate
	if event.FeeMultiplier > 5.0 {
		urgency += 0.40
	} else if event.FeeMultiplier > 2.0 {
		urgency += 0.25
	} else if event.FeeMultiplier > 1.5 {
		urgency += 0.15
	}

	event.UrgencyScore = math.Min(urgency, 1.0)

	// Check if recipient changed (double-spend detection)
	// Build output sets
	origOutputs := make(map[string]int64)
	for _, out := range original.Outputs {
		origOutputs[out.Address] = out.Value
	}

	for _, out := range replacement.Outputs {
		if origVal, exists := origOutputs[out.Address]; exists {
			if origVal != out.Value {
				event.OutputsChanged = true
			}
		} else {
			event.RecipientChanged = true
		}
	}

	event.IsDoubleSpend = event.RecipientChanged

	// Fee strategy analysis reveals wallet software
	switch {
	case event.FeeMultiplier >= 1.9 && event.FeeMultiplier <= 2.1:
		event.WalletEvidence = "2x_multiplier_bitcoin_core_default"
	case event.FeeDelta == 1 || event.FeeDelta == 2:
		event.WalletEvidence = "minimal_bump_electrum_style"
	case event.FeeMultiplier > 5:
		event.WalletEvidence = "aggressive_bump_manual_or_panic"
	}

	return event
}

// RBFTxData holds the data needed for RBF analysis
type RBFTxData struct {
	TxID      string
	Fee       int64
	Timestamp int64 // Unix seconds
	Outputs   []RBFOutput
}

// RBFOutput is a simplified output for RBF comparison
type RBFOutput struct {
	Address string
	Value   int64
}

// RBFMonitor tracks RBF events across the mempool
type RBFMonitor struct {
	mu     sync.RWMutex
	events []RBFEvent
}

var (
	globalRBFMonitor *RBFMonitor
	rbfMonitorOnce   sync.Once
)

// GetGlobalRBFMonitor returns the singleton RBF monitor
func GetGlobalRBFMonitor() *RBFMonitor {
	rbfMonitorOnce.Do(func() {
		globalRBFMonitor = &RBFMonitor{}
	})
	return globalRBFMonitor
}

// Record stores an RBF event
func (rm *RBFMonitor) Record(event RBFEvent) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.events = append(rm.events, event)
}

// GetDoubleSpends returns all detected double-spend attempts
func (rm *RBFMonitor) GetDoubleSpends() []RBFEvent {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var ds []RBFEvent
	for _, e := range rm.events {
		if e.IsDoubleSpend {
			ds = append(ds, e)
		}
	}
	return ds
}

// GetHighUrgency returns events with urgency score above threshold
func (rm *RBFMonitor) GetHighUrgency(threshold float64) []RBFEvent {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var urgent []RBFEvent
	for _, e := range rm.events {
		if e.UrgencyScore >= threshold {
			urgent = append(urgent, e)
		}
	}
	return urgent
}

// ═══════════════════════════════════════════════════════════════════════
// Address Type Migration Tracking (Bonus: T19)
// ═══════════════════════════════════════════════════════════════════════

// AddressTypeMigration tracks when an entity migrates address types
type AddressTypeMigration struct {
	ClusterRoot     string            `json:"clusterRoot"`
	TypeDistribution map[string]int   `json:"typeDistribution"` // "p2pkh" → count
	DominantType    string            `json:"dominantType"`
	MigrationEvents []MigrationEvent  `json:"migrationEvents,omitempty"`
	HasMigrated     bool              `json:"hasMigrated"`
}

// MigrationEvent records a single address type change
type MigrationEvent struct {
	FromType   string    `json:"fromType"`
	ToType     string    `json:"toType"`
	DetectedAt time.Time `json:"detectedAt"`
}

// ClassifyAddressType returns the type of a Bitcoin address based on prefix
func ClassifyAddressType(address string) string {
	if len(address) == 0 {
		return "unknown"
	}

	switch {
	case address[0] == '1':
		return "p2pkh"
	case address[0] == '3':
		return "p2sh"
	case len(address) >= 4 && address[:4] == "bc1q" && len(address) == 42:
		return "p2wpkh" // Native SegWit v0
	case len(address) >= 4 && address[:4] == "bc1q" && len(address) == 62:
		return "p2wsh" // Native SegWit v0 (script)
	case len(address) >= 4 && address[:4] == "bc1p":
		return "p2tr" // Taproot
	default:
		return "unknown"
	}
}

// AnalyzeAddressMigration checks if an entity's address type usage has changed
func AnalyzeAddressMigration(addresses []string) AddressTypeMigration {
	result := AddressTypeMigration{
		TypeDistribution: make(map[string]int),
	}

	for _, addr := range addresses {
		addrType := ClassifyAddressType(addr)
		result.TypeDistribution[addrType]++
	}

	// Find dominant type
	maxCount := 0
	for t, count := range result.TypeDistribution {
		if count > maxCount {
			maxCount = count
			result.DominantType = t
		}
	}

	// If multiple types exist, migration happened
	typeCount := 0
	for _, count := range result.TypeDistribution {
		if count > 0 {
			typeCount++
		}
	}

	result.HasMigrated = typeCount > 1

	return result
}

// SortTimestamps sorts timestamps chronologically
func SortTimestamps(timestamps []time.Time) {
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i].Before(timestamps[j])
	})
}
