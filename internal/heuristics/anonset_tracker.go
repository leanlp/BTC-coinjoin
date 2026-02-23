package heuristics

import (
	"math"
	"time"
)

// AnonSetWindow represents the time-evolving anonymity set for a specific output.
// Effective Time-Evolving Anonymity Set (A_E) tracked at
// T+1d, T+7d, T+30d, T+365d observation windows.
type AnonSetWindow struct {
	Txid         string `json:"txid"`
	OutputIndex  int    `json:"outputIndex"`
	AnonSetLocal int    `json:"anonsetLocal"`  // A_0: transaction-local pool size
	AnonSet1d    int    `json:"anonset1d"`     // A(T+1 day)
	AnonSet7d    int    `json:"anonset7d"`     // A(T+7 days)
	AnonSet30d   int    `json:"anonset30d"`    // A(T+30 days)
	AnonSet365d  int    `json:"anonset365d"`   // A(T+365 days)
	LastUpdated  time.Time `json:"lastUpdated"`
}

// ErosionEvent represents an on-chain event that reduces a participant's anonymity.
// Examples: recombination with exchange deposit, change consolidation, address reuse.
type ErosionEvent struct {
	Timestamp   time.Time
	EventType   ErosionType
	Severity    float64 // 0.0 (no impact) to 1.0 (fully deanonymized)
	Description string
}

// ErosionType classifies the type of privacy-reducing event
type ErosionType int

const (
	ErosionNone              ErosionType = 0
	ErosionExchangeDeposit   ErosionType = 1 // UTXO sent to known exchange
	ErosionChangeConsolidate ErosionType = 2 // Change output merged with other UTXOs
	ErosionAddressReuse      ErosionType = 3 // Address used multiple times
	ErosionTimingCorrelation ErosionType = 4 // Suspicious timing patterns
)

// ComputeWindowedAnonSet calculates the time-evolving anonymity set for a given output.
// It takes the initial local anonymity set and a list of erosion events observed
// over time, then computes the decayed AnonSet at each observation window.
//
// Mathematical model:
//   A_t(o) = f(A_0(o), {E(s)}_{t_0 < s <= t})
//
// The decay function models: each significant erosion event reduces the
// candidate pool by removing participants whose identities can be distinguished.
func ComputeWindowedAnonSet(localAnonSet int, mixTime time.Time, events []ErosionEvent) AnonSetWindow {
	now := time.Now()

	windows := []struct {
		duration time.Duration
		field    *int
	}{
		{24 * time.Hour, nil},
		{7 * 24 * time.Hour, nil},
		{30 * 24 * time.Hour, nil},
		{365 * 24 * time.Hour, nil},
	}

	result := AnonSetWindow{
		AnonSetLocal: localAnonSet,
		LastUpdated:  now,
	}

	windowPtrs := []*int{&result.AnonSet1d, &result.AnonSet7d, &result.AnonSet30d, &result.AnonSet365d}

	for i, w := range windows {
		windows[i].field = windowPtrs[i]
		_ = w // suppress unused
		cutoff := mixTime.Add(windows[i].duration)

		// Only compute if enough real time has elapsed
		if now.Before(cutoff) {
			*windowPtrs[i] = localAnonSet // Not enough time has passed for erosion
			continue
		}

		// Apply decay from erosion events within this window
		*windowPtrs[i] = applyErosionDecay(localAnonSet, mixTime, cutoff, events)
	}

	return result
}

// applyErosionDecay models the reduction of anonymity based on observed events.
// Each event with severity S reduces the effective AnonSet by a multiplicative factor.
//
// For N events with severities S_1..S_N within the window:
//   A_t = A_0 * product(1 - S_i) for all events in window
//
// This ensures: no event alone fully collapses privacy, but accumulated
// erosion compounds (matching the ESORICS 2025 finding of 10-50% decay).
func applyErosionDecay(anonSetLocal int, mixTime, windowEnd time.Time, events []ErosionEvent) int {
	survivalFactor := 1.0

	for _, evt := range events {
		// Only count events within the observation window
		if evt.Timestamp.After(mixTime) && evt.Timestamp.Before(windowEnd) {
			survivalFactor *= (1.0 - evt.Severity)
		}
	}

	// Clamp to minimum of 1 (there's always at least one candidate: the owner)
	decayed := int(math.Round(float64(anonSetLocal) * survivalFactor))
	if decayed < 1 {
		decayed = 1
	}

	return decayed
}
