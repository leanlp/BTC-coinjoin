package heuristics

import (
	"log"
	"sync"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ──────────────────────────────────────────────────────────────────
// Global Taint Map Singleton
//
// Thread-safe taint state shared across the pipeline. Seeded from
// investigation theft addresses and external intelligence feeds.
// The poller and block scanner call CheckInputsForTaint() on every
// analyzed transaction to set FlagHighRisk when tainted funds move.
// ──────────────────────────────────────────────────────────────────

var (
	globalTaintMap TaintMap
	taintMu        sync.RWMutex
	taintInitOnce  sync.Once
)

// InitGlobalTaintMap initializes the singleton. Safe to call multiple times.
func InitGlobalTaintMap() {
	taintInitOnce.Do(func() {
		globalTaintMap = NewTaintMap()
		log.Println("[TaintSeed] Global taint map initialized")
	})
}

// SeedFromInvestigationAddresses loads theft addresses from active investigations
// into the global taint map with full taint (1.0). Called at startup and when
// new investigations are created.
func SeedFromInvestigationAddresses(addresses []string) int {
	taintMu.Lock()
	defer taintMu.Unlock()

	if globalTaintMap == nil {
		globalTaintMap = NewTaintMap()
	}

	seeded := 0
	for _, addr := range addresses {
		if addr == "" {
			continue
		}
		if _, exists := globalTaintMap[addr]; !exists {
			globalTaintMap[addr] = 1.0 // Full taint for known theft addresses
			seeded++
		}
	}

	if seeded > 0 {
		log.Printf("[TaintSeed] Seeded %d new addresses (total tracked: %d)", seeded, len(globalTaintMap))
	}
	return seeded
}

// SeedFromExternalIntel loads external intelligence (sanctions lists,
// known scam wallets, exchange hot wallets) with source-specific taint levels.
func SeedFromExternalIntel(sources []TaintSource) int {
	taintMu.Lock()
	defer taintMu.Unlock()

	if globalTaintMap == nil {
		globalTaintMap = NewTaintMap()
	}

	seeded := 0
	for _, src := range sources {
		current, exists := globalTaintMap[src.Address]
		if !exists || src.TaintLevel > current {
			globalTaintMap[src.Address] = src.TaintLevel
			seeded++
		}
	}
	return seeded
}

// CheckInputsForTaint checks if any transaction inputs come from tainted addresses.
// Returns the maximum taint level found and whether FlagHighRisk should be set.
//
// Called by AnalyzeTx (Step 28) to integrate taint into the pipeline.
func CheckInputsForTaint(tx models.Transaction) (taintLevel float64, isHighRisk bool) {
	taintMu.RLock()
	defer taintMu.RUnlock()

	if globalTaintMap == nil || len(globalTaintMap) == 0 {
		return 0, false
	}

	maxTaint := 0.0
	for _, input := range tx.Inputs {
		if input.Address == "" {
			continue
		}
		if taint, exists := globalTaintMap[input.Address]; exists && taint > maxTaint {
			maxTaint = taint
		}
	}

	// FlagHighRisk threshold: 25% taint exposure (matches FATF "high" category)
	return maxTaint, maxTaint >= 0.25
}

// GetGlobalTaintMapSize returns the current number of tracked tainted addresses
func GetGlobalTaintMapSize() int {
	taintMu.RLock()
	defer taintMu.RUnlock()
	if globalTaintMap == nil {
		return 0
	}
	return len(globalTaintMap)
}
