package heuristics

import (
	"log"
	"strings"
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
		addr = strings.TrimSpace(addr)
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
		addr := strings.TrimSpace(src.Address)
		if addr == "" {
			continue
		}
		src.Address = addr
		current, exists := globalTaintMap[src.Address]
		if !exists || src.TaintLevel > current {
			globalTaintMap[src.Address] = src.TaintLevel
			seeded++
		}
	}
	return seeded
}

// CheckInputsForTaint evaluates taint exposure across transaction inputs.
//
// Returns the weighted taint ratio (Σ input_value*taint / Σ input_value) and
// whether FlagHighRisk should be set.
//
// High-risk is triggered when:
//   - weighted exposure >= 0.25 (material taint share), OR
//   - any direct source taint >= 0.85 (near-certain sanctioned/theft source)
//
// Called by AnalyzeTx and risk scoring paths to integrate taint into the pipeline.
func CheckInputsForTaint(tx models.Transaction) (taintLevel float64, isHighRisk bool) {
	taintMu.RLock()
	defer taintMu.RUnlock()

	if globalTaintMap == nil || len(globalTaintMap) == 0 {
		return 0, false
	}

	var totalIn int64
	var weightedTaint float64
	maxTaint := 0.0

	for _, input := range tx.Inputs {
		addr := strings.TrimSpace(input.Address)
		if addr == "" {
			continue
		}
		if input.Value <= 0 {
			continue
		}

		totalIn += input.Value

		if taint, exists := globalTaintMap[addr]; exists {
			weightedTaint += taint * float64(input.Value)
			if taint > maxTaint {
				maxTaint = taint
			}
		}
	}

	totalOut := int64(0)
	for _, out := range tx.Outputs {
		if out.Value > 0 {
			totalOut += out.Value
		}
	}

	denom := totalIn
	if totalOut > denom {
		denom = totalOut
	}
	if denom <= 0 {
		return 0, false
	}

	exposure := weightedTaint / float64(denom)
	isHigh := exposure >= 0.25 || maxTaint >= 0.85

	return exposure, isHigh
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
