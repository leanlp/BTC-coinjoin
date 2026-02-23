package heuristics

import (
	"sync"
	"time"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Address Watchlist Engine — Real-Time Monitoring
//
// Concurrent-safe address monitoring for incident response. Every
// mempool transaction is checked against the watchlist. When a
// watched address appears as input or output, an alert fires.
//
// Performance: O(1) lookup using map-based set.
// Concurrency: sync.RWMutex allows concurrent reads during the
// hot path (checking transactions) while writes (adding/removing
// addresses) are serialized.
//
// Categories:
//   theft      — Stolen fund origin addresses
//   suspect    — Addresses under investigation
//   exchange   — Known exchange deposit/withdrawal addresses
//   sanctioned — OFAC/SDN listed addresses
//   service    — Known service addresses (mixing, gambling, etc)

// WatchedAddress holds metadata for a monitored address
type WatchedAddress struct {
	Address    string    `json:"address"`
	Category   string    `json:"category"` // theft/suspect/exchange/sanctioned/service
	Label      string    `json:"label"`    // Human-readable name
	CaseID     string    `json:"caseId"`   // Investigation case reference
	AddedAt    time.Time `json:"addedAt"`
	AlertLevel string    `json:"alertLevel"` // info/low/medium/high/critical
}

// WatchlistHit represents a match during transaction scanning
type WatchlistHit struct {
	Address    string `json:"address"`
	Category   string `json:"category"`
	Label      string `json:"label"`
	CaseID     string `json:"caseId"`
	Direction  string `json:"direction"` // "input" or "output"
	Value      int64  `json:"value"`     // Sats involved
	AlertLevel string `json:"alertLevel"`
}

// AddressWatchlist is a concurrent-safe address monitoring engine
type AddressWatchlist struct {
	mu        sync.RWMutex
	addresses map[string]WatchedAddress
}

// NewAddressWatchlist creates a new empty watchlist
func NewAddressWatchlist() *AddressWatchlist {
	return &AddressWatchlist{
		addresses: make(map[string]WatchedAddress),
	}
}

// Add registers an address for monitoring
func (w *AddressWatchlist) Add(addr, category, label, caseID, alertLevel string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.addresses[addr] = WatchedAddress{
		Address:    addr,
		Category:   category,
		Label:      label,
		CaseID:     caseID,
		AddedAt:    time.Now(),
		AlertLevel: alertLevel,
	}
}

// Remove stops monitoring an address
func (w *AddressWatchlist) Remove(addr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.addresses, addr)
}

// Contains checks if an address is watchlisted (O(1))
func (w *AddressWatchlist) Contains(addr string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, exists := w.addresses[addr]
	return exists
}

// Get returns the watchlist entry for an address
func (w *AddressWatchlist) Get(addr string) (WatchedAddress, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	entry, exists := w.addresses[addr]
	return entry, exists
}

// CheckTransaction scans a transaction for watchlisted addresses.
// Returns all hits (may be multiple if both inputs and outputs match).
func (w *AddressWatchlist) CheckTransaction(tx models.Transaction) []WatchlistHit {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var hits []WatchlistHit

	// Check all inputs
	for _, in := range tx.Inputs {
		if in.Address == "" {
			continue
		}
		if entry, exists := w.addresses[in.Address]; exists {
			hits = append(hits, WatchlistHit{
				Address:    in.Address,
				Category:   entry.Category,
				Label:      entry.Label,
				CaseID:     entry.CaseID,
				Direction:  "input",
				Value:      in.Value,
				AlertLevel: entry.AlertLevel,
			})
		}
	}

	// Check all outputs
	for _, out := range tx.Outputs {
		if out.Address == "" {
			continue
		}
		if entry, exists := w.addresses[out.Address]; exists {
			hits = append(hits, WatchlistHit{
				Address:    out.Address,
				Category:   entry.Category,
				Label:      entry.Label,
				CaseID:     entry.CaseID,
				Direction:  "output",
				Value:      out.Value,
				AlertLevel: entry.AlertLevel,
			})
		}
	}

	return hits
}

// LoadFromInvestigation populates the watchlist from an investigation's addresses
func (w *AddressWatchlist) LoadFromInvestigation(inv *Investigation) {
	// Add theft addresses
	for _, addr := range inv.TheftAddresses {
		w.Add(addr, "theft", "Theft: "+inv.Name, inv.ID, "critical")
	}

	// Add tagged addresses
	for _, tag := range inv.TaggedAddresses {
		alertLevel := "medium"
		if tag.Role == "exchange" {
			alertLevel = "high"
		} else if tag.Role == "suspect" {
			alertLevel = "high"
		}
		w.Add(tag.Address, tag.Role, tag.Label, inv.ID, alertLevel)
	}
}

// Size returns the number of watched addresses
func (w *AddressWatchlist) Size() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.addresses)
}

// ListAll returns all watched addresses
func (w *AddressWatchlist) ListAll() []WatchedAddress {
	w.mu.RLock()
	defer w.mu.RUnlock()

	list := make([]WatchedAddress, 0, len(w.addresses))
	for _, entry := range w.addresses {
		list = append(list, entry)
	}
	return list
}
