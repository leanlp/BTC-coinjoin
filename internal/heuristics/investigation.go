package heuristics

import (
	"sync"
	"time"
)

// Investigation Case Manager
//
// Manages incident response investigations. An investigator:
//   1. Creates a case with theft addresses
//   2. Runs a fund flow trace
//   3. Tags addresses (exchange, suspect, service)
//   4. Reviews timeline and exit points
//   5. Exports evidence for law enforcement
//
// This is analogous to Chainalysis Reactor cases or Elliptic
// Navigator investigations. Each case maintains a persistent
// flow graph that can be updated as new on-chain data appears.
//
// Investigation lifecycle:
//   active    → trace running, new data being added
//   paused    → temporarily halted
//   completed → all funds accounted for
//   archived  → closed and preserved for records

// Investigation represents a single incident response case
type Investigation struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Status          string          `json:"status"` // "active"/"paused"/"completed"/"archived"
	TheftAddresses  []string        `json:"theftAddresses"`
	TaggedAddresses []TaggedAddress `json:"taggedAddresses"`
	FlowGraph       *FlowGraph      `json:"flowGraph,omitempty"`
	TotalStolen     int64           `json:"totalStolen"`    // Total sats stolen
	TotalRecovered  int64           `json:"totalRecovered"` // Sats at identified exchange exits
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
	TraceConfig     TraceConfig     `json:"traceConfig"`
}

// TaggedAddress is an address with investigator-provided metadata
type TaggedAddress struct {
	Address   string    `json:"address"`
	Label     string    `json:"label"` // "Binance Hot Wallet", "Suspect Wallet", etc.
	Role      string    `json:"role"`  // "theft"/"suspect"/"exchange"/"service"/"unknown"
	Notes     string    `json:"notes,omitempty"`
	HopNumber int       `json:"hopNumber"`
	Value     int64     `json:"value"` // Sats tracked to this address
	TaggedAt  time.Time `json:"taggedAt"`
	TaggedBy  string    `json:"taggedBy,omitempty"` // Investigator name/ID
}

// TimelineEvent represents a chronological event in the investigation
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"eventType"` // "theft"/"transfer"/"mixer_entry"/"mixer_exit"/"exchange_deposit"/"tagged"
	Description string    `json:"description"`
	Txid        string    `json:"txid,omitempty"`
	FromAddress string    `json:"fromAddress,omitempty"`
	ToAddress   string    `json:"toAddress,omitempty"`
	Value       int64     `json:"value"`
	HopNumber   int       `json:"hopNumber"`
}

// InvestigationManager handles CRUD for investigations
type InvestigationManager struct {
	mu    sync.RWMutex
	cases map[string]*Investigation
}

// NewInvestigationManager creates a new case manager
func NewInvestigationManager() *InvestigationManager {
	return &InvestigationManager{
		cases: make(map[string]*Investigation),
	}
}

// CreateInvestigation starts a new incident response case
func (m *InvestigationManager) CreateInvestigation(id, name, description string, theftAddresses []string, totalStolen int64) *Investigation {
	now := time.Now()
	inv := &Investigation{
		ID:             id,
		Name:           name,
		Description:    description,
		Status:         "active",
		TheftAddresses: theftAddresses,
		TotalStolen:    totalStolen,
		CreatedAt:      now,
		UpdatedAt:      now,
		TraceConfig:    DefaultTraceConfig(),
	}

	m.mu.Lock()
	m.cases[id] = inv
	m.mu.Unlock()
	return inv
}

// GetInvestigation retrieves a case by ID
func (m *InvestigationManager) GetInvestigation(id string) *Investigation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cases[id]
}

// ListInvestigations returns all active cases
func (m *InvestigationManager) ListInvestigations() []*Investigation {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []*Investigation
	for _, inv := range m.cases {
		list = append(list, inv)
	}
	return list
}

// RunTrace executes the fund flow trace for a case
func (inv *Investigation) RunTrace() {
	inv.FlowGraph = &FlowGraph{}
	graph := TraceFundFlow(inv.TheftAddresses, inv.TraceConfig)
	inv.FlowGraph = &graph
	inv.UpdatedAt = time.Now()
}

// TagAddress adds a label and metadata to an address in the investigation
func (inv *Investigation) TagAddress(addr, label, role, notes, taggedBy string) {
	tag := TaggedAddress{
		Address:  addr,
		Label:    label,
		Role:     role,
		Notes:    notes,
		TaggedAt: time.Now(),
		TaggedBy: taggedBy,
	}

	// Find existing tag and update, or append new
	for i, existing := range inv.TaggedAddresses {
		if existing.Address == addr {
			inv.TaggedAddresses[i] = tag
			inv.UpdatedAt = time.Now()
			return
		}
	}

	inv.TaggedAddresses = append(inv.TaggedAddresses, tag)
	inv.UpdatedAt = time.Now()

	// Also update the flow graph node if it exists
	if inv.FlowGraph != nil {
		for i := range inv.FlowGraph.Nodes {
			if inv.FlowGraph.Nodes[i].Address == addr {
				inv.FlowGraph.Nodes[i].Label = label
				inv.FlowGraph.Nodes[i].Role = role
				inv.FlowGraph.Nodes[i].IsFlagged = true
				break
			}
		}
	}
}

// GetTimeline builds a chronological timeline of all events
func (inv *Investigation) GetTimeline() []TimelineEvent {
	var events []TimelineEvent

	// Add theft events
	for _, addr := range inv.TheftAddresses {
		events = append(events, TimelineEvent{
			Timestamp:   inv.CreatedAt,
			EventType:   "theft",
			Description: "Funds stolen from address",
			ToAddress:   addr,
			Value:       inv.TotalStolen,
			HopNumber:   0,
		})
	}

	// Add flow events from the graph
	if inv.FlowGraph != nil {
		for _, edge := range inv.FlowGraph.Edges {
			eventType := "transfer"
			desc := "Fund transfer"
			if edge.IsCoinJoin {
				eventType = "mixer_entry"
				desc = "Funds entered CoinJoin mixer"
			}

			events = append(events, TimelineEvent{
				Timestamp:   edge.Timestamp,
				EventType:   eventType,
				Description: desc,
				Txid:        edge.Txid,
				FromAddress: edge.FromAddress,
				ToAddress:   edge.ToAddress,
				Value:       edge.Value,
				HopNumber:   edge.HopNumber,
			})
		}

		// Add exchange exit events
		for _, node := range inv.FlowGraph.Nodes {
			if node.Role == "exchange" {
				events = append(events, TimelineEvent{
					EventType:   "exchange_deposit",
					Description: "Funds deposited to " + node.Label,
					ToAddress:   node.Address,
					Value:       node.ValueReceived,
					HopNumber:   node.HopNumber,
				})
			}
		}
	}

	// Add tagging events
	for _, tag := range inv.TaggedAddresses {
		events = append(events, TimelineEvent{
			Timestamp:   tag.TaggedAt,
			EventType:   "tagged",
			Description: "Address tagged as: " + tag.Label,
			ToAddress:   tag.Address,
			HopNumber:   tag.HopNumber,
		})
	}

	return events
}

// GetExchangeExits returns all identified exchange deposit points
func (inv *Investigation) GetExchangeExits() []FlowNode {
	if inv.FlowGraph == nil {
		return nil
	}
	return inv.FlowGraph.GetExitPoints()
}

// ComputeRecovery calculates total value at identified exchange exits
func (inv *Investigation) ComputeRecovery() int64 {
	exits := inv.GetExchangeExits()
	total := int64(0)
	for _, exit := range exits {
		total += exit.ValueReceived
	}
	inv.TotalRecovered = total
	return total
}

// SetStatus updates the investigation status
func (inv *Investigation) SetStatus(status string) {
	inv.Status = status
	inv.UpdatedAt = time.Now()
}
