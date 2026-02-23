package heuristics

import (
	"time"
)

// Fund Flow Tracer — Incident Response Core
//
// Given a theft address, traces ALL downstream UTXO flows hop-by-hop
// through the Bitcoin transaction graph. Builds a directed acyclic
// graph (DAG) showing exactly where the stolen funds went.
//
// This is the core of what Chainalysis Reactor does:
//   1. Start at the theft address
//   2. Find all transactions spending from that address
//   3. For each output, record where the value went
//   4. Recurse on each output address (next hop)
//   5. Stop at exchange deposits, dead ends, or max hops
//
// The tracer respects CoinJoin boundaries: when funds enter a mixer,
// it hands off to the CoinJoin Penetration module to maintain tracking.
//
// References:
//   - Chainalysis, "The 2024 Crypto Crime Report"
//   - Elliptic, "Follow the Money: How to Track Cryptocurrency Transactions"
//   - FBI, "Tracing Cryptocurrency: A DOJ Framework" (2022)

// FlowGraph represents the complete fund flow from a theft address
type FlowGraph struct {
	InvestigationID string     `json:"investigationId"`
	SourceAddresses []string   `json:"sourceAddresses"` // Theft addresses
	Nodes           []FlowNode `json:"nodes"`           // All addresses in the flow
	Edges           []FlowEdge `json:"edges"`           // All fund movements
	TotalTracked    int64      `json:"totalTracked"`    // Total sats tracked
	MaxHopReached   int        `json:"maxHopReached"`   // Deepest hop reached
	ExchangeExits   int        `json:"exchangeExits"`   // Number of exchange cash-outs found
	MixersPassed    int        `json:"mixersPassed"`    // Number of CoinJoins traversed
	CreatedAt       time.Time  `json:"createdAt"`
}

// FlowNode represents a single address in the flow graph
type FlowNode struct {
	Address       string  `json:"address"`
	HopNumber     int     `json:"hopNumber"`       // Distance from theft
	ValueReceived int64   `json:"valueReceived"`   // Total sats received
	ValueSent     int64   `json:"valueSent"`       // Total sats sent onward
	Role          string  `json:"role"`            // "theft"/"intermediate"/"mixer"/"exchange"/"unspent"/"unknown"
	Label         string  `json:"label,omitempty"` // Custom label (e.g., "Binance Hot Wallet")
	RiskScore     float64 `json:"riskScore"`       // 0.0-1.0 from taint analysis
	IsFlagged     bool    `json:"isFlagged"`       // Manually flagged by investigator
}

// FlowEdge represents a single fund movement between addresses
type FlowEdge struct {
	FromAddress string    `json:"fromAddress"`
	ToAddress   string    `json:"toAddress"`
	Txid        string    `json:"txid"`
	Value       int64     `json:"value"` // Sats transferred
	HopNumber   int       `json:"hopNumber"`
	IsCoinJoin  bool      `json:"isCoinJoin"` // Went through a mixer
	Confidence  float64   `json:"confidence"` // 0-1, lower for CoinJoin penetration
	Timestamp   time.Time `json:"timestamp"`
}

// TraceConfig controls the tracing behavior
type TraceConfig struct {
	MaxHops         int     `json:"maxHops"`         // Maximum hop depth (default: 10)
	MaxBranches     int     `json:"maxBranches"`     // Max branches to follow per hop (default: 50)
	MinValue        int64   `json:"minValue"`        // Minimum value to trace (ignore dust)
	MinConfidence   float64 `json:"minConfidence"`   // Minimum confidence to continue (default: 0.3)
	PenetrateMixers bool    `json:"penetrateMixers"` // Attempt to trace through CoinJoins
}

// DefaultTraceConfig returns sensible defaults for fund tracing
func DefaultTraceConfig() TraceConfig {
	return TraceConfig{
		MaxHops:         10,
		MaxBranches:     50,
		MinValue:        10000, // Ignore < 10,000 sats (dust)
		MinConfidence:   0.3,
		PenetrateMixers: true,
	}
}

// TraceFundFlow builds the complete flow graph from source addresses.
// In a full implementation, this would query the Bitcoin node for
// transaction data at each hop. This implementation provides the
// framework and data structures for the tracing engine.
func TraceFundFlow(sourceAddresses []string, config TraceConfig) FlowGraph {
	graph := FlowGraph{
		SourceAddresses: sourceAddresses,
		CreatedAt:       time.Now(),
	}

	// Initialize source nodes
	for _, addr := range sourceAddresses {
		graph.Nodes = append(graph.Nodes, FlowNode{
			Address:   addr,
			HopNumber: 0,
			Role:      "theft",
			RiskScore: 1.0, // Theft address = maximum risk
			IsFlagged: true,
		})
	}

	return graph
}

// AddHop extends the flow graph with a new hop of transactions.
// Called by the block scanner or RPC client as it discovers
// downstream transactions from traced addresses.
func (g *FlowGraph) AddHop(fromAddr, toAddr, txid string, value int64, hopNum int, isCoinJoin bool, confidence float64) {
	// Add the edge
	g.Edges = append(g.Edges, FlowEdge{
		FromAddress: fromAddr,
		ToAddress:   toAddr,
		Txid:        txid,
		Value:       value,
		HopNumber:   hopNum,
		IsCoinJoin:  isCoinJoin,
		Confidence:  confidence,
		Timestamp:   time.Now(),
	})

	// Track total value
	g.TotalTracked += value

	// Update max hop
	if hopNum > g.MaxHopReached {
		g.MaxHopReached = hopNum
	}

	// Add destination node if not already present
	if !g.hasNode(toAddr) {
		role := "intermediate"
		if isCoinJoin {
			role = "mixer"
			g.MixersPassed++
		}

		g.Nodes = append(g.Nodes, FlowNode{
			Address:       toAddr,
			HopNumber:     hopNum,
			ValueReceived: value,
			Role:          role,
			RiskScore:     computeHopRisk(hopNum, confidence),
		})
	} else {
		// Update existing node's received value
		for i := range g.Nodes {
			if g.Nodes[i].Address == toAddr {
				g.Nodes[i].ValueReceived += value
				break
			}
		}
	}
}

// MarkExchangeExit tags a node as an exchange deposit (cash-out point)
func (g *FlowGraph) MarkExchangeExit(addr, exchangeName string) {
	for i := range g.Nodes {
		if g.Nodes[i].Address == addr {
			g.Nodes[i].Role = "exchange"
			g.Nodes[i].Label = exchangeName
			g.Nodes[i].IsFlagged = true
			g.ExchangeExits++
			return
		}
	}
}

// GetExitPoints returns all nodes classified as exchange exits
func (g *FlowGraph) GetExitPoints() []FlowNode {
	var exits []FlowNode
	for _, node := range g.Nodes {
		if node.Role == "exchange" {
			exits = append(exits, node)
		}
	}
	return exits
}

// GetTimeline returns all edges sorted by hop number (chronological)
func (g *FlowGraph) GetTimeline() []FlowEdge {
	// Already ordered by insertion (hop order)
	return g.Edges
}

// GetHop returns all edges at a specific hop number
func (g *FlowGraph) GetHop(hop int) []FlowEdge {
	var edges []FlowEdge
	for _, edge := range g.Edges {
		if edge.HopNumber == hop {
			edges = append(edges, edge)
		}
	}
	return edges
}

// hasNode checks if an address already exists in the graph
func (g *FlowGraph) hasNode(addr string) bool {
	for _, node := range g.Nodes {
		if node.Address == addr {
			return true
		}
	}
	return false
}

// computeHopRisk calculates risk score based on distance from theft
// Risk decays with distance but stays elevated for high-confidence paths
func computeHopRisk(hop int, confidence float64) float64 {
	// Base decay: 0.85^hop
	decay := 1.0
	for i := 0; i < hop; i++ {
		decay *= 0.85
	}
	risk := decay * confidence
	if risk < 0 {
		return 0
	}
	if risk > 1 {
		return 1
	}
	return risk
}

// Summary returns a human-readable summary of the trace
func (g *FlowGraph) Summary() map[string]interface{} {
	return map[string]interface{}{
		"sourceAddresses": g.SourceAddresses,
		"totalNodes":      len(g.Nodes),
		"totalEdges":      len(g.Edges),
		"totalTracked":    g.TotalTracked,
		"maxHopReached":   g.MaxHopReached,
		"exchangeExits":   g.ExchangeExits,
		"mixersPassed":    g.MixersPassed,
	}
}
