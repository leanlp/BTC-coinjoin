package heuristics

import (
	"sync"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Full-Chain UTXO Graph Traversal
// ═══════════════════════════════════════════════════════════════════════
//
// Two key capabilities:
//   1. Backtracking: Given a target tx, follow inputs backward to source
//   2. Forward Flow: Given a source tx, follow outputs forward to destinations
//
// Uses callback functions (TxLookupFunc/SpendingLookupFunc) to decouple
// from Bitcoin Core RPC — can use any data source.

// UTXORef is a reference to a specific unspent output
type UTXORef struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

// TraversalNode represents a node in the BFS traversal graph
type TraversalNode struct {
	TxID       string  `json:"txid"`
	Depth      int     `json:"depth"`
	Value      int64   `json:"value"`
	Address    string  `json:"address"`
	IsCoinbase bool    `json:"isCoinbase,omitempty"`
	IsCoinJoin bool    `json:"isCoinJoin,omitempty"`
	TaintScore float64 `json:"taintScore"`
}

// TraversalEdge represents a fund movement between traversal nodes
type TraversalEdge struct {
	FromTxID string  `json:"fromTxid"`
	ToTxID   string  `json:"toTxid"`
	Value    int64   `json:"value"`
	Ratio    float64 `json:"ratio"`
}

// TraversalGraph is the complete BFS traversal result
type TraversalGraph struct {
	Nodes     []TraversalNode `json:"nodes"`
	Edges     []TraversalEdge `json:"edges"`
	MaxDepth  int             `json:"maxDepth"`
	TotalFlow int64           `json:"totalFlow"`
	Direction string          `json:"direction"`
}

// TxLookupFunc retrieves a transaction by its txid.
type TxLookupFunc func(txid string) (*models.Transaction, error)

// SpendingLookupFunc finds the transaction that spends a given output.
type SpendingLookupFunc func(txid string, vout uint32) (*models.Transaction, error)

// BacktrackConfig controls backtracking behavior
type BacktrackConfig struct {
	MaxDepth    int
	MaxNodes    int
	MinValue    int64
	TaintDecay  float64
	StopAtMixer bool
}

// DefaultBacktrackConfig returns sane defaults
func DefaultBacktrackConfig() BacktrackConfig {
	return BacktrackConfig{MaxDepth: 10, MaxNodes: 1000, MinValue: 546, TaintDecay: 0.9, StopAtMixer: true}
}

// BacktrackUTXO traces fund origins by following inputs backward
func BacktrackUTXO(startTxID string, lookupTx TxLookupFunc, config BacktrackConfig) (*TraversalGraph, error) {
	graph := &TraversalGraph{Direction: "backward", MaxDepth: config.MaxDepth}
	visited := make(map[string]bool)

	type item struct {
		txid  string
		depth int
		taint float64
	}
	queue := []item{{startTxID, 0, 1.0}}

	for len(queue) > 0 && len(graph.Nodes) < config.MaxNodes {
		curr := queue[0]
		queue = queue[1:]
		if visited[curr.txid] || curr.depth > config.MaxDepth {
			continue
		}
		visited[curr.txid] = true

		tx, err := lookupTx(curr.txid)
		if err != nil || tx == nil {
			continue
		}

		isCoinbase := len(tx.Inputs) == 1 && tx.Inputs[0].Txid == ""
		isCj := isCoinJoinLike(*tx)

		node := TraversalNode{
			TxID: tx.Txid, Depth: curr.depth,
			IsCoinbase: isCoinbase, IsCoinJoin: isCj, TaintScore: curr.taint,
		}
		for _, out := range tx.Outputs {
			node.Value += out.Value
		}
		if len(tx.Outputs) > 0 {
			node.Address = tx.Outputs[0].Address
		}
		graph.Nodes = append(graph.Nodes, node)

		if isCoinbase || (config.StopAtMixer && isCj) {
			continue
		}

		for _, in := range tx.Inputs {
			if in.Txid == "" || in.Value < config.MinValue {
				continue
			}
			proportion := 1.0
			if node.Value > 0 {
				proportion = float64(in.Value) / float64(node.Value)
			}
			graph.Edges = append(graph.Edges, TraversalEdge{
				FromTxID: in.Txid, ToTxID: tx.Txid, Value: in.Value, Ratio: proportion,
			})
			queue = append(queue, item{in.Txid, curr.depth + 1, curr.taint * config.TaintDecay * proportion})
		}
	}

	for _, e := range graph.Edges {
		graph.TotalFlow += e.Value
	}
	return graph, nil
}

// ForwardFlowConfig controls forward tracing
type ForwardFlowConfig struct {
	MaxDepth int
	MaxNodes int
	MinValue int64
	TaintDecay float64
}

// DefaultForwardFlowConfig returns sane defaults
func DefaultForwardFlowConfig() ForwardFlowConfig {
	return ForwardFlowConfig{MaxDepth: 10, MaxNodes: 1000, MinValue: 546, TaintDecay: 0.9}
}

// ForwardFlowTrace follows funds forward from source to destinations
func ForwardFlowTrace(startTxID string, lookupSpending SpendingLookupFunc, lookupTx TxLookupFunc, config ForwardFlowConfig) (*TraversalGraph, error) {
	graph := &TraversalGraph{Direction: "forward", MaxDepth: config.MaxDepth}
	visited := make(map[string]bool)

	startTx, err := lookupTx(startTxID)
	if err != nil || startTx == nil {
		return graph, err
	}

	type item struct {
		txid  string
		vout  uint32
		depth int
		taint float64
		value int64
	}

	var queue []item
	for i, out := range startTx.Outputs {
		queue = append(queue, item{startTxID, uint32(i), 0, 1.0, out.Value})
	}

	graph.Nodes = append(graph.Nodes, TraversalNode{
		TxID: startTxID, Depth: 0, Value: totalOutputValue(startTx.Outputs),
	})

	for len(queue) > 0 && len(graph.Nodes) < config.MaxNodes {
		curr := queue[0]
		queue = queue[1:]
		if curr.depth >= config.MaxDepth || curr.value < config.MinValue {
			continue
		}

		spendingTx, err := lookupSpending(curr.txid, curr.vout)
		if err != nil || spendingTx == nil {
			continue
		}
		if visited[spendingTx.Txid] {
			continue
		}
		visited[spendingTx.Txid] = true

		outVal := totalOutputValue(spendingTx.Outputs)
		node := TraversalNode{
			TxID: spendingTx.Txid, Depth: curr.depth + 1,
			Value: outVal, IsCoinJoin: isCoinJoinLike(*spendingTx),
			TaintScore: curr.taint * config.TaintDecay,
		}
		if len(spendingTx.Outputs) > 0 {
			node.Address = spendingTx.Outputs[0].Address
		}
		graph.Nodes = append(graph.Nodes, node)
		graph.Edges = append(graph.Edges, TraversalEdge{
			FromTxID: curr.txid, ToTxID: spendingTx.Txid, Value: curr.value,
		})

		for i, out := range spendingTx.Outputs {
			queue = append(queue, item{
				spendingTx.Txid, uint32(i), curr.depth + 1,
				curr.taint * config.TaintDecay, out.Value,
			})
		}
	}

	for _, e := range graph.Edges {
		graph.TotalFlow += e.Value
	}
	return graph, nil
}

// UTXOIndex provides in-memory tx lookup for graph traversal
type UTXOIndex struct {
	mu    sync.RWMutex
	txs   map[string]*models.Transaction
	spent map[string]*models.Transaction
}

func NewUTXOIndex() *UTXOIndex {
	return &UTXOIndex{txs: make(map[string]*models.Transaction), spent: make(map[string]*models.Transaction)}
}

func (idx *UTXOIndex) IndexTransaction(tx models.Transaction) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	txCopy := tx
	idx.txs[tx.Txid] = &txCopy
	for _, in := range tx.Inputs {
		if in.Txid != "" {
			key := in.Txid + ":" + utxoKey(in.Vout)
			idx.spent[key] = &txCopy
		}
	}
}

func (idx *UTXOIndex) LookupTx(txid string) (*models.Transaction, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.txs[txid], nil
}

func (idx *UTXOIndex) LookupSpending(txid string, vout uint32) (*models.Transaction, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.spent[txid+":"+utxoKey(vout)], nil
}

func utxoKey(vout uint32) string { return string(rune('0' + vout)) }

// isCoinJoinLike does a quick structural check for CoinJoin-like transactions
func isCoinJoinLike(tx models.Transaction) bool {
	if len(tx.Inputs) < 2 || len(tx.Outputs) < 2 {
		return false
	}
	valueCounts := make(map[int64]int)
	for _, out := range tx.Outputs {
		valueCounts[out.Value]++
	}
	for _, count := range valueCounts {
		if count >= 3 {
			return true
		}
	}
	return false
}

func totalOutputValue(outputs []models.TxOut) int64 {
	total := int64(0)
	for _, out := range outputs {
		total += out.Value
	}
	return total
}

