package heuristics

import (
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Address Clustering Engine (Union-Find)
//
// The CORE of every chain analysis firm. Merges addresses into entity
// clusters using the Common-Input-Ownership Heuristic (CIOH):
//   "All inputs to a non-CoinJoin transaction belong to the same entity"
//
// Implementation: Weighted Union-Find with path compression.
//   - Find: O(α(n)) ≈ O(1) amortized (inverse Ackermann)
//   - Union: O(α(n)) ≈ O(1) amortized
//   - Space: O(n) where n = number of unique addresses
//
// Critical gating:
//   - NEVER merge across CoinJoin boundaries
//   - NEVER merge when PayJoin is suspected
//   - Discount change-based merges by confidence
//
// References:
//   - Meiklejohn et al., "A Fistful of Bitcoins" (IMC 2013) — defined CIOH
//   - Ron & Shamir, "Quantitative Analysis" (FC 2013 — first large-scale clustering
//   - Harrigan & Fretter, "Unreasonable Effectiveness of Address Clustering" (2016)

// ClusterEngine implements weighted Union-Find for address clustering
type ClusterEngine struct {
	parent map[string]string // parent[addr] = parent address
	rank   map[string]int    // rank for union by rank
	size   map[string]int    // cluster size at root
}

// NewClusterEngine creates a new clustering engine
func NewClusterEngine() *ClusterEngine {
	return &ClusterEngine{
		parent: make(map[string]string),
		rank:   make(map[string]int),
		size:   make(map[string]int),
	}
}

// Find returns the root representative of the cluster containing addr.
// Uses path compression for amortized O(1) performance.
func (ce *ClusterEngine) Find(addr string) string {
	if _, exists := ce.parent[addr]; !exists {
		ce.parent[addr] = addr
		ce.rank[addr] = 0
		ce.size[addr] = 1
	}

	// Path compression: make every node point directly to root
	if ce.parent[addr] != addr {
		ce.parent[addr] = ce.Find(ce.parent[addr])
	}
	return ce.parent[addr]
}

// Union merges the clusters containing addr1 and addr2.
// Uses union by rank to keep tree balanced.
// Returns true if a merge actually occurred (they were in different clusters).
func (ce *ClusterEngine) Union(addr1, addr2 string) bool {
	root1 := ce.Find(addr1)
	root2 := ce.Find(addr2)

	if root1 == root2 {
		return false // Already in the same cluster
	}

	// Union by rank: attach smaller tree under root of larger tree
	if ce.rank[root1] < ce.rank[root2] {
		ce.parent[root1] = root2
		ce.size[root2] += ce.size[root1]
	} else if ce.rank[root1] > ce.rank[root2] {
		ce.parent[root2] = root1
		ce.size[root1] += ce.size[root2]
	} else {
		ce.parent[root2] = root1
		ce.size[root1] += ce.size[root2]
		ce.rank[root1]++
	}

	return true
}

// MergeFromEdges processes evidence edges and merges addresses.
// Only CIOH and Change edges trigger merges. CoinJoin-gated edges
// and PayJoin suspects are explicitly excluded.
func (ce *ClusterEngine) MergeFromEdges(edges []models.EvidenceEdge) int {
	mergeCount := 0

	for _, edge := range edges {
		// Only merge on strong ownership signals
		switch edge.EdgeType {
		case EdgeTypeCIOH:
			// Standard CIOH: merge unconditionally
			if ce.Union(edge.SrcNodeID, edge.DstNodeID) {
				mergeCount++
			}

		case EdgeTypeChange:
			// Change detection: merge if LLR is sufficiently high
			if edge.LLRScore >= 1.5 {
				if ce.Union(edge.SrcNodeID, edge.DstNodeID) {
					mergeCount++
				}
			}

		case EdgeTypeCIOHInvalidated, EdgeTypeCoinjoinSuspected, EdgeTypePayJoinSuspect:
			// NEVER merge across these boundaries
			continue

		case EdgeTypePeelChain:
			// Peel chains: merge with high confidence
			if edge.LLRScore >= 2.0 {
				if ce.Union(edge.SrcNodeID, edge.DstNodeID) {
					mergeCount++
				}
			}

		default:
			// Other edge types: require very strong evidence
			if edge.LLRScore >= 3.0 {
				if ce.Union(edge.SrcNodeID, edge.DstNodeID) {
					mergeCount++
				}
			}
		}
	}

	return mergeCount
}

// MergeFromTransaction applies CIOH to a single transaction.
// All inputs of a non-CoinJoin transaction are merged.
func (ce *ClusterEngine) MergeFromTransaction(tx models.Transaction, isCoinJoin bool) int {
	if isCoinJoin || len(tx.Inputs) < 2 {
		return 0
	}

	mergeCount := 0
	firstAddr := tx.Inputs[0].Address

	for i := 1; i < len(tx.Inputs); i++ {
		if tx.Inputs[i].Address != "" && tx.Inputs[i].Address != firstAddr {
			if ce.Union(firstAddr, tx.Inputs[i].Address) {
				mergeCount++
			}
		}
	}

	return mergeCount
}

// GetCluster returns all addresses in the same cluster as addr
func (ce *ClusterEngine) GetCluster(addr string) []string {
	root := ce.Find(addr)
	var cluster []string

	for a := range ce.parent {
		if ce.Find(a) == root {
			cluster = append(cluster, a)
		}
	}
	return cluster
}

// GetClusterSize returns the number of addresses in the cluster
func (ce *ClusterEngine) GetClusterSize(addr string) int {
	root := ce.Find(addr)
	return ce.size[root]
}

// ClusterStats holds statistics about an address cluster
type ClusterStats struct {
	RootAddress  string `json:"rootAddress"`
	AddressCount int    `json:"addressCount"`
	TotalValue   int64  `json:"totalValue"` // Sum of all UTXO values
	TxCount      int    `json:"txCount"`    // Number of transactions
}

// GetStats returns statistics for the cluster containing addr
func (ce *ClusterEngine) GetStats(addr string) ClusterStats {
	cluster := ce.GetCluster(addr)
	return ClusterStats{
		RootAddress:  ce.Find(addr),
		AddressCount: len(cluster),
	}
}

// TotalClusters returns the number of distinct clusters
func (ce *ClusterEngine) TotalClusters() int {
	roots := make(map[string]bool)
	for addr := range ce.parent {
		roots[ce.Find(addr)] = true
	}
	return len(roots)
}

// TotalAddresses returns the number of tracked addresses
func (ce *ClusterEngine) TotalAddresses() int {
	return len(ce.parent)
}
