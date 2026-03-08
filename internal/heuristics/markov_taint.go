package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Markov Taint Scoring Engine (Phase 18)
//
// Implements absorbing random walk analysis on the transaction graph.
// Given a starting address, computes the probability that a random walk
// through the transaction fan-out will eventually be absorbed by known
// entities (exchanges, mixers, darknet markets).
//
// Mathematical model:
//   Defines a Markov chain over the transaction graph. Absorbing states
//   are known entities. Transient states are intermediate addresses.
//   Absorption probability B = (I - Q)^{-1} R, computed iteratively
//   using the power method to avoid O(V³) matrix inversion.
//
// Complexity: O(E × D × I) where E = edges, D = max depth, I = iterations
//
// References:
//   - Chainalysis, "Reactor Entity Mapping" (proprietary, inferred from patents)
//   - Meiklejohn et al., "A Fistful of Bitcoins" (IMC 2013)
//   - Ron & Shamir, "Quantitative Analysis of the Full Bitcoin TX Graph" (FC 2013)

const (
	// markovMaxDepth limits the BFS/random walk depth to prevent explosion.
	markovMaxDepth = 10

	// markovMaxIterations caps the power method convergence iterations.
	markovMaxIterations = 50

	// markovConvergenceEpsilon is the threshold for probability stabilization.
	markovConvergenceEpsilon = 1e-6
)

// TransactionGraphNode represents a node in the transaction graph for Markov analysis.
type TransactionGraphNode struct {
	Address  string
	Edges    []TransactionGraphEdge
	IsAbsorber bool   // True if this address is a known exchange/mixer/entity
	Label      string // Entity label for absorbers
}

// TransactionGraphEdge represents a directed edge with a transition probability.
type TransactionGraphEdge struct {
	ToAddress   string
	Value       int64
	Probability float64 // Transition probability (value-weighted)
}

// TransactionGraph is a sparse adjacency list representation.
type TransactionGraph struct {
	Nodes map[string]*TransactionGraphNode
}

// NewTransactionGraph creates an empty graph.
func NewTransactionGraph() *TransactionGraph {
	return &TransactionGraph{
		Nodes: make(map[string]*TransactionGraphNode),
	}
}

// AddTransaction ingests a transaction into the graph, creating edges
// from each input address to each output address weighted by value.
func (g *TransactionGraph) AddTransaction(tx models.Transaction) {
	totalOutputValue := int64(0)
	for _, out := range tx.Outputs {
		totalOutputValue += out.Value
	}
	if totalOutputValue <= 0 {
		return
	}

	for _, in := range tx.Inputs {
		if in.Address == "" {
			continue
		}

		// Ensure source node exists
		if _, exists := g.Nodes[in.Address]; !exists {
			g.Nodes[in.Address] = &TransactionGraphNode{
				Address: in.Address,
			}
		}

		for _, out := range tx.Outputs {
			if out.Address == "" || out.Address == in.Address {
				continue
			}

			// Ensure destination node exists
			if _, exists := g.Nodes[out.Address]; !exists {
				g.Nodes[out.Address] = &TransactionGraphNode{
					Address: out.Address,
				}
			}

			// Transition probability = output value / total output value
			prob := float64(out.Value) / float64(totalOutputValue)

			g.Nodes[in.Address].Edges = append(g.Nodes[in.Address].Edges, TransactionGraphEdge{
				ToAddress:   out.Address,
				Value:       out.Value,
				Probability: prob,
			})
		}
	}
}

// MarkAbsorber flags an address as a known absorbing entity.
func (g *TransactionGraph) MarkAbsorber(address string, label string) {
	node, exists := g.Nodes[address]
	if !exists {
		g.Nodes[address] = &TransactionGraphNode{
			Address:    address,
			IsAbsorber: true,
			Label:      label,
		}
		return
	}
	node.IsAbsorber = true
	node.Label = label
}

// ComputeMarkovScore computes the absorption probabilities from startAddr
// to all known absorbers using an iterative power method (BFS-bounded).
func ComputeMarkovScore(startAddr string, graph *TransactionGraph) models.MarkovScoreResult {
	result := models.MarkovScoreResult{
		StartAddress: startAddr,
	}

	if graph == nil || len(graph.Nodes) == 0 {
		return result
	}

	startNode, exists := graph.Nodes[startAddr]
	if !exists || startNode.IsAbsorber {
		// If the start is itself an absorber, probability = 1.0
		if exists && startNode.IsAbsorber {
			result.AbsorptionProbs = []models.AbsorptionTarget{
				{Address: startAddr, Label: startNode.Label, Probability: 1.0, HopsAway: 0},
			}
			result.PrimaryDestination = startNode.Label
			result.PrimaryProbability = 1.0
			result.ConvergenceReached = true
		}
		return result
	}

	// Collect all absorber addresses
	absorbers := make(map[string]string) // address → label
	for addr, node := range graph.Nodes {
		if node.IsAbsorber {
			absorbers[addr] = node.Label
		}
	}

	if len(absorbers) == 0 {
		return result
	}

	// Initialize probability vector: P[absorber] = probability of being absorbed there
	probs := make(map[string]float64) // absorber address → cumulative probability

	// BFS-bounded iterative simulation (power method)
	// frontier[addr] = probability mass at that address in current iteration
	frontier := map[string]float64{startAddr: 1.0}

	visited := make(map[string]bool)
	totalNodesVisited := 0
	maxHops := 0
	converged := false

	for depth := 0; depth < markovMaxDepth; depth++ {
		nextFrontier := make(map[string]float64)

		for addr, mass := range frontier {
			if mass < markovConvergenceEpsilon {
				continue
			}

			node, exists := graph.Nodes[addr]
			if !exists {
				continue
			}

			if !visited[addr] {
				visited[addr] = true
				totalNodesVisited++
			}

			// If this is an absorber, accumulate the mass
			if node.IsAbsorber {
				probs[addr] += mass
				continue
			}

			// Distribute mass to neighbors
			if len(node.Edges) == 0 {
				continue
			}

			for _, edge := range node.Edges {
				nextMass := mass * edge.Probability
				if nextMass < markovConvergenceEpsilon {
					continue
				}
				nextFrontier[edge.ToAddress] += nextMass
			}
		}

		if len(nextFrontier) == 0 {
			converged = true
			break
		}

		frontier = nextFrontier
		if depth+1 > maxHops {
			maxHops = depth + 1
		}
	}

	// Build result
	result.MaxHopsTraversed = maxHops
	result.TotalNodesVisited = totalNodesVisited
	result.ConvergenceReached = converged

	bestProb := 0.0
	bestLabel := ""
	for addr, label := range absorbers {
		prob := probs[addr]
		if prob > 0 {
			hop := computeShortestPath(graph, startAddr, addr, markovMaxDepth)
			result.AbsorptionProbs = append(result.AbsorptionProbs, models.AbsorptionTarget{
				Address:     addr,
				Label:       label,
				Probability: math.Round(prob*10000) / 10000,
				HopsAway:    hop,
			})
			if prob > bestProb {
				bestProb = prob
				bestLabel = label
			}
		}
	}

	result.PrimaryDestination = bestLabel
	result.PrimaryProbability = math.Round(bestProb*10000) / 10000

	return result
}

// computeShortestPath finds the shortest path length from src to dst using BFS.
func computeShortestPath(graph *TransactionGraph, src, dst string, maxDepth int) int {
	if src == dst {
		return 0
	}

	visited := map[string]bool{src: true}
	queue := []struct {
		addr string
		hops int
	}{{src, 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.hops >= maxDepth {
			continue
		}

		node, exists := graph.Nodes[current.addr]
		if !exists {
			continue
		}

		for _, edge := range node.Edges {
			if edge.ToAddress == dst {
				return current.hops + 1
			}
			if !visited[edge.ToAddress] {
				visited[edge.ToAddress] = true
				queue = append(queue, struct {
					addr string
					hops int
				}{edge.ToAddress, current.hops + 1})
			}
		}
	}

	return maxDepth // Unreachable within max depth
}
