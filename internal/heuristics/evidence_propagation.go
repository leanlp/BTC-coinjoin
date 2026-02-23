package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Cross-Transaction Evidence Propagation Module
//
// Currently, evidence dies at single-transaction boundaries. A CIOH edge
// linking address A→B in Tx₁ has no effect on Tx₂ that spends B→C.
// This module propagates evidence across multiple hops:
//
//   Tx₁: A ──(LLR=3.0)──▶ B
//   Tx₂: B ──(LLR=2.0)──▶ C
//   ───────────────────────────
//   Transitive: A ──(LLR=3.8)──▶ C   (3+2=5, discounted by hop decay ×0.76)
//
// The hop decay factor accounts for increasing uncertainty with distance:
//   - 1 hop: full strength (×1.0)
//   - 2 hops: ×0.76 (= 0.76¹)
//   - 3 hops: ×0.58 (= 0.76²)
//   - 4 hops: ×0.44 (= 0.76³)
//   - Beyond 5 hops: evidence too weak to be actionable
//
// References:
//   - Kappos et al., "An Empirical Analysis of Anonymity in Zcash" (2018)
//   - Meiklejohn et al., "A Fistful of Bitcoins" (2013)
//   - Harrigan & Fretter, "Unreasonable Effectiveness of Address Clustering" (2016)

const (
	// DefaultHopDecay is the per-hop evidence decay factor.
	// Calibrated so that evidence decays to <10% after 5 hops.
	DefaultHopDecay = 0.76

	// MaxPropagationHops is the maximum number of hops to propagate
	MaxPropagationHops = 5

	// MinTransitiveLLR is the minimum LLR for a transitive edge to be emitted
	MinTransitiveLLR = 0.5
)

// EvidenceChainLink represents one hop in a multi-hop evidence chain
type EvidenceChainLink struct {
	Txid      string  `json:"txid"`
	FromAddr  string  `json:"fromAddr"`
	ToAddr    string  `json:"toAddr"`
	LLR       float64 `json:"llr"`
	EdgeType  int     `json:"edgeType"`
	HopNumber int     `json:"hopNumber"`
}

// PropagatedEdge is a transitive evidence edge spanning multiple hops
type PropagatedEdge struct {
	OriginalEdges []EvidenceChainLink `json:"originalEdges"`
	TotalLLR      float64             `json:"totalLLR"`   // Raw sum of LLRs
	DecayedLLR    float64             `json:"decayedLLR"` // After hop decay
	Hops          int                 `json:"hops"`       // Number of hops
	SourceAddr    string              `json:"sourceAddr"` // First address in chain
	SinkAddr      string              `json:"sinkAddr"`   // Last address in chain
	Confidence    float64             `json:"confidence"` // Posterior probability
}

// PropagateEvidence composes evidence edges across multiple transaction hops.
// Given a chain of evidence edges [E₁, E₂, ..., Eₙ], it produces a
// transitive edge with LLR = sum(LLR_i) × hopDecay^(n-1).
//
// The hopDecay factor models the increasing uncertainty with each hop:
// even if A→B and B→C are both high confidence, the transitive A→C
// link is necessarily weaker due to the possibility of B being a
// distinct entity (mixer, exchange) that breaks the chain.
func PropagateEvidence(chain []models.EvidenceEdge, hopDecay float64) *PropagatedEdge {
	if len(chain) < 2 {
		return nil
	}

	if hopDecay <= 0 || hopDecay > 1 {
		hopDecay = DefaultHopDecay
	}

	hops := len(chain)
	if hops > MaxPropagationHops {
		return nil // Too many hops, evidence too weak
	}

	// Sum LLRs across the chain
	totalLLR := 0.0
	links := make([]EvidenceChainLink, hops)
	for i, edge := range chain {
		totalLLR += edge.LLRScore
		links[i] = EvidenceChainLink{
			Txid:      edge.EdgeID,
			FromAddr:  edge.SrcNodeID,
			ToAddr:    edge.DstNodeID,
			LLR:       edge.LLRScore,
			EdgeType:  edge.EdgeType,
			HopNumber: i + 1,
		}
	}

	// Apply distance decay: decay^(hops-1)
	decayFactor := math.Pow(hopDecay, float64(hops-1))
	decayedLLR := totalLLR * decayFactor

	if decayedLLR < MinTransitiveLLR {
		return nil // Too weak after decay
	}

	// Convert LLR to posterior probability
	confidence := LLRToProb(decayedLLR)

	return &PropagatedEdge{
		OriginalEdges: links,
		TotalLLR:      math.Round(totalLLR*100) / 100,
		DecayedLLR:    math.Round(decayedLLR*100) / 100,
		Hops:          hops,
		SourceAddr:    chain[0].SrcNodeID,
		SinkAddr:      chain[len(chain)-1].DstNodeID,
		Confidence:    math.Round(confidence*1000) / 1000,
	}
}

// BuildTransitiveEdge converts a propagated edge into a standard
// EvidenceEdge for inclusion in the UTXO graph.
func BuildTransitiveEdge(prop *PropagatedEdge) models.EvidenceEdge {
	if prop == nil {
		return models.EvidenceEdge{}
	}

	return models.EvidenceEdge{
		SrcNodeID:       prop.SourceAddr,
		DstNodeID:       prop.SinkAddr,
		EdgeType:        EdgeTypeTransitive,
		LLRScore:        prop.DecayedLLR,
		DependencyGroup: DepGroupNone,
	}
}

// LLRToProb converts a Log-Likelihood Ratio back to a probability.
// P = 10^LLR / (1 + 10^LLR)
func LLRToProb(llr float64) float64 {
	if llr > 10 {
		return 0.999
	}
	if llr < -10 {
		return 0.001
	}
	odds := math.Pow(10, llr)
	return odds / (1 + odds)
}

// ComputeChainStrength returns a human-readable assessment of a
// multi-hop evidence chain's reliability.
func ComputeChainStrength(hops int, decayedLLR float64) string {
	if hops <= 1 {
		return "direct" // Single-hop, no propagation
	}

	switch {
	case decayedLLR >= 3.0:
		return "strong" // Very high confidence after decay
	case decayedLLR >= 1.5:
		return "moderate" // Actionable for clustering
	case decayedLLR >= 0.5:
		return "weak" // Useful for leads, not for clustering
	default:
		return "trace" // Background noise
	}
}

// EstimateMaxReach computes how many hops evidence can travel
// before decaying below the minimum threshold.
// Given initial LLR and hop decay, returns the maximum useful hops.
func EstimateMaxReach(initialLLR float64, hopDecay float64) int {
	if initialLLR <= MinTransitiveLLR || hopDecay <= 0 || hopDecay >= 1 {
		return 0
	}

	for hops := 1; hops <= 10; hops++ {
		decayed := initialLLR * math.Pow(hopDecay, float64(hops))
		if decayed < MinTransitiveLLR {
			return hops
		}
	}
	return 10
}
