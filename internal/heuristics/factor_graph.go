package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// FactorGraphInference implements the dependency-aware evidence composition
// layer described in the architecture.
//
// Factor-graph semantics: A global function is expressed as a product of local functions.
// The sum-product algorithm computes marginal beliefs efficiently.
//
// Independent features → separate factors, multiply in log-space (add LLRs)
// Correlated features → fused into one factor or down-weighted jointly
//
// This prevents the "confidence inflation" anti-pattern where overlapping
// heuristics (script homogeneity + round numbers + optimal change) falsely
// inflate linkage confidence.

// InferenceResult is re-exported from models for convenience
// See models.InferenceResult for the canonical definition.

// EvaluateFactorGraph takes a set of evidence edges and produces a calibrated
// posterior belief by grouping edges by dependency_group, fusing correlated
// signals, and summing independent LLR contributions.
//
// Mathematical basis:
//   posterior_LLR = sum of max(LLR per group)
//   rather than:   sum of ALL LLRs (which double-counts)
func EvaluateFactorGraph(edges []models.EvidenceEdge) models.InferenceResult {
	if len(edges) == 0 {
		return models.InferenceResult{
			PosteriorLLR:    0,
			ConfidenceLevel: "rejected",
		}
	}

	// Group edges by dependency_group
	groups := make(map[int][]models.EvidenceEdge)
	for _, edge := range edges {
		groups[edge.DependencyGroup] = append(groups[edge.DependencyGroup], edge)
	}

	// For each dependency group, fuse the correlated signals.
	// Strategy: take the MAXIMUM LLR within each group (conservative fusion).
	// This prevents double-counting: correlated features contribute at most
	// the strength of the strongest single feature.
	var posteriorLLR float64
	discounted := 0

	for _, groupEdges := range groups {
		if len(groupEdges) == 0 {
			continue
		}

		// Find the strongest signal in this dependency group
		maxLLR := groupEdges[0].LLRScore
		for _, edge := range groupEdges[1:] {
			if math.Abs(edge.LLRScore) > math.Abs(maxLLR) {
				maxLLR = edge.LLRScore
			}
		}

		// The remaining edges in this group are discounted (fused)
		discounted += len(groupEdges) - 1

		// Add the group's representative to the posterior
		posteriorLLR += maxLLR
	}

	// Classify confidence level based on posterior LLR magnitude
	confidenceLevel := classifyConfidence(posteriorLLR)

	return models.InferenceResult{
		PosteriorLLR:     posteriorLLR,
		ConfidenceLevel:  confidenceLevel,
		DiscountedEdges:  discounted,
		TotalEdges:       len(edges),
		EffectiveFactors: len(groups),
	}
}

// classifyConfidence maps the posterior LLR to a human-readable confidence band.
// Based on Jeffrey's scale for evidence strength:
//   |LLR| > 2.0  → "high"     (decisive evidence)
//   |LLR| > 1.0  → "medium"   (strong evidence)
//   |LLR| > 0.5  → "low"      (moderate evidence)
//   |LLR| <= 0.5 → "rejected" (insufficient evidence)
func classifyConfidence(llr float64) string {
	absLLR := math.Abs(llr)
	switch {
	case absLLR > 2.0:
		return "high"
	case absLLR > 1.0:
		return "medium"
	case absLLR > 0.5:
		return "low"
	default:
		return "rejected"
	}
}

// ComputeClusterPosterior evaluates whether a set of addresses belong to the
// same entity by running factor-graph inference over all evidence edges
// connecting them.
//
// This is the core function called by the Policy Snapshot Compiler to
// materialize cluster views.
func ComputeClusterPosterior(edges []models.EvidenceEdge) (bool, float64) {
	result := EvaluateFactorGraph(edges)

	// A cluster is materialized only if the posterior confidence is "medium" or higher
	// This prevents cluster collapse from weak/correlated evidence
	shouldCluster := result.ConfidenceLevel == "high" || result.ConfidenceLevel == "medium"

	return shouldCluster, result.PosteriorLLR
}
