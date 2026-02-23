package heuristics

import (
	"math"
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

func TestEvaluateFactorGraph_IndependentEdges(t *testing.T) {
	// Two independent edges (different dependency groups) should add LLRs
	edges := []models.EvidenceEdge{
		{EdgeType: 1, LLRScore: 1.28, DependencyGroup: 0}, // Independent: CIOH
		{EdgeType: 2, LLRScore: 0.95, DependencyGroup: 2}, // Independent: Value constraint
	}

	result := EvaluateFactorGraph(edges)

	expectedLLR := 1.28 + 0.95
	if result.PosteriorLLR != expectedLLR {
		t.Errorf("Expected posterior LLR to be %.2f for independent edges. Got: %.2f", expectedLLR, result.PosteriorLLR)
	}

	if result.DiscountedEdges != 0 {
		t.Errorf("Expected 0 discounted edges. Got: %d", result.DiscountedEdges)
	}

	if result.EffectiveFactors != 2 {
		t.Errorf("Expected 2 effective factors. Got: %d", result.EffectiveFactors)
	}

	if result.ConfidenceLevel != "high" {
		t.Errorf("Expected 'high' confidence. Got: %s", result.ConfidenceLevel)
	}
}

func TestEvaluateFactorGraph_CorrelatedEdges(t *testing.T) {
	// Three edges in the SAME dependency group → only strongest contributes
	edges := []models.EvidenceEdge{
		{EdgeType: 1, LLRScore: 0.60, DependencyGroup: 1}, // Script homogeneity
		{EdgeType: 1, LLRScore: 1.28, DependencyGroup: 1}, // Same group (correlated)
		{EdgeType: 1, LLRScore: 0.45, DependencyGroup: 1}, // Same group (correlated)
	}

	result := EvaluateFactorGraph(edges)

	// Only the max (1.28) should survive fusion
	if result.PosteriorLLR != 1.28 {
		t.Errorf("Expected posterior LLR to be 1.28 after fusion. Got: %.2f", result.PosteriorLLR)
	}

	if result.DiscountedEdges != 2 {
		t.Errorf("Expected 2 discounted edges. Got: %d", result.DiscountedEdges)
	}

	if result.EffectiveFactors != 1 {
		t.Errorf("Expected 1 effective factor. Got: %d", result.EffectiveFactors)
	}
}

func TestEvaluateFactorGraph_MixedGroups(t *testing.T) {
	// Realistic scenario: 2 independent groups, one with correlated edges
	edges := []models.EvidenceEdge{
		{EdgeType: 1, LLRScore: 1.28, DependencyGroup: 0},  // CIOH (independent)
		{EdgeType: 2, LLRScore: 0.60, DependencyGroup: 1},  // Script (group 1)
		{EdgeType: 2, LLRScore: 0.80, DependencyGroup: 1},  // Script (group 1, correlated)
		{EdgeType: 3, LLRScore: -2.0, DependencyGroup: 3},  // Negative gating (independent)
	}

	result := EvaluateFactorGraph(edges)

	// posterior = 1.28 + max(0.60, 0.80) + (-2.0) = 1.28 + 0.80 - 2.0 = 0.08
	expected := 1.28 + 0.80 + (-2.0)
	if math.Abs(result.PosteriorLLR-expected) > 0.001 {
		t.Errorf("Expected posterior %.2f. Got: %.2f", expected, result.PosteriorLLR)
	}

	// Negative gating (CoinJoin) overwhelms the positive evidence
	if result.ConfidenceLevel != "rejected" {
		t.Errorf("Expected 'rejected' due to negative gating. Got: %s", result.ConfidenceLevel)
	}

	if result.DiscountedEdges != 1 {
		t.Errorf("Expected 1 discounted edge. Got: %d", result.DiscountedEdges)
	}
}

func TestComputeClusterPosterior_ShouldCluster(t *testing.T) {
	edges := []models.EvidenceEdge{
		{EdgeType: 1, LLRScore: 1.28, DependencyGroup: 0},
		{EdgeType: 2, LLRScore: 0.95, DependencyGroup: 2},
	}

	shouldCluster, llr := ComputeClusterPosterior(edges)

	if !shouldCluster {
		t.Error("Expected cluster to be materialized with strong evidence")
	}

	if llr < 2.0 {
		t.Errorf("Expected LLR > 2.0. Got: %f", llr)
	}
}

func TestComputeClusterPosterior_ShouldReject(t *testing.T) {
	edges := []models.EvidenceEdge{
		{EdgeType: 1, LLRScore: 0.3, DependencyGroup: 0}, // Weak evidence
	}

	shouldCluster, _ := ComputeClusterPosterior(edges)

	if shouldCluster {
		t.Error("Expected cluster to be rejected with weak evidence")
	}
}
