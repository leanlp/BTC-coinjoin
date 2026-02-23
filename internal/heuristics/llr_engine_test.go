package heuristics

import (
	"math"
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

func TestProbToLLR(t *testing.T) {
	tests := []struct {
		name     string
		prob     float64
		expected float64
	}{
		{"Absolute Certainty", 1.0, 999.0},
		{"Absolute Negative Certainty", 0.0, -999.0},
		{"High Probability", 0.99, math.Log10(0.99 / 0.01)}, // ~1.995
		{"Coin Flip", 0.5, 0.0},
		{"Low Probability", 0.01, math.Log10(0.01 / 0.99)}, // ~-1.995
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProbToLLR(tt.prob)
			// Allow for minor float precision differences
			if math.Abs(result-tt.expected) > 0.001 {
				t.Errorf("ProbToLLR() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGenerateCIOHEdges_StandardPayment(t *testing.T) {
	tx := models.Transaction{
		Txid: "standard_tx",
		Inputs: []models.TxIn{
			{Address: "bc1q_A", Value: 1000},
			{Address: "bc1q_B", Value: 2000},
		},
	}

	edges := GenerateCIOHEdges(tx, false, 800000)

	if len(edges) != 1 {
		t.Fatalf("Expected exactly 1 CIOH edge linking the two inputs, got %d", len(edges))
	}

	edge := edges[0]
	if edge.EdgeType != EdgeTypeCIOH {
		t.Errorf("Expected EdgeTypeCIOH (%d), got %v", EdgeTypeCIOH, edge.EdgeType)
	}
	if edge.SrcNodeID != "bc1q_A" || edge.DstNodeID != "bc1q_B" {
		t.Errorf("Expected edge to link bc1q_A to bc1q_B")
	}
	if edge.LLRScore <= 0 {
		t.Errorf("Expected positive LLR score for a standard CIOH linkage, got %v", edge.LLRScore)
	}
}

func TestGenerateCIOHEdges_CoinJoinGating(t *testing.T) {
	tx := models.Transaction{
		Txid: "coinjoin_tx",
		Inputs: []models.TxIn{
			{Address: "bc1q_A", Value: 1000},
			{Address: "bc1q_B", Value: 1000},
		},
	}

	edges := GenerateCIOHEdges(tx, true, 800000)

	if len(edges) != 4 {
		t.Fatalf("Expected exactly 4 edges (invalidated and suspected for each input), got %d", len(edges))
	}

	for _, edge := range edges {
		if edge.EdgeType != EdgeTypeCIOHInvalidated && edge.EdgeType != EdgeTypeCoinjoinSuspected {
			t.Errorf("Expected EdgeTypeCIOHInvalidated or EdgeTypeCoinjoinSuspected, got %v", edge.EdgeType)
		}
		if edge.DependencyGroup != DepGroupCoordination {
			t.Errorf("Expected DependencyGroup DepGroupCoordination (%d), got %v", DepGroupCoordination, edge.DependencyGroup)
		}
	}
}

func TestBitmaskOperations(t *testing.T) {
	var bitmask uint64 = 0

	// Apply Whirlpool and Address Reuse
	bitmask |= FlagIsWhirlpoolStruct
	bitmask |= FlagAddressReuse

	// Verify Whirlpool is applied
	if bitmask&FlagIsWhirlpoolStruct != FlagIsWhirlpoolStruct {
		t.Errorf("Expected Whirlpool flag to be present")
	}

	// Verify Address Reuse is applied
	if bitmask&FlagAddressReuse != FlagAddressReuse {
		t.Errorf("Expected Address Reuse flag to be present")
	}

	// Verify Wasabi is NOT applied
	if bitmask&FlagIsWasabiSuspect == FlagIsWasabiSuspect {
		t.Errorf("Expected Wasabi flag to NOT be present")
	}
}
