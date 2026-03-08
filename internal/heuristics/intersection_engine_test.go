package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// TestRegisterAndIntersect_TwoRounds verifies that two CoinJoin rounds with
// overlapping participants correctly compute the intersection.
// Round 1: {Alice, Bob, Carol, Dave, Eve}
// Round 2: {Alice, Bob, Frank, Grace, Heidi}
// Intersection: {Alice, Bob} → effective anonset = 2
func TestRegisterAndIntersect_TwoRounds(t *testing.T) {
	registry := &IntersectionRegistry{
		roundParticipants: make(map[string]map[string]bool),
		addressRounds:     make(map[string][]string),
		roundMeta:         make(map[string]ParticipantSet),
	}

	// Round 1: 5 participants
	tx1 := models.Transaction{
		Txid:   "round1_txid",
		Inputs: make([]models.TxIn, 5),
		Outputs: []models.TxOut{
			{Address: "Alice", Value: 1000000},
			{Address: "Bob", Value: 1000000},
			{Address: "Carol", Value: 1000000},
			{Address: "Dave", Value: 1000000},
			{Address: "Eve", Value: 1000000},
		},
	}
	result1 := models.PrivacyAnalysisResult{
		AnonSet:        5,
		HeuristicFlags: uint64(FlagLikelyCollabConstruct),
	}
	registry.RegisterCoinJoinParticipants(tx1, result1)

	// Round 2: 5 participants, 2 overlap with Round 1
	tx2 := models.Transaction{
		Txid:   "round2_txid",
		Inputs: make([]models.TxIn, 5),
		Outputs: []models.TxOut{
			{Address: "Alice", Value: 1000000},
			{Address: "Bob", Value: 1000000},
			{Address: "Frank", Value: 1000000},
			{Address: "Grace", Value: 1000000},
			{Address: "Heidi", Value: 1000000},
		},
	}
	result2 := models.PrivacyAnalysisResult{
		AnonSet:        5,
		HeuristicFlags: uint64(FlagLikelyCollabConstruct),
	}
	registry.RegisterCoinJoinParticipants(tx2, result2)

	// Analyze intersection for Alice
	analysis := registry.ComputeIntersection("Alice")

	if analysis.TotalRounds != 2 {
		t.Errorf("expected 2 rounds, got %d", analysis.TotalRounds)
	}
	if analysis.EffectiveAnonSet != 2 {
		t.Errorf("expected effective anonset 2, got %d", analysis.EffectiveAnonSet)
	}
	if !analysis.IsVulnerable {
		t.Error("expected IsVulnerable to be true (effective anonset ≤ 3)")
	}
	if analysis.ErosionRate < 0.5 {
		t.Errorf("expected erosion rate > 0.5, got %.2f", analysis.ErosionRate)
	}
}

// TestIntersection_NoOverlap verifies that disjoint participant sets
// produce an empty intersection (effective anonset = 0).
func TestIntersection_NoOverlap(t *testing.T) {
	registry := &IntersectionRegistry{
		roundParticipants: make(map[string]map[string]bool),
		addressRounds:     make(map[string][]string),
		roundMeta:         make(map[string]ParticipantSet),
	}

	// Manually register a unique address in two rounds with different co-participants
	registry.roundParticipants["round_a"] = map[string]bool{
		"Target": true, "X1": true, "X2": true,
	}
	registry.roundParticipants["round_b"] = map[string]bool{
		"Target": true, "Y1": true, "Y2": true,
	}
	registry.addressRounds["Target"] = []string{"round_a", "round_b"}
	registry.roundMeta["round_a"] = ParticipantSet{Txid: "round_a", Protocol: "wasabi"}
	registry.roundMeta["round_b"] = ParticipantSet{Txid: "round_b", Protocol: "wasabi"}

	analysis := registry.ComputeIntersection("Target")

	// Only "Target" itself appears in both rounds
	if analysis.EffectiveAnonSet != 1 {
		t.Errorf("expected effective anonset 1 (only target), got %d", analysis.EffectiveAnonSet)
	}
	if !analysis.IsVulnerable {
		t.Error("expected IsVulnerable = true when effective anonset = 1")
	}
}

// TestIntersection_FullOverlap verifies that identical participant sets
// preserve the original anonset.
func TestIntersection_FullOverlap(t *testing.T) {
	registry := &IntersectionRegistry{
		roundParticipants: make(map[string]map[string]bool),
		addressRounds:     make(map[string][]string),
		roundMeta:         make(map[string]ParticipantSet),
	}

	participants := map[string]bool{
		"A": true, "B": true, "C": true, "D": true, "E": true,
	}

	registry.roundParticipants["r1"] = participants
	registry.roundParticipants["r2"] = participants
	registry.addressRounds["A"] = []string{"r1", "r2"}
	registry.roundMeta["r1"] = ParticipantSet{Txid: "r1", Protocol: "whirlpool"}
	registry.roundMeta["r2"] = ParticipantSet{Txid: "r2", Protocol: "whirlpool"}

	analysis := registry.ComputeIntersection("A")

	if analysis.EffectiveAnonSet != 5 {
		t.Errorf("expected effective anonset 5 (full overlap), got %d", analysis.EffectiveAnonSet)
	}
	if analysis.ErosionRate != 0.0 {
		t.Errorf("expected erosion rate 0.0, got %.2f", analysis.ErosionRate)
	}
	if analysis.IsVulnerable {
		t.Error("expected IsVulnerable = false when effective anonset = 5")
	}
}

// TestEffectiveAnonSet_DegradedByIntersection verifies progressive erosion
// across 3 rounds. Each round removes some participants from the intersection.
func TestEffectiveAnonSet_DegradedByIntersection(t *testing.T) {
	registry := &IntersectionRegistry{
		roundParticipants: make(map[string]map[string]bool),
		addressRounds:     make(map[string][]string),
		roundMeta:         make(map[string]ParticipantSet),
	}

	// Round 1: {T, A, B, C, D}    (anonset=5)
	// Round 2: {T, A, B, E, F}    (anonset=5, intersection with R1: {T,A,B} = 3)
	// Round 3: {T, A, G, H, I}    (anonset=5, intersection with R1∩R2: {T,A} = 2)
	registry.roundParticipants["r1"] = map[string]bool{"T": true, "A": true, "B": true, "C": true, "D": true}
	registry.roundParticipants["r2"] = map[string]bool{"T": true, "A": true, "B": true, "E": true, "F": true}
	registry.roundParticipants["r3"] = map[string]bool{"T": true, "A": true, "G": true, "H": true, "I": true}
	registry.addressRounds["T"] = []string{"r1", "r2", "r3"}
	registry.roundMeta["r1"] = ParticipantSet{Txid: "r1", Protocol: "wasabi"}
	registry.roundMeta["r2"] = ParticipantSet{Txid: "r2", Protocol: "wasabi"}
	registry.roundMeta["r3"] = ParticipantSet{Txid: "r3", Protocol: "wasabi"}

	analysis := registry.ComputeIntersection("T")

	if analysis.TotalRounds != 3 {
		t.Errorf("expected 3 rounds, got %d", analysis.TotalRounds)
	}
	if analysis.EffectiveAnonSet != 2 {
		t.Errorf("expected effective anonset 2 (T∩all rounds = {T, A}), got %d", analysis.EffectiveAnonSet)
	}
	if !analysis.IsVulnerable {
		t.Error("expected IsVulnerable = true (effective anonset ≤ 3)")
	}
	if analysis.Confidence <= 0.5 {
		t.Errorf("expected confidence > 0.5 with 3 rounds, got %.2f", analysis.Confidence)
	}

	// Verify pairwise intersections
	if len(analysis.PairwiseIntersections) != 3 {
		t.Errorf("expected 3 pairwise intersections (C(3,2)), got %d", len(analysis.PairwiseIntersections))
	}

	// GetEffectiveAnonSet should also return 2
	effective := registry.GetEffectiveAnonSet("T")
	if effective != 2 {
		t.Errorf("GetEffectiveAnonSet expected 2, got %d", effective)
	}
}
