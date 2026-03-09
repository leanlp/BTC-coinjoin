package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Spend-Graph Engine Tests — Full-Node Powered Forensics
// ═══════════════════════════════════════════════════════════════════════

func TestAgeDisparity_LargeSpread(t *testing.T) {
	// One input is 365 days old, another is 1 day old
	ages := []float64{1.0, 365.0}

	result := ComputeAgeDisparity(ages)

	if !result.SameEntity {
		t.Fatal("expected same entity with 364-day age spread")
	}
	if result.Confidence < 0.90 {
		t.Errorf("expected confidence >= 0.90, got %f", result.Confidence)
	}
	if result.SpreadDays != 364.0 {
		t.Errorf("expected spread 364 days, got %f", result.SpreadDays)
	}
}

func TestAgeDisparity_SmallSpread(t *testing.T) {
	// Both inputs are ~1 day old
	ages := []float64{0.5, 1.5}

	result := ComputeAgeDisparity(ages)

	if result.SameEntity {
		t.Error("should not flag same entity with 1-day spread")
	}
	if result.Confidence > 0.50 {
		t.Errorf("expected low confidence, got %f", result.Confidence)
	}
}

func TestRoundTracker_MixingHistory(t *testing.T) {
	tracker := GetGlobalRoundTracker()

	addr := "test-mixer-address-xyz"

	// Record 3 mixing rounds
	tracker.RecordRound(addr, RoundParticipation{
		TxID:          "round1",
		Protocol:      "whirlpool",
		Denomination:  5000000,
		AnonSetGained: 5,
		IsRemix:       false,
	})
	tracker.RecordRound(addr, RoundParticipation{
		TxID:          "round2",
		Protocol:      "whirlpool",
		Denomination:  5000000,
		AnonSetGained: 5,
		IsRemix:       true,
	})
	tracker.RecordRound(addr, RoundParticipation{
		TxID:          "round3",
		Protocol:      "whirlpool",
		Denomination:  5000000,
		AnonSetGained: 5,
		IsRemix:       true,
	})

	history := tracker.GetMixingHistory(addr)

	if history.TotalRounds != 3 {
		t.Errorf("expected 3 rounds, got %d", history.TotalRounds)
	}
	if history.TotalRemixes != 2 {
		t.Errorf("expected 2 remixes, got %d", history.TotalRemixes)
	}
	// Cumulative anonset: 5 × 5 × 5 = 125
	if history.CumulativeAnonSet != 125 {
		t.Errorf("expected cumulative anonset 125, got %d", history.CumulativeAnonSet)
	}
}

func TestConfidenceWeightedScore(t *testing.T) {
	// Two high-confidence scores and one low-confidence
	scores := []float64{0.9, 0.8, 0.3}
	confidences := []float64{0.95, 0.90, 0.20}

	result := ConfidenceWeightedScore(scores, confidences)

	// High-confidence scores should dominate
	if result < 0.6 || result > 0.95 {
		t.Errorf("expected confidence-weighted score in [0.6, 0.95], got %f", result)
	}
}

func TestSpendOrder_PaymentFirst(t *testing.T) {
	tx := models.Transaction{
		Txid: "tx-spend-test",
		Outputs: []models.TxOut{
			{Value: 50000, Address: "payee"},   // Index 0 — spent first (payment)
			{Value: 49000, Address: "change"},  // Index 1 — spent later (change)
		},
	}

	spendData := map[int]*SpendInfo{
		0: {SpentInTxid: "spend1", TimeToSpend: 600, IsUnspent: false},    // 10 min
		1: {SpentInTxid: "spend2", TimeToSpend: 86400, IsUnspent: false},  // 1 day
	}

	profile := AnalyzeSpendOrder(tx, spendData)

	if profile.FirstSpentIndex != 0 {
		t.Errorf("expected output 0 spent first, got %d", profile.FirstSpentIndex)
	}
	if profile.ChangeCandidate != 1 {
		t.Errorf("expected output 1 as change candidate, got %d", profile.ChangeCandidate)
	}
	if profile.ChangeConfidence < 0.80 {
		t.Errorf("expected high confidence (>10 min gap), got %f", profile.ChangeConfidence)
	}
}
