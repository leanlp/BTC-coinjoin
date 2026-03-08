package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

func TestAnalyzeTemporalCorrelation_PeriodicPattern(t *testing.T) {
	// Simulate 5 transactions at exactly 60-second intervals (bot behavior)
	baseTx := models.Transaction{
		Txid:      "target_tx",
		BlockTime: 1709900360,
	}
	recentTxs := []models.Transaction{
		{Txid: "tx_1", BlockTime: 1709900300},
		{Txid: "tx_2", BlockTime: 1709900240},
		{Txid: "tx_3", BlockTime: 1709900180},
		{Txid: "tx_4", BlockTime: 1709900120},
	}

	result := AnalyzeTemporalCorrelation(baseTx, recentTxs)

	if !result.HasTimingPattern {
		t.Error("Expected periodic timing pattern to be detected")
	}
	if result.PatternType != "periodic" {
		t.Errorf("Expected 'periodic' pattern, got '%s'", result.PatternType)
	}
	if result.Confidence < 0.5 {
		t.Errorf("Expected high confidence for perfect periodic pattern, got %.4f", result.Confidence)
	}
	if result.IntervalSeconds < 55 || result.IntervalSeconds > 65 {
		t.Errorf("Expected ~60s interval, got %.1f", result.IntervalSeconds)
	}
}

func TestAnalyzeTemporalCorrelation_NoPattern(t *testing.T) {
	// Random timing — no pattern
	baseTx := models.Transaction{
		Txid:      "target_random",
		BlockTime: 1709900000,
	}
	recentTxs := []models.Transaction{
		{Txid: "r_1", BlockTime: 1709800000}, // 100000s ago
		{Txid: "r_2", BlockTime: 1709700000}, // 200000s ago
		{Txid: "r_3", BlockTime: 1709100000}, // 800000s ago
	}

	result := AnalyzeTemporalCorrelation(baseTx, recentTxs)

	// Large irregular intervals should not match periodic or burst
	if result.PatternType == "periodic" || result.PatternType == "burst" {
		t.Errorf("Expected no periodic/burst pattern for irregular timing, got '%s'", result.PatternType)
	}
}

func TestAnalyzeTemporalCorrelation_TimeBucket(t *testing.T) {
	// 14:00 UTC = business hours
	tx := models.Transaction{
		Txid:      "bucket_test",
		BlockTime: 1709906400, // 14:00 UTC
	}
	result := AnalyzeTemporalCorrelation(tx, nil)
	if result.TimeBucket != "business" {
		t.Errorf("Expected 'business' time bucket for 14:00 UTC, got '%s'", result.TimeBucket)
	}
}

func TestMarkovScore_LinearChain(t *testing.T) {
	// A → B → C → Exchange
	graph := NewTransactionGraph()

	graph.AddTransaction(models.Transaction{
		Inputs:  []models.TxIn{{Address: "A", Value: 100000}},
		Outputs: []models.TxOut{{Address: "B", Value: 100000}},
	})
	graph.AddTransaction(models.Transaction{
		Inputs:  []models.TxIn{{Address: "B", Value: 100000}},
		Outputs: []models.TxOut{{Address: "C", Value: 100000}},
	})
	graph.AddTransaction(models.Transaction{
		Inputs:  []models.TxIn{{Address: "C", Value: 100000}},
		Outputs: []models.TxOut{{Address: "EXCHANGE", Value: 100000}},
	})

	graph.MarkAbsorber("EXCHANGE", "binance")

	result := ComputeMarkovScore("A", graph)

	if result.PrimaryDestination != "binance" {
		t.Errorf("Expected primary destination 'binance', got '%s'", result.PrimaryDestination)
	}

	if result.PrimaryProbability < 0.9 {
		t.Errorf("Expected high absorption probability for deterministic chain, got %.4f", result.PrimaryProbability)
	}
}

func TestMarkovScore_BranchingGraph(t *testing.T) {
	// A → B (50%), A → C (50%)
	// B → Exchange1
	// C → Exchange2
	graph := NewTransactionGraph()

	graph.AddTransaction(models.Transaction{
		Inputs: []models.TxIn{{Address: "A", Value: 100000}},
		Outputs: []models.TxOut{
			{Address: "B", Value: 50000},
			{Address: "C", Value: 50000},
		},
	})
	graph.AddTransaction(models.Transaction{
		Inputs:  []models.TxIn{{Address: "B", Value: 50000}},
		Outputs: []models.TxOut{{Address: "EX1", Value: 50000}},
	})
	graph.AddTransaction(models.Transaction{
		Inputs:  []models.TxIn{{Address: "C", Value: 50000}},
		Outputs: []models.TxOut{{Address: "EX2", Value: 50000}},
	})

	graph.MarkAbsorber("EX1", "coinbase")
	graph.MarkAbsorber("EX2", "kraken")

	result := ComputeMarkovScore("A", graph)

	if len(result.AbsorptionProbs) < 2 {
		t.Fatalf("Expected 2 absorption targets, got %d", len(result.AbsorptionProbs))
	}

	// Each exchange should get ~50% probability
	for _, target := range result.AbsorptionProbs {
		if target.Probability < 0.4 || target.Probability > 0.6 {
			t.Errorf("Expected ~50%% for %s, got %.4f", target.Label, target.Probability)
		}
	}
}

func TestMarkovScore_NoAbsorbers(t *testing.T) {
	graph := NewTransactionGraph()
	graph.AddTransaction(models.Transaction{
		Inputs:  []models.TxIn{{Address: "X", Value: 100000}},
		Outputs: []models.TxOut{{Address: "Y", Value: 100000}},
	})

	result := ComputeMarkovScore("X", graph)

	if len(result.AbsorptionProbs) > 0 {
		t.Error("Expected no absorption targets when no absorbers are marked")
	}
}
