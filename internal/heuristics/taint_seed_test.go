package heuristics

import (
	"math"
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

func resetTaintMapForTest(entries map[string]float64) {
	taintMu.Lock()
	defer taintMu.Unlock()

	globalTaintMap = NewTaintMap()
	for addr, level := range entries {
		globalTaintMap[addr] = level
	}
}

func TestCheckInputsForTaint_WeightedExposure(t *testing.T) {
	resetTaintMapForTest(map[string]float64{
		"tainted": 1.0,
	})

	tx := models.Transaction{
		Inputs: []models.TxIn{
			{Address: "tainted", Value: 10000},
			{Address: "clean", Value: 90000},
		},
		Outputs: []models.TxOut{
			{Value: 100000},
		},
	}

	exposure, highRisk := CheckInputsForTaint(tx)

	if math.Abs(exposure-0.10) > 0.0001 {
		t.Fatalf("expected exposure=0.10, got %.4f", exposure)
	}
	if highRisk {
		t.Fatalf("expected highRisk=false for 10%% weighted taint")
	}
}

func TestCheckInputsForTaint_UsesOutputDenominatorWhenInputsSparse(t *testing.T) {
	resetTaintMapForTest(map[string]float64{
		"tainted": 1.0,
	})

	tx := models.Transaction{
		Inputs: []models.TxIn{
			{Address: "tainted", Value: 1000},
			{Address: "unknown", Value: 0},
		},
		Outputs: []models.TxOut{
			{Value: 100000},
		},
	}

	exposure, _ := CheckInputsForTaint(tx)

	if math.Abs(exposure-0.01) > 0.0001 {
		t.Fatalf("expected exposure=0.01 with output fallback denominator, got %.4f", exposure)
	}
}

func TestScoreTransaction_TaintSignalsEscalateRisk(t *testing.T) {
	resetTaintMapForTest(map[string]float64{
		"tainted": 1.0,
	})

	tx := models.Transaction{
		Txid: "tx-tainted",
		Inputs: []models.TxIn{
			{Address: "tainted", Value: 50000},
		},
		Outputs: []models.TxOut{
			{Address: "dest", Value: 50000},
		},
	}
	result := models.PrivacyAnalysisResult{
		Txid:         tx.Txid,
		PrivacyScore: 50,
	}

	assessment := ScoreTransaction(tx, result, nil)

	if assessment.RiskScore < 45 {
		t.Fatalf("expected taint-driven risk score >=45, got %d", assessment.RiskScore)
	}
	if assessment.Severity != "medium" && assessment.Severity != "high" && assessment.Severity != "critical" {
		t.Fatalf("expected severity to escalate beyond low, got %s", assessment.Severity)
	}
}
