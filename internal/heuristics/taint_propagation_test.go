package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

func TestPropagateTaintAdvanced_Proportional(t *testing.T) {
	// Setup: seed a tainted address
	InitGlobalTaintMap()
	SeedFromExternalIntel([]TaintSource{
		{Address: "TAINTED_ADDR_1", Category: "theft", TaintLevel: 1.0, Label: "Lazarus"},
	})

	tx := models.Transaction{
		Txid: "test_proportional",
		Inputs: []models.TxIn{
			{Value: 100000000, Address: "TAINTED_ADDR_1"}, // 1 BTC, fully tainted
			{Value: 100000000, Address: "CLEAN_ADDR_1"},   // 1 BTC, clean
		},
		Outputs: []models.TxOut{
			{Value: 99000000, Address: "OUT_1"},
			{Value: 99000000, Address: "OUT_2"},
		},
	}

	result := PropagateTaintAdvanced(tx, "proportional")

	if result.Method != "proportional" {
		t.Errorf("Expected method 'proportional', got '%s'", result.Method)
	}

	// 50% of input value is tainted → each output should get ~50% taint
	for _, ot := range result.OutputTaints {
		if ot.TaintLevel < 0.45 || ot.TaintLevel > 0.55 {
			t.Errorf("Expected ~50%% taint on output %d, got %.4f", ot.Index, ot.TaintLevel)
		}
	}

	if result.InputTaintLevel < 0.45 || result.InputTaintLevel > 0.55 {
		t.Errorf("Expected ~50%% aggregate input taint, got %.4f", result.InputTaintLevel)
	}
}

func TestPropagateTaintAdvanced_FIFO(t *testing.T) {
	InitGlobalTaintMap()
	SeedFromExternalIntel([]TaintSource{
		{Address: "FIFO_TAINTED", Category: "ransomware", TaintLevel: 1.0, Label: "Conti"},
	})

	tx := models.Transaction{
		Txid: "test_fifo",
		Inputs: []models.TxIn{
			{Value: 50000000, Address: "FIFO_TAINTED"}, // 0.5 BTC, fully tainted (first)
			{Value: 50000000, Address: "FIFO_CLEAN"},   // 0.5 BTC, clean (second)
		},
		Outputs: []models.TxOut{
			{Value: 50000000, Address: "FIFO_OUT_1"}, // Should absorb all taint (FIFO)
			{Value: 48000000, Address: "FIFO_OUT_2"}, // Should be clean
		},
	}

	result := PropagateTaintAdvanced(tx, "fifo")

	if result.Method != "fifo" {
		t.Errorf("Expected method 'fifo', got '%s'", result.Method)
	}

	// FIFO: first 50M tainted sats fill first output (50M) entirely
	if len(result.OutputTaints) < 2 {
		t.Fatal("Expected at least 2 output taint entries")
	}

	if result.OutputTaints[0].TaintLevel < 0.95 {
		t.Errorf("FIFO: first output should be ~100%% tainted, got %.4f", result.OutputTaints[0].TaintLevel)
	}

	if result.OutputTaints[1].TaintLevel > 0.05 {
		t.Errorf("FIFO: second output should be ~0%% tainted, got %.4f", result.OutputTaints[1].TaintLevel)
	}
}

func TestPropagateTaintAdvanced_CleanTx(t *testing.T) {
	InitGlobalTaintMap()

	tx := models.Transaction{
		Txid: "test_clean",
		Inputs: []models.TxIn{
			{Value: 100000000, Address: "TOTALLY_CLEAN_ADDR"},
		},
		Outputs: []models.TxOut{
			{Value: 99900000, Address: "CLEAN_OUT_1"},
		},
	}

	result := PropagateTaintAdvanced(tx, "proportional")

	if result.InputTaintLevel != 0 {
		t.Errorf("Expected 0 input taint for clean tx, got %.4f", result.InputTaintLevel)
	}

	for _, ot := range result.OutputTaints {
		if ot.TaintLevel != 0 {
			t.Errorf("Expected 0 output taint for clean tx, got %.4f", ot.TaintLevel)
		}
	}
}
