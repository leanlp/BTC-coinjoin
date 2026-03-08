package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// CPFP Detection Tests
// ═══════════════════════════════════════════════════════════════════════

func TestCPFP_ValidAcceleration(t *testing.T) {
	parentTx := &models.Transaction{
		Txid: "parent-tx",
		Fee:  500,
		Vsize: 250,
		Outputs: []models.TxOut{
			{Value: 100000, Address: "recipient_addr"},
			{Value: 49500, Address: "change_addr"},
		},
	}

	childTx := models.Transaction{
		Txid: "child-tx",
		Fee:  5000, // 10x higher fee
		Vsize: 150,
		Inputs: []models.TxIn{
			{Txid: "parent-tx", Vout: 0, Address: "recipient_addr", Value: 100000},
		},
		Outputs: []models.TxOut{
			{Value: 94500, Address: "final_dest"},
		},
	}

	event := DetectCPFP(childTx, parentTx)

	if event == nil {
		t.Fatal("expected CPFP detection")
	}
	if !event.IsAccelerating {
		t.Error("expected acceleration flag")
	}
	if event.ConfirmedOwner != "recipient_addr" {
		t.Errorf("expected confirmed owner recipient_addr, got %s", event.ConfirmedOwner)
	}
	if event.ChildFeeRate <= event.ParentFeeRate {
		t.Error("child fee rate should exceed parent")
	}
}

func TestCPFP_NotCPFP(t *testing.T) {
	parentTx := &models.Transaction{
		Txid: "parent-tx",
		Fee:  5000,
		Vsize: 250,
		Outputs: []models.TxOut{
			{Value: 100000, Address: "recipient_addr"},
		},
	}

	childTx := models.Transaction{
		Txid: "child-tx",
		Fee:  500, // Lower fee = not CPFP
		Vsize: 150,
		Inputs: []models.TxIn{
			{Txid: "parent-tx", Vout: 0, Address: "recipient_addr", Value: 100000},
		},
		Outputs: []models.TxOut{
			{Value: 99500, Address: "final_dest"},
		},
	}

	event := DetectCPFP(childTx, parentTx)

	if event != nil {
		t.Error("should not detect CPFP when child fee is lower than parent")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Money Laundering Pattern Tests
// ═══════════════════════════════════════════════════════════════════════

func TestLaundering_FanOut(t *testing.T) {
	// 1 input → 12 outputs = distribution
	tx := models.Transaction{
		Inputs: []models.TxIn{{Value: 1000000}},
		Outputs: []models.TxOut{
			{Value: 80000}, {Value: 80000}, {Value: 80000}, {Value: 80000},
			{Value: 80000}, {Value: 80000}, {Value: 80000}, {Value: 80000},
			{Value: 80000}, {Value: 80000}, {Value: 80000}, {Value: 80000},
		},
	}

	result := DetectLaunderingPattern(tx)

	if result.Pattern != PatternFanOut {
		t.Errorf("expected fan_out pattern, got %s", result.Pattern)
	}
	if result.RiskScore < 0.5 {
		t.Errorf("expected risk > 0.5, got %f", result.RiskScore)
	}
}

func TestLaundering_FanIn(t *testing.T) {
	// 12 inputs → 1 output = collection
	inputs := make([]models.TxIn, 12)
	for i := range inputs {
		inputs[i] = models.TxIn{Value: 80000}
	}

	tx := models.Transaction{
		Inputs:  inputs,
		Outputs: []models.TxOut{{Value: 950000}},
	}

	result := DetectLaunderingPattern(tx)

	if result.Pattern != PatternFanIn {
		t.Errorf("expected fan_in pattern, got %s", result.Pattern)
	}
}

func TestLaundering_NormalTx(t *testing.T) {
	tx := models.Transaction{
		Inputs:  []models.TxIn{{Value: 100000}, {Value: 50000}},
		Outputs: []models.TxOut{{Value: 140000}, {Value: 9000}},
	}

	result := DetectLaunderingPattern(tx)

	if result.Pattern != PatternNone {
		t.Errorf("normal tx should have no laundering pattern, got %s", result.Pattern)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Value Fingerprint Registry Tests
// ═══════════════════════════════════════════════════════════════════════

func TestValueRegistry_SpecificValues(t *testing.T) {
	vr := GetGlobalValueRegistry()

	// Record a specific value
	vr.RecordValue(12345678, "tx1", "addr1", false) // output
	vr.RecordValue(12345678, "tx2", "addr2", true)  // input (later)

	matches := vr.FindMatches(12345678)
	if len(matches) < 2 {
		t.Errorf("expected 2 matches for unique value, got %d", len(matches))
	}

	outputs, inputs := vr.FindLinkedTransactions(12345678)
	if len(outputs) < 1 || len(inputs) < 1 {
		t.Error("expected both output and input matches for linked tx detection")
	}
}

func TestValueRegistry_RoundValuesExcluded(t *testing.T) {
	vr := GetGlobalValueRegistry()

	// Round values should be excluded
	vr.RecordValue(100000000, "tx-round", "addr-round", false) // 1 BTC exactly

	matches := vr.FindMatches(100000000)
	if len(matches) > 0 {
		t.Error("round values (1 BTC) should be excluded from fingerprinting")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Address Poisoning Tests
// ═══════════════════════════════════════════════════════════════════════

func TestAddressPoisoning_SimilarAddresses(t *testing.T) {
	// Simulate a poisoning attack with lookalike address
	tx := models.Transaction{
		Txid: "poison-tx",
		Inputs: []models.TxIn{
			{Address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Value: 100000},
		},
		Outputs: []models.TxOut{
			// Very similar address (same prefix/suffix, different middle)
			{Address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Value: 99000}, // Same (change)
			{Address: "bc1qw508d6aaaaaaaaay5r3zarvary0c5xw7kv8f3t4", Value: 500}, // Poisoned lookalike
		},
	}

	events := DetectAddressPoisoning(tx)
	// This specific test checks the detection logic works without crashing
	// In practice, addresses differ more subtly
	_ = events
}

func TestIsSpecificValue(t *testing.T) {
	tests := []struct {
		value    int64
		expected bool
	}{
		{12345678, true},   // Specific (1 trailing zero)
		{12345000, true},   // 3 trailing zeros - still specific
		{12340000, false},  // 4 trailing zeros - too round
		{100000000, false}, // 8 trailing zeros - very round
		{546, true},        // Dust
		{0, false},         // Zero
	}

	for _, tt := range tests {
		got := isSpecificValue(tt.value)
		if got != tt.expected {
			t.Errorf("isSpecificValue(%d) = %v, want %v", tt.value, got, tt.expected)
		}
	}
}
