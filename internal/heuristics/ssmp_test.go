package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

func TestCalculateAnonSet_MitM(t *testing.T) {
	// Scenario 1: A classic 3-person mix with a minor fee discrepancy
	// User A: 1.5 BTC  -> 1.0 BTC (Anon) + 0.499 BTC (Change) + 0.001 (Fee)
	// User B: 2.0 BTC  -> 1.0 BTC (Anon) + 0.999 BTC (Change) + 0.001 (Fee)
	// User C: 1.2 BTC  -> 1.0 BTC (Anon) + 0.199 BTC (Change) + 0.001 (Fee)
	
	inputs := []models.TxIn{
		{Value: 150000000, Address: "A"}, // 1.5 BTC
		{Value: 200000000, Address: "B"}, // 2.0 BTC
		{Value: 120000000, Address: "C"}, // 1.2 BTC
	}

	outputs := []models.TxOut{
		{Value: 100000000}, // 1.0
		{Value: 100000000}, // 1.0
		{Value: 100000000}, // 1.0
		{Value: 49970000},  // A Change (1.5 - 1.0 - 0.0003 fee)
		{Value: 99970000},  // B Change (2.0 - 1.0 - 0.0003 fee)
		{Value: 19970000},  // C Change (1.2 - 1.0 - 0.0003 fee)
	}

	// Total Input:  470,000,000
	// Total Output: 469,700,000
	// Fee:              300,000
	txFee := int64(90000)
	txVsize := 450 // higher feerate to match the 30k tau

	anonSet := CalculateAnonSet(inputs, outputs, txFee, txVsize)

	// Since there are 3 distinct equivalent outputs mapped safely to 3 inputs within the fee tolerance
	// The solver should identify the Anonymity Set as 3
	if anonSet != 3 {
		t.Errorf("Expected MitM AnonSet to be 3 for a perfectly balanced 3-person mix. Got: %d", anonSet)
	}
}

func TestCalculateAnonSet_MassiveBailout(t *testing.T) {
	// Scenario: A massive 50x50 transaction should trigger the processor safety lockout
	// and fallback to structural counting rather than combinatorial MitM.
	inputs := make([]models.TxIn, 50)
	outputs := make([]models.TxOut, 50)
	
	// Create a structural pattern (50 identical outputs)
	for i := 0; i < 50; i++ {
		inputs[i] = models.TxIn{Value: 1050000}
		outputs[i] = models.TxOut{Value: 1000000}
	}

	anonSet := CalculateAnonSet(inputs, outputs, 50000*50, 10000)

	// Structural counter should see 50 identically sized outputs.
	if anonSet != 50 {
		t.Errorf("Expected bailout structural AnonSet to be 50. Got: %d", anonSet)
	}
}
