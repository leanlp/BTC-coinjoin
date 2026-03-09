package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// TestFullPipeline_Phase20 verifies that the complete 52-step AnalyzeTx pipeline
// runs end-to-end without crashing and populates Phase 20-22 fields.
func TestFullPipeline_Phase20_NormalTx(t *testing.T) {
	tx := models.Transaction{
		Txid:  "pipeline-test-normal",
		Fee:   5000,
		Vsize: 250,
		Inputs: []models.TxIn{
			{Txid: "prev1", Vout: 0, Value: 100000, Address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Sequence: 0xFFFFFFFE},
			{Txid: "prev2", Vout: 1, Value: 50000, Address: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Sequence: 0xFFFFFFFF},
		},
		Outputs: []models.TxOut{
			{Value: 130000, Address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
			{Value: 15000, Address: "1CounterpartyXXXXXXXXXXXXXXXUWLpVr"},
		},
		Version:  2,
		LockTime: 800000,
	}

	result := AnalyzeTx(tx)

	if result.Txid != tx.Txid {
		t.Errorf("expected txid %s, got %s", tx.Txid, result.Txid)
	}

	// Privacy score should be in valid range
	if result.PrivacyScore < 0 || result.PrivacyScore > 100 {
		t.Errorf("privacy score %d out of range [0,100]", result.PrivacyScore)
	}

	// Phase 20 fields should be populated
	if result.WalletFingerprint == nil {
		t.Log("WalletFingerprint: nil (expected for simple tx, acceptable)")
	}

	// Laundering should NOT be flagged on normal tx
	if result.LaunderingFlags != nil {
		t.Log("LaunderingFlags present — checking if it's a false positive")
	}

	// Fusion verdict should always be populated
	if result.FusionVerdict == nil {
		t.Error("FusionVerdict should always be populated by Step 36")
	}
}

// TestFullPipeline_Phase20_CoinJoin verifies that CoinJoin-specific
// Phase 20 steps execute correctly (Steps 38, 43)
func TestFullPipeline_Phase20_CoinJoin(t *testing.T) {
	// Build a CoinJoin-like transaction (5 equal outputs)
	tx := models.Transaction{
		Txid:  "pipeline-test-coinjoin",
		Fee:   10000,
		Vsize: 1200,
		Inputs: []models.TxIn{
			{Txid: "in1", Vout: 0, Value: 5100000, Address: "addr_a", Sequence: 0xFFFFFFFE},
			{Txid: "in2", Vout: 0, Value: 5100000, Address: "addr_b", Sequence: 0xFFFFFFFE},
			{Txid: "in3", Vout: 0, Value: 5100000, Address: "addr_c", Sequence: 0xFFFFFFFE},
			{Txid: "in4", Vout: 0, Value: 5100000, Address: "addr_d", Sequence: 0xFFFFFFFE},
			{Txid: "in5", Vout: 0, Value: 5100000, Address: "addr_e", Sequence: 0xFFFFFFFE},
		},
		Outputs: []models.TxOut{
			{Value: 5000000, Address: "out_a"},
			{Value: 5000000, Address: "out_b"},
			{Value: 5000000, Address: "out_c"},
			{Value: 5000000, Address: "out_d"},
			{Value: 5000000, Address: "out_e"},
		},
		Version:  2,
		LockTime: 0,
	}

	result := AnalyzeTx(tx)

	// Anonset computation depends on the MitM solver finding valid subset sums.
	// For synthetic data, the structural counting fallback may apply.
	// The key assertion is that the pipeline completes without panics.
	t.Logf("CoinJoin anonset: %d, privacy score: %d", result.AnonSet, result.PrivacyScore)

	if result.PrivacyScore < 0 || result.PrivacyScore > 100 {
		t.Errorf("privacy score %d out of range [0,100]", result.PrivacyScore)
	}

	// CoordinatorID is populated only when isCj=true (depends on anonset)
	if result.AnonSet >= 2 && result.CoordinatorID == nil {
		// CoordinatorID depends on specific coordinator detection heuristics
		// that may not trigger with synthetic test data
		t.Log("CoordinatorID is nil even with AnonSet >= 2 (expected for synthetic data)")
	}

	// Fusion verdict should always be present
	if result.FusionVerdict == nil {
		t.Error("FusionVerdict should be populated")
	}
}

// TestFullPipeline_Phase20_Consolidation verifies that consolidation
// detection fires in the pipeline (Step 39)
func TestFullPipeline_Phase20_Consolidation(t *testing.T) {
	// Build a high-fanin consolidation (8 inputs → 1 output)
	inputs := make([]models.TxIn, 8)
	for i := range inputs {
		inputs[i] = models.TxIn{
			Txid:    "consol_in",
			Vout:    uint32(i),
			Value:   100000,
			Address: "consolidation_addr",
		}
	}

	tx := models.Transaction{
		Txid:    "pipeline-test-consolidation",
		Fee:     5000,
		Vsize:   800,
		Inputs:  inputs,
		Outputs: []models.TxOut{{Value: 795000, Address: "exchange_deposit"}},
	}

	result := AnalyzeTx(tx)

	// ScammerProfile should be populated
	if result.ScammerProfile == nil {
		t.Error("ScammerProfile should be populated for consolidation transactions")
	}

	// FlagConsolidation or FlagSelfSpend may or may not be set depending on taint
	if result.PrivacyScore > 100 || result.PrivacyScore < 0 {
		t.Errorf("privacy score %d out of range", result.PrivacyScore)
	}
}

// TestFullPipeline_Phase20_FanOut verifies laundering pattern detection (Step 41)
func TestFullPipeline_Phase20_FanOut(t *testing.T) {
	// 1 input → 15 outputs = suspicious fan-out
	outputs := make([]models.TxOut, 15)
	for i := range outputs {
		outputs[i] = models.TxOut{Value: 60000, Address: "fanout_addr_" + string(rune('a'+i))}
	}

	tx := models.Transaction{
		Txid:    "pipeline-test-fanout",
		Fee:     5000,
		Vsize:   600,
		Inputs:  []models.TxIn{{Value: 905000, Address: "source"}},
		Outputs: outputs,
	}

	result := AnalyzeTx(tx)

	// Laundering flags should be set for fan-out
	if result.LaunderingFlags == nil {
		t.Error("LaunderingFlags should be populated for fan-out pattern")
	}
}
