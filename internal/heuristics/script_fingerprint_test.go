package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

func TestAnalyzeScriptFingerprint_NativeSegwit(t *testing.T) {
	tx := models.Transaction{
		Txid:     "test_segwit",
		LockTime: 850000, // Anti-fee-sniping
		Inputs: []models.TxIn{
			{Address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Sequence: 0xFFFFFFFD}, // RBF
			{Address: "bc1qrp33g0q5b5698ahp5jnf0y36ziyr0lg7g8ck4n", Sequence: 0xFFFFFFFD},
		},
		Outputs: []models.TxOut{
			{Value: 50000000, Address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
			{Value: 49000000, Address: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"},
		},
	}

	result := AnalyzeScriptFingerprint(tx)

	if result.InputScriptTypes["p2wpkh"] != 2 {
		t.Errorf("Expected 2 p2wpkh inputs, got %d", result.InputScriptTypes["p2wpkh"])
	}

	if result.NSequenceAnalysis != "rbf-enabled" {
		t.Errorf("Expected 'rbf-enabled', got '%s'", result.NSequenceAnalysis)
	}

	if result.SignatureScheme != "ecdsa" {
		t.Errorf("Expected 'ecdsa', got '%s'", result.SignatureScheme)
	}

	// Bitcoin Core inference: native segwit + RBF + anti-fee-sniping locktime
	if result.WalletSignature != "bitcoin-core" {
		t.Errorf("Expected 'bitcoin-core' wallet, got '%s'", result.WalletSignature)
	}

	if !result.HasTimeLock {
		t.Error("Expected timelock detection from nLockTime")
	}
}

func TestAnalyzeScriptFingerprint_Taproot(t *testing.T) {
	tx := models.Transaction{
		Txid: "test_taproot",
		Inputs: []models.TxIn{
			{Address: "bc1p5cyxnuxmeuwuvkwfem96lqzszee2457nljy53k", Sequence: 0xFFFFFFFD},
		},
		Outputs: []models.TxOut{
			{Value: 10000000, Address: "bc1p5cyxnuxmeuwuvkwfem96lqzszee2457nljy53k"},
		},
	}

	result := AnalyzeScriptFingerprint(tx)

	if result.InputScriptTypes["p2tr"] != 1 {
		t.Errorf("Expected 1 p2tr input, got %d", result.InputScriptTypes["p2tr"])
	}

	if result.SignatureScheme != "schnorr" {
		t.Errorf("Expected 'schnorr', got '%s'", result.SignatureScheme)
	}

	hasV1 := false
	for _, v := range result.WitnessVersions {
		if v == 1 {
			hasV1 = true
		}
	}
	if !hasV1 {
		t.Error("Expected witness version 1 for Taproot")
	}
}

func TestAnalyzeScriptFingerprint_OPReturn(t *testing.T) {
	tx := models.Transaction{
		Txid: "test_opreturn",
		Inputs: []models.TxIn{
			{Address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Sequence: 0xFFFFFFFF},
		},
		Outputs: []models.TxOut{
			{Value: 0, Address: "", ScriptPubKey: "6a0b68656c6c6f20776f726c64"}, // OP_RETURN "hello world"
			{Value: 50000000, Address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		},
	}

	result := AnalyzeScriptFingerprint(tx)

	if len(result.OPReturnPayloads) == 0 {
		t.Error("Expected OP_RETURN payload to be detected")
	}

	if result.NSequenceAnalysis != "final" {
		t.Errorf("Expected 'final' nSequence, got '%s'", result.NSequenceAnalysis)
	}
}
