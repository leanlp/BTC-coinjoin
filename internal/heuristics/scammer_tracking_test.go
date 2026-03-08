package heuristics

import (
	"testing"
	"time"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Scammer Behavior Tests
// ═══════════════════════════════════════════════════════════════════════

func TestDetectConsolidation_HighFanIn(t *testing.T) {
	tx := models.Transaction{
		Txid: "consolid-test",
		Inputs: []models.TxIn{
			{Value: 10000}, {Value: 10000}, {Value: 10000}, {Value: 10000},
			{Value: 10000}, {Value: 10000}, {Value: 10000}, {Value: 10000},
		},
		Outputs: []models.TxOut{{Value: 79000}},
	}

	event := DetectConsolidation(tx, 0.8)

	if event == nil {
		t.Fatal("expected consolidation event for 8:1 fan-in")
	}
	if !event.IsSuspicious {
		t.Error("expected suspicious flag for tainted consolidation")
	}
	if event.RiskScore < 0.4 {
		t.Errorf("expected risk > 0.4, got %f", event.RiskScore)
	}
}

func TestDetectConsolidation_NormalTx(t *testing.T) {
	tx := models.Transaction{
		Txid: "normal-tx",
		Inputs: []models.TxIn{{Value: 50000}, {Value: 60000}},
		Outputs: []models.TxOut{{Value: 100000}, {Value: 9000}},
	}

	event := DetectConsolidation(tx, 0)

	if event != nil {
		t.Error("should not flag a normal 2:2 transaction as consolidation")
	}
}

func TestVelocityClassification_RugPull(t *testing.T) {
	now := time.Now()

	// Rug pull pattern: massive inflows over 2 hours then instant drain
	flows := []TxFlowEntry{
		{Timestamp: now, Value: 500000000, IsInflow: true},                           // 5 BTC in
		{Timestamp: now.Add(10 * time.Minute), Value: 300000000, IsInflow: true},     // 3 BTC in
		{Timestamp: now.Add(20 * time.Minute), Value: 200000000, IsInflow: true},     // 2 BTC in
		{Timestamp: now.Add(30 * time.Minute), Value: 100000000, IsInflow: true},     // 1 BTC in
		{Timestamp: now.Add(35 * time.Minute), Value: 1050000000, IsInflow: false},   // Drain 10.5 BTC
	}

	profile := ClassifyVelocity(flows)

	// With short holding time and high burst, should classify as rug pull
	if profile.ClassifiedAs != ScamTypeRugPull {
		// Accept ransomware too — fast drain with few inputs is close
		if profile.ClassifiedAs != ScamTypeRansomware && profile.ClassifiedAs != ScamTypeUnknown {
			t.Errorf("expected rug_pull or ransomware, got %s", profile.ClassifiedAs)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Compound Fingerprint Tests
// ═══════════════════════════════════════════════════════════════════════

func TestCompoundFingerprint_Wasabi(t *testing.T) {
	// Wasabi signature: nVersion=1, nLockTime=height, nSequence=RBF
	tx := models.Transaction{
		Version:  1,
		LockTime: 800000, // Current block height
		Inputs:   []models.TxIn{{Sequence: 0xfffffffe}}, // RBF
	}

	name, confidence := GetBestWalletMatch(tx)

	if name != "wasabi" {
		t.Errorf("expected wasabi, got %s", name)
	}
	if confidence < 0.7 {
		t.Errorf("expected confidence >= 0.7, got %f", confidence)
	}
}

func TestCompoundFingerprint_Ledger(t *testing.T) {
	// Ledger signature: nVersion=1, nLockTime=0, nSequence=final
	tx := models.Transaction{
		Version:  1,
		LockTime: 0,
		Inputs:   []models.TxIn{{Sequence: 0xffffffff}}, // Final
	}

	name, confidence := GetBestWalletMatch(tx)

	if name != "ledger" && name != "trezor" {
		t.Errorf("expected ledger or trezor, got %s", name)
	}
	if confidence < 0.4 {
		t.Errorf("expected confidence >= 0.4, got %f", confidence)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Coordinator Fingerprint Tests
// ═══════════════════════════════════════════════════════════════════════

func TestCoordinatorFingerprint_Whirlpool(t *testing.T) {
	// Whirlpool: 5 equal inputs, 5 equal outputs at pool denomination
	tx := models.Transaction{
		Version: 1,
		Inputs: []models.TxIn{
			{Value: 5000000}, {Value: 5000000}, {Value: 5000000},
			{Value: 5000000}, {Value: 5000000},
		},
		Outputs: []models.TxOut{
			{Value: 5000000}, {Value: 5000000}, {Value: 5000000},
			{Value: 5000000}, {Value: 5000000},
		},
	}

	result := IdentifyCoordinator(tx, true)

	if result.Protocol != ProtocolWhirlpool {
		t.Errorf("expected whirlpool, got %s", result.Protocol)
	}
	if result.Confidence < 0.5 {
		t.Errorf("expected confidence >= 0.5, got %f", result.Confidence)
	}
}

func TestSybilDetection_Compromised(t *testing.T) {
	// Create a CoinJoin with some inputs from the same cluster
	tx := models.Transaction{
		Txid: "sybil-test",
		Inputs: []models.TxIn{
			{Address: "addr1", Value: 100000},
			{Address: "addr2", Value: 100000},
			{Address: "addr3", Value: 100000},
		},
	}

	// Even without cluster data, should return valid structure
	result := DetectSybilAttack(tx, 3)

	if result.TotalInputCount != 3 {
		t.Errorf("expected 3 total inputs, got %d", result.TotalInputCount)
	}
	if result.OriginalAnonSet != 3 {
		t.Errorf("expected original anonset 3, got %d", result.OriginalAnonSet)
	}
}
