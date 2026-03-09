package heuristics

import (
	"testing"
	"time"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Dust Tracer Tests
// ═══════════════════════════════════════════════════════════════════════

func TestDustTracer_FullLifecycle(t *testing.T) {
	tracer := GetGlobalDustTracer()

	// Phase 1: Attacker deploys dust
	attackTx := models.Transaction{
		Txid: "dust-attack-tx",
		Outputs: []models.TxOut{
			{Value: 546, Address: "victim_addr"},      // Dust to victim
			{Value: 99000, Address: "attacker_change"}, // Attacker's change
		},
	}

	deployed := tracer.Phase1_DetectDustDeployment(attackTx)

	if len(deployed) != 1 {
		t.Fatalf("expected 1 dust deployment, got %d", len(deployed))
	}
	if deployed[0].TargetAddress != "victim_addr" {
		t.Errorf("expected target victim_addr, got %s", deployed[0].TargetAddress)
	}
	if deployed[0].Phase != DustPhaseDeployed {
		t.Errorf("expected phase deployed, got %s", deployed[0].Phase)
	}

	// Phase 2: Victim consolidates (spends dust with other UTXOs)
	consolidateTx := models.Transaction{
		Txid: "consolidate-tx",
		Inputs: []models.TxIn{
			{Address: "victim_addr", Value: 546},       // The dust
			{Address: "victim_addr2", Value: 50000},    // Another UTXO
			{Address: "victim_addr3", Value: 30000},    // Another UTXO
		},
		Outputs: []models.TxOut{
			{Value: 79000, Address: "recipient"},
		},
	}

	consolidated := tracer.Phase2_DetectConsolidation(consolidateTx)

	if len(consolidated) < 1 {
		t.Fatal("expected consolidation to be detected")
	}
	if consolidated[0].Phase != DustPhaseExposed {
		t.Errorf("expected phase exposed, got %s", consolidated[0].Phase)
	}
	if consolidated[0].ExposureCount < 3 {
		t.Errorf("expected 3+ exposed addresses, got %d", consolidated[0].ExposureCount)
	}
}

func TestDustTracer_NoDust(t *testing.T) {
	tracer := GetGlobalDustTracer()

	normalTx := models.Transaction{
		Txid: "normal-no-dust",
		Outputs: []models.TxOut{
			{Value: 50000, Address: "addr1"},
			{Value: 49000, Address: "addr2"},
		},
	}

	deployed := tracer.Phase1_DetectDustDeployment(normalTx)
	if len(deployed) != 0 {
		t.Error("should not detect dust in normal transaction")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Peeling Chain Tests
// ═══════════════════════════════════════════════════════════════════════

func TestPeelingChain_SimpleChain(t *testing.T) {
	hopData := []PeelHopData{
		{
			TxID: "peel1", InputValue: 1000000,
			OutputValues: []int64{950000, 40000},
			OutputAddresses: []string{"change1", "peel_recipient1"},
			Fee: 10000,
		},
		{
			TxID: "peel2", InputValue: 950000,
			OutputValues: []int64{900000, 40000},
			OutputAddresses: []string{"change2", "peel_recipient2"},
			Fee: 10000,
		},
		{
			TxID: "peel3", InputValue: 900000,
			OutputValues: []int64{850000, 40000},
			OutputAddresses: []string{"change3", "peel_recipient3"},
			Fee: 10000,
		},
	}

	result := AnalyzePeelingChain("theft_addr", hopData)

	if result.TotalHops != 3 {
		t.Errorf("expected 3 hops, got %d", result.TotalHops)
	}
	if result.TotalPeeled < 100000 {
		t.Errorf("expected total peeled >= 100k sats, got %d", result.TotalPeeled)
	}
	if result.Confidence < 0.80 {
		t.Errorf("expected confidence > 0.80, got %f", result.Confidence)
	}
	if len(result.PeelAddresses) != 3 {
		t.Errorf("expected 3 peel addresses, got %d", len(result.PeelAddresses))
	}
}

func TestIsPeelingPattern_Valid(t *testing.T) {
	isPeel, peelIdx, changeIdx := IsPeelingPattern(100000, []int64{90000, 9000})

	if !isPeel {
		t.Error("expected valid peeling pattern")
	}
	if changeIdx != 0 {
		t.Errorf("expected change at index 0, got %d", changeIdx)
	}
	if peelIdx != 1 {
		t.Errorf("expected peel at index 1, got %d", peelIdx)
	}
}

func TestIsPeelingPattern_EqualSplit(t *testing.T) {
	isPeel, _, _ := IsPeelingPattern(100000, []int64{50000, 49000})

	if isPeel {
		t.Error("equal split should NOT be a peeling pattern")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Timezone Profiling Tests
// ═══════════════════════════════════════════════════════════════════════

func TestTimezoneProfile_UTC8(t *testing.T) {
	// Simulate a user active 9AM-11PM in UTC+8 (= 1AM-3PM UTC)
	var timestamps []time.Time
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	for day := 0; day < 30; day++ {
		// Active hours in UTC: 1-15 (= 9AM-11PM in UTC+8)
		for hour := 1; hour <= 15; hour++ {
			ts := base.Add(time.Duration(day*24+hour) * time.Hour)
			timestamps = append(timestamps, ts)
		}
	}

	profile := ProfileTimezone(timestamps)

	if profile.TxCount != 450 {
		t.Errorf("expected 450 txs, got %d", profile.TxCount)
	}

	// Quiet window should be roughly 16-0 UTC (sleep time for UTC+8)
	if profile.QuietWindowLen < 4 {
		t.Errorf("expected quiet window >= 4 hours, got %d", profile.QuietWindowLen)
	}
	if profile.Confidence < 0.5 {
		t.Errorf("expected confidence >= 0.5, got %f", profile.Confidence)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// RBF Forensics Tests
// ═══════════════════════════════════════════════════════════════════════

func TestRBFEvent_DoubleSpend(t *testing.T) {
	original := RBFTxData{
		TxID: "orig-tx", Fee: 500, Timestamp: 1000,
		Outputs: []RBFOutput{
			{Address: "merchant", Value: 100000},
			{Address: "change", Value: 49500},
		},
	}

	replacement := RBFTxData{
		TxID: "replace-tx", Fee: 2500, Timestamp: 1030,
		Outputs: []RBFOutput{
			{Address: "attacker_self", Value: 147000}, // Recipient changed!
		},
	}

	event := AnalyzeRBFEvent(original, replacement)

	if !event.IsDoubleSpend {
		t.Error("expected double-spend detection")
	}
	if !event.RecipientChanged {
		t.Error("expected recipient changed flag")
	}
	if event.UrgencyScore < 0.5 {
		t.Errorf("expected high urgency (30s + 5x fee), got %f", event.UrgencyScore)
	}
}

func TestRBFEvent_NormalBump(t *testing.T) {
	original := RBFTxData{
		TxID: "orig-tx", Fee: 500, Timestamp: 1000,
		Outputs: []RBFOutput{
			{Address: "merchant", Value: 100000},
			{Address: "change", Value: 49500},
		},
	}

	replacement := RBFTxData{
		TxID: "replace-tx", Fee: 1000, Timestamp: 5000,
		Outputs: []RBFOutput{
			{Address: "merchant", Value: 100000},
			{Address: "change", Value: 49000},
		},
	}

	event := AnalyzeRBFEvent(original, replacement)

	if event.IsDoubleSpend {
		t.Error("normal fee bump should NOT be flagged as double-spend")
	}
	if event.FeeMultiplier < 1.9 || event.FeeMultiplier > 2.1 {
		t.Errorf("expected 2x fee multiplier, got %f", event.FeeMultiplier)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Address Migration Tests
// ═══════════════════════════════════════════════════════════════════════

func TestAddressTypeMigration(t *testing.T) {
	addrs := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  // P2PKH
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",   // P2SH
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // P2WPKH
		"bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9", // P2TR
	}

	result := AnalyzeAddressMigration(addrs)

	if !result.HasMigrated {
		t.Error("expected migration detected with 4 different address types")
	}
	if len(result.TypeDistribution) < 3 {
		t.Errorf("expected 3+ address types, got %d", len(result.TypeDistribution))
	}
}
