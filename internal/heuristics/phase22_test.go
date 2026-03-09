package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// ML Feature Extraction Tests
// ═══════════════════════════════════════════════════════════════════════

func TestExtractFeatures_CoinJoin(t *testing.T) {
	tx := models.Transaction{
		Txid: "coinjoin_test",
		Inputs: []models.TxIn{
			{Txid: "a", Vout: 0, Value: 1100000, Address: "bc1qtest1"},
			{Txid: "b", Vout: 0, Value: 1100000, Address: "bc1qtest2"},
			{Txid: "c", Vout: 0, Value: 1100000, Address: "bc1qtest3"},
		},
		Outputs: []models.TxOut{
			{Value: 1000000, Address: "bc1qout1"},
			{Value: 1000000, Address: "bc1qout2"},
			{Value: 1000000, Address: "bc1qout3"},
			{Value: 200000, Address: "bc1qchange"},
		},
	}

	f := ExtractFeatures(tx)

	if f.InputCount != 3 {
		t.Errorf("InputCount = %d, want 3", f.InputCount)
	}
	if f.OutputCount != 4 {
		t.Errorf("OutputCount = %d, want 4", f.OutputCount)
	}
	if f.MaxEqualOutputs != 3 {
		t.Errorf("MaxEqualOutputs = %d, want 3", f.MaxEqualOutputs)
	}
	if f.EqualOutputRatio < 0.5 {
		t.Errorf("EqualOutputRatio = %f, want >= 0.5", f.EqualOutputRatio)
	}
	if f.CoinJoinLikelihood < 0.4 {
		t.Errorf("CoinJoinLikelihood = %f, want >= 0.4", f.CoinJoinLikelihood)
	}
}

func TestExtractFeatures_SimplePayment(t *testing.T) {
	tx := models.Transaction{
		Txid: "payment_test",
		Inputs: []models.TxIn{
			{Txid: "a", Vout: 0, Value: 5000000, Address: "1TestAddr"},
		},
		Outputs: []models.TxOut{
			{Value: 4500000, Address: "1RecipAddr"},
			{Value: 490000, Address: "1ChangeAddr"},
		},
	}

	f := ExtractFeatures(tx)

	if f.InputCount != 1 || f.OutputCount != 2 {
		t.Errorf("IO = %d/%d, want 1/2", f.InputCount, f.OutputCount)
	}
	if f.CoinJoinLikelihood > 0.3 {
		t.Errorf("CoinJoinLikelihood = %f, should be low for simple payment", f.CoinJoinLikelihood)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// ML Classifier Tests
// ═══════════════════════════════════════════════════════════════════════

func TestClassifyTransaction_CoinJoin(t *testing.T) {
	f := TxFeatureVector{
		InputCount:       5,
		OutputCount:      5,
		EqualOutputRatio: 0.8,
		MaxEqualOutputs:  4,
		MixedScriptTypes: true,
		OutputGini:       0.1,
	}

	result := ClassifyTransaction(f)
	if !result.IsCoinJoin {
		t.Error("Expected CoinJoin classification")
	}
	if result.TxType != "coinjoin" {
		t.Errorf("TxType = %s, want coinjoin", result.TxType)
	}
	if result.Confidence < 0.85 {
		t.Errorf("Confidence = %f, want >= 0.85", result.Confidence)
	}
}

func TestClassifyTransaction_Consolidation(t *testing.T) {
	f := TxFeatureVector{
		InputCount:  10,
		OutputCount: 1,
	}

	result := ClassifyTransaction(f)
	if result.TxType != "consolidation" {
		t.Errorf("TxType = %s, want consolidation", result.TxType)
	}
}

func TestClassifyTransaction_BatchPayout(t *testing.T) {
	f := TxFeatureVector{
		InputCount:       1,
		OutputCount:      10,
		RoundOutputRatio: 0.7,
	}

	result := ClassifyTransaction(f)
	if result.TxType != "batch_payout" {
		t.Errorf("TxType = %s, want batch_payout", result.TxType)
	}
}

func TestClassifyTransaction_Payment(t *testing.T) {
	f := TxFeatureVector{
		InputCount:      1,
		OutputCount:     2,
		HasLikelyChange: true,
	}

	result := ClassifyTransaction(f)
	if result.TxType != "payment" {
		t.Errorf("TxType = %s, want payment", result.TxType)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Anomaly Detector Tests
// ═══════════════════════════════════════════════════════════════════════

func TestAnomalyDetector_Basic(t *testing.T) {
	det := &AnomalyDetector{stats: make(map[string]*runningStats)}

	// Train with 200 normal transactions (with slight variance)
	for i := 0; i < 200; i++ {
		det.RecordFeatures(TxFeatureVector{
			InputCount: 2 + (i % 2), OutputCount: 2 + (i % 3), Fee: int64(1000 + i*10),
			FeeRate: 10.0 + float64(i%5), TotalOutputValue: int64(5000000 + i*1000),
			OutputGini: 0.5 + float64(i%10)*0.01, OutputEntropy: 1.0 + float64(i%5)*0.1,
			IORatio: 1.0 + float64(i%3)*0.1,
		})
	}

	// Normal tx should not be anomaly
	normal := det.DetectAnomalies(TxFeatureVector{
		InputCount: 2, OutputCount: 2, Fee: 1500, FeeRate: 12.0,
		TotalOutputValue: 5100000, OutputGini: 0.52, OutputEntropy: 1.1, IORatio: 1.1,
	})
	if normal.IsAnomaly {
		t.Error("Normal transaction should not be anomaly")
	}

	// Extreme outlier (100x normal values)
	outlier := det.DetectAnomalies(TxFeatureVector{
		InputCount: 500, OutputCount: 500, Fee: 5000000, FeeRate: 999.0,
		TotalOutputValue: 999999999999, OutputGini: 0.001, OutputEntropy: 9.0, IORatio: 50.0,
	})
	if !outlier.IsAnomaly {
		t.Error("Extreme outlier should be anomaly")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Deposit Heuristic Tests
// ═══════════════════════════════════════════════════════════════════════

func TestDepositHeuristic(t *testing.T) {
	engine := &DepositHeuristicEngine{
		addrTxCount:  make(map[string]int),
		addrForwards: make(map[string]int),
		hotWallets:   make(map[string]int),
	}

	// Simulate: deposit address received 1 tx, hot wallet received 20 txs
	engine.addrTxCount["deposit_addr"] = 1
	engine.addrTxCount["hot_wallet"] = 20

	tx := models.Transaction{
		Inputs: []models.TxIn{
			{Txid: "prev", Vout: 0, Value: 500000, Address: "deposit_addr"},
		},
		Outputs: []models.TxOut{
			{Value: 498000, Address: "hot_wallet"},
		},
	}

	patterns := engine.DetectDepositPattern(tx)
	if len(patterns) == 0 {
		t.Fatal("Expected deposit pattern detection")
	}
	if !patterns[0].IsOneTimeAddress {
		t.Error("Expected one-time address flag")
	}
	if patterns[0].Confidence < 0.8 {
		t.Errorf("Expected high confidence for hot wallet (20 inbound), got %f", patterns[0].Confidence)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Mixer Fingerprint Tests
// ═══════════════════════════════════════════════════════════════════════

func TestDetectMixerService_ChipMixer(t *testing.T) {
	tx := models.Transaction{
		Inputs: []models.TxIn{
			{Txid: "a", Vout: 0, Value: 1000000},
		},
		Outputs: []models.TxOut{
			{Value: 100000}, {Value: 200000}, {Value: 400000},
			{Value: 0, ScriptPubKey: "6a..."}, // OP_RETURN
		},
	}

	result := DetectMixerService(tx)
	if !result.IsMixer {
		t.Error("Expected mixer detection for ChipMixer pattern")
	}
	if result.Type != MixerChipMixer {
		t.Errorf("Type = %s, want chipmixer", result.Type)
	}
}

func TestDetectMixerService_NotMixer(t *testing.T) {
	tx := models.Transaction{
		Inputs: []models.TxIn{
			{Txid: "a", Vout: 0, Value: 5000000},
		},
		Outputs: []models.TxOut{
			{Value: 4500000, Address: "1Recv"},
			{Value: 490000, Address: "1Change"},
		},
	}

	result := DetectMixerService(tx)
	if result.IsMixer {
		t.Error("Simple payment should not be detected as mixer")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// SIGHASH Analysis Tests
// ═══════════════════════════════════════════════════════════════════════

func TestAnalyzeSigHash_Normal(t *testing.T) {
	tx := models.Transaction{
		Inputs: []models.TxIn{
			{ScriptSig: "304402...01"},
			{ScriptSig: "3045...01"},
		},
	}

	result := AnalyzeSigHash(tx)
	if result.HasUnusual {
		t.Error("Normal SIGHASH_ALL inputs should not be unusual")
	}
}

func TestAnalyzeSigHash_AnyoneCanPay(t *testing.T) {
	tx := models.Transaction{
		Inputs: []models.TxIn{
			{ScriptSig: "304402...81"}, // SIGHASH_ALL|ANYONECANPAY
			{ScriptSig: "3045...01"},   // Normal
		},
	}

	result := AnalyzeSigHash(tx)
	if !result.HasUnusual {
		t.Error("ANYONECANPAY should be flagged as unusual")
	}
	if result.UnusualInputs != 1 {
		t.Errorf("UnusualInputs = %d, want 1", result.UnusualInputs)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Darknet Pattern Tests
// ═══════════════════════════════════════════════════════════════════════

func TestDetectDarknetPatterns_WithdrawalFee(t *testing.T) {
	tx := models.Transaction{
		Outputs: []models.TxOut{
			{Value: 50000},   // Known market fee
			{Value: 5000000}, // Withdrawal amount
		},
	}

	patterns := DetectDarknetPatterns(tx)
	found := false
	for _, p := range patterns {
		if p.PatternType == "withdrawal_fee" {
			found = true
		}
	}
	if !found {
		t.Error("Expected withdrawal_fee pattern detection")
	}
}

func TestDetectDarknetPatterns_Clean(t *testing.T) {
	tx := models.Transaction{
		Outputs: []models.TxOut{
			{Value: 4567890},
			{Value: 1234567},
		},
	}

	patterns := DetectDarknetPatterns(tx)
	if len(patterns) > 0 {
		t.Error("Clean transaction should not trigger darknet patterns")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Risk Engine Tests
// ═══════════════════════════════════════════════════════════════════════

func TestRiskEngine_HighValueTx(t *testing.T) {
	re := &RiskEngine{indicators: defaultIndicators()}

	tx := models.Transaction{
		Outputs: []models.TxOut{
			{Value: 200000000}, // 2 BTC
		},
	}
	result := models.PrivacyAnalysisResult{PrivacyScore: 50}

	profile := re.EvaluateRisk(tx, &result)
	if profile.RiskLevel == "low" {
		t.Error("2 BTC tx should not be low risk")
	}
	if len(profile.TriggeredRules) == 0 {
		t.Error("Expected at least high_value rule to trigger")
	}
}

func TestRiskEngine_DustAttack(t *testing.T) {
	re := &RiskEngine{indicators: defaultIndicators()}

	tx := models.Transaction{
		Outputs: []models.TxOut{
			{Value: 500},     // Dust
			{Value: 5000000}, // Normal
		},
	}
	result := models.PrivacyAnalysisResult{PrivacyScore: 80}

	profile := re.EvaluateRisk(tx, &result)
	dustTriggered := false
	for _, rule := range profile.TriggeredRules {
		if rule.IndicatorID == "dust_attack" {
			dustTriggered = true
		}
	}
	if !dustTriggered {
		t.Error("Expected dust_attack rule to trigger")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Alert Engine Tests
// ═══════════════════════════════════════════════════════════════════════

func TestAlertEngine_HighRisk(t *testing.T) {
	ae := GetGlobalRiskAlertEngine()

	tx := models.Transaction{Txid: "test_alert_tx"}
	profile := RiskProfile{
		OverallScore: 85,
		RiskLevel:    "critical",
		Categories:   map[RiskCategory]float64{RiskMixer: 0.7},
	}

	alerts := ae.ProcessTransaction(tx, profile)
	if len(alerts) == 0 {
		t.Error("Expected alerts for critical risk profile")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Compliance Engine Tests
// ═══════════════════════════════════════════════════════════════════════

func TestSARGenerator(t *testing.T) {
	sg := &SARGenerator{btcPrice: 85000}

	tx := models.Transaction{
		Txid: "sar_test",
		Inputs: []models.TxIn{
			{Txid: "a", Value: 100000000, Address: "1InputAddr"},
		},
		Outputs: []models.TxOut{
			{Value: 99900000, Address: "1OutputAddr"},
		},
	}
	result := models.PrivacyAnalysisResult{PrivacyScore: 20}
	profile := RiskProfile{
		OverallScore:   80,
		RiskLevel:      "critical",
		TriggeredRules: []TriggeredRule{{Name: "test", Details: "test"}},
		Categories:     map[RiskCategory]float64{RiskMixer: 0.7},
	}

	report := sg.GenerateSAR(tx, &result, profile)
	if report == nil {
		t.Fatal("Expected SAR report for critical-risk tx")
	}
	if report.Status != "draft" {
		t.Errorf("Status = %s, want draft", report.Status)
	}
	if report.TotalAmountUSD < 80000 {
		t.Errorf("Expected USD value > 80000, got %f", report.TotalAmountUSD)
	}
}

func TestSARGenerator_LowRisk(t *testing.T) {
	sg := &SARGenerator{btcPrice: 85000}

	tx := models.Transaction{Txid: "clean_tx"}
	result := models.PrivacyAnalysisResult{PrivacyScore: 80}
	profile := RiskProfile{OverallScore: 10, RiskLevel: "low"}

	report := sg.GenerateSAR(tx, &result, profile)
	if report != nil {
		t.Error("Should not generate SAR for low-risk tx")
	}
}

func TestJurisdictionRisk(t *testing.T) {
	je := &JurisdictionEngine{countries: loadFATFData()}

	// North Korea = blacklist
	nk := je.GetRisk("KP")
	if nk == nil {
		t.Fatal("North Korea should be in database")
	}
	if nk.FATFStatus != "black_list" {
		t.Errorf("NK status = %s, want black_list", nk.FATFStatus)
	}
	if nk.RiskScore < 90 {
		t.Errorf("NK risk = %f, want >= 90", nk.RiskScore)
	}

	// Nigeria = grey list
	ng := je.GetRisk("NG")
	if ng == nil {
		t.Fatal("Nigeria should be in database")
	}
	if ng.FATFStatus != "grey_list" {
		t.Errorf("NG status = %s, want grey_list", ng.FATFStatus)
	}

	// USA = not in high-risk
	us := je.GetRisk("US")
	if us != nil {
		t.Error("USA should not be in high-risk database")
	}

	if !je.IsHighRisk("KP") {
		t.Error("North Korea should be high risk")
	}
	if je.IsHighRisk("US") {
		t.Error("USA should not be high risk")
	}
}

func TestTravelRule(t *testing.T) {
	tx := models.Transaction{
		Outputs: []models.TxOut{
			{Value: 50000000}, // 0.5 BTC
		},
	}

	// At $85k BTC, 0.5 BTC = $42,500 → above $1,000 threshold
	check := CheckTravelRule(tx, 85000.0)
	if !check.RequiresCompliance {
		t.Error("0.5 BTC at $85k should require travel rule compliance")
	}

	// Very small tx
	smallTx := models.Transaction{
		Outputs: []models.TxOut{
			{Value: 1000}, // 0.00001 BTC
		},
	}
	smallCheck := CheckTravelRule(smallTx, 85000.0)
	if smallCheck.RequiresCompliance {
		t.Error("Small tx should not require travel rule compliance")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Graph Traversal Tests
// ═══════════════════════════════════════════════════════════════════════

func TestUTXOIndex_BacktrackUTXO(t *testing.T) {
	idx := NewUTXOIndex()

	// Build a chain: tx1 → tx2 → tx3
	tx1 := models.Transaction{
		Txid:    "tx1",
		Inputs:  []models.TxIn{{Txid: "", Value: 5000000000}}, // Coinbase
		Outputs: []models.TxOut{{Value: 5000000000, Address: "addr1"}},
	}
	tx2 := models.Transaction{
		Txid:    "tx2",
		Inputs:  []models.TxIn{{Txid: "tx1", Vout: 0, Value: 5000000000, Address: "addr1"}},
		Outputs: []models.TxOut{{Value: 4999990000, Address: "addr2"}},
	}
	tx3 := models.Transaction{
		Txid:    "tx3",
		Inputs:  []models.TxIn{{Txid: "tx2", Vout: 0, Value: 4999990000, Address: "addr2"}},
		Outputs: []models.TxOut{{Value: 4999980000, Address: "addr3"}},
	}

	idx.IndexTransaction(tx1)
	idx.IndexTransaction(tx2)
	idx.IndexTransaction(tx3)

	graph, err := BacktrackUTXO("tx3", idx.LookupTx, DefaultBacktrackConfig())
	if err != nil {
		t.Fatalf("BacktrackUTXO error: %v", err)
	}
	if len(graph.Nodes) < 2 {
		t.Errorf("Expected at least 2 nodes, got %d", len(graph.Nodes))
	}
}

func TestCrossChainMatcher(t *testing.T) {
	matcher := NewCrossChainMatcher()

	// Add an Ethereum tx
	matcher.AddExternalEvent("eth_tx_123", "ethereum", 5000000, 1000)

	tx := models.Transaction{
		Txid: "btc_tx_456",
		Outputs: []models.TxOut{
			{Value: 5000000, Address: "bc1qtest"},
		},
	}

	matches := matcher.FindMatches(tx, 1000) // Same timestamp
	if len(matches) == 0 {
		t.Error("Expected cross-chain match for identical value+time")
	}
	if matches[0].Score < 0.9 {
		t.Errorf("Expected high score for exact match, got %f", matches[0].Score)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Entity Behavior Tracker Tests
// ═══════════════════════════════════════════════════════════════════════

func TestEntityTracker(t *testing.T) {
	et := &EntityTracker{profiles: make(map[string]*entityAccumulator)}

	// Record 10 txs for entity
	for i := 0; i < 10; i++ {
		et.RecordBehavior("entity_1", TxFeatureVector{
			InputCount:       2,
			OutputCount:      2,
			FeeRate:          15.0,
			TotalOutputValue: 5000000,
			HasSegWit:        true,
			IsBIP69:          true,
			Version:          2,
		})
	}

	behavior := et.GetBehavior("entity_1")
	if behavior == nil {
		t.Fatal("Expected behavior profile")
	}
	if behavior.TxCount != 10 {
		t.Errorf("TxCount = %d, want 10", behavior.TxCount)
	}
	if !behavior.UsesSegWit {
		t.Error("Expected UsesSegWit = true")
	}
	if !behavior.UsesRBF {
		t.Error("Expected UsesRBF = true (version 2)")
	}
	if !behavior.UsesBIP69 {
		t.Error("Expected UsesBIP69 = true")
	}

	// Unknown entity
	unknown := et.GetBehavior("nonexistent")
	if unknown != nil {
		t.Error("Expected nil for unknown entity")
	}
}
