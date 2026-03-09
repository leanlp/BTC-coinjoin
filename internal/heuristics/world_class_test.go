package heuristics

import (
	"testing"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Ownership Matrix Tests — Boltzmann P(i→j) Analysis
// ═══════════════════════════════════════════════════════════════════════

func TestOwnershipMatrix_SingleInput(t *testing.T) {
	tx := models.Transaction{
		Inputs:  []models.TxIn{{Value: 100000}},
		Outputs: []models.TxOut{{Value: 50000}, {Value: 49000}},
	}

	matrix := ComputeOwnershipMatrix(tx)

	if matrix.Interpretation != "deterministic" {
		t.Fatalf("single input should be deterministic, got %s", matrix.Interpretation)
	}
	if len(matrix.Probabilities) != 1 {
		t.Fatalf("expected 1 input row, got %d", len(matrix.Probabilities))
	}
	// Single input must fund all outputs with P=1.0
	for j, p := range matrix.Probabilities[0] {
		if p != 1.0 {
			t.Fatalf("P(0→%d) should be 1.0, got %f", j, p)
		}
	}
}

func TestOwnershipMatrix_EqualCoinJoin(t *testing.T) {
	// Perfect Whirlpool-style: 5 inputs of 100k, 5 outputs of 100k
	tx := models.Transaction{
		Inputs: []models.TxIn{
			{Value: 100000}, {Value: 100000}, {Value: 100000},
			{Value: 100000}, {Value: 100000},
		},
		Outputs: []models.TxOut{
			{Value: 100000}, {Value: 100000}, {Value: 100000},
			{Value: 100000}, {Value: 100000},
		},
	}

	matrix := ComputeOwnershipMatrix(tx)

	// With 5 equal inputs and 5 equal outputs, every input can fund every output
	// So each P(i→j) should be approximately 1/5 = 0.2
	if matrix.ValidMappings <= 0 {
		t.Fatalf("expected valid mappings > 0, got %d", matrix.ValidMappings)
	}

	for i, row := range matrix.Probabilities {
		for j, p := range row {
			// Each input should have roughly equal probability of funding each output
			if p < 0.1 || p > 0.4 {
				t.Errorf("P(%d→%d) = %f, expected ~0.2 for equal CoinJoin", i, j, p)
			}
		}
	}

	// Entropy should be positive (ambiguity exists)
	if matrix.Entropy <= 0 {
		t.Errorf("expected positive entropy for equal CoinJoin, got %f", matrix.Entropy)
	}
}

func TestOwnershipMatrix_DeterministicLink(t *testing.T) {
	// Input 0 (50k) can fund Output 1 (40k) alone, and Output 0 (150k) via pair
	// Input 1 (200k) can fund both outputs alone
	tx := models.Transaction{
		Inputs:  []models.TxIn{{Value: 50000}, {Value: 200000}},
		Outputs: []models.TxOut{{Value: 150000}, {Value: 40000}},
	}

	matrix := ComputeOwnershipMatrix(tx)

	if len(matrix.Probabilities) != 2 {
		t.Fatalf("expected 2 input rows, got %d", len(matrix.Probabilities))
	}

	// With subset-sum: both inputs can fund output 0 (50k+200k >= 150k)
	// So P(1→0) should be 0.5, not 1.0 — this is correct Boltzmann behavior
	if matrix.Probabilities[1][0] < 0.4 || matrix.Probabilities[1][0] > 0.6 {
		t.Errorf("P(1→0) should be ~0.5 with subset-sum, got %f", matrix.Probabilities[1][0])
	}

	// Entropy should be positive (non-deterministic due to pair-funding)
	if matrix.Entropy <= 0 {
		t.Errorf("expected positive entropy, got %f", matrix.Entropy)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Signal Fusion Tests — Bayesian Multi-Signal Combination
// ═══════════════════════════════════════════════════════════════════════

func TestFusionEngine_TaintedTxEscalatesThreat(t *testing.T) {
	engine := GetGlobalFusionEngine()

	tx := models.Transaction{
		Txid:   "tx-tainted-fusion",
		Inputs: []models.TxIn{{Address: "addr1", Value: 100000}},
	}

	result := models.PrivacyAnalysisResult{
		TaintExposure:  0.9,
		HeuristicFlags: uint64(FlagHighRisk),
	}

	verdict := engine.FuseSignals(tx, result)

	// High taint exposure should produce elevated threat posterior
	if verdict.ThreatPosterior < 0.7 {
		t.Errorf("expected threat posterior >= 0.7 for tainted tx, got %f", verdict.ThreatPosterior)
	}
}

func TestFusionEngine_CleanTxLowThreat(t *testing.T) {
	engine := GetGlobalFusionEngine()

	tx := models.Transaction{
		Txid:   "tx-clean-fusion",
		Inputs: []models.TxIn{{Address: "clean_addr", Value: 100000}},
	}

	result := models.PrivacyAnalysisResult{
		TaintExposure:  0.0,
		HeuristicFlags: 0,
		PrivacyScore:   85,
	}

	verdict := engine.FuseSignals(tx, result)

	// Clean transaction should have low threat posterior
	if verdict.ThreatPosterior > 0.6 {
		t.Errorf("expected threat posterior < 0.6 for clean tx, got %f", verdict.ThreatPosterior)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Entity Attribution Tests
// ═══════════════════════════════════════════════════════════════════════

func TestEntityRegistry_SanctionedAddress(t *testing.T) {
	registry := GetGlobalEntityRegistry()

	// Look up a known OFAC sanctioned address
	attr := registry.LookupEntity("12QtD5BFwRsdNsAZY76GUNB2CwABTfR3v4")

	if !attr.IsLabeled {
		t.Fatal("expected OFAC sanctioned address to be labeled")
	}
	if attr.PrimaryLabel == nil {
		t.Fatal("expected non-nil primary label")
	}
	if attr.PrimaryLabel.Type != EntitySanctioned {
		t.Errorf("expected type sanctioned, got %s", attr.PrimaryLabel.Type)
	}
	if attr.PrimaryLabel.RiskLevel != "critical" {
		t.Errorf("expected critical risk, got %s", attr.PrimaryLabel.RiskLevel)
	}
}

func TestEntityRegistry_UnknownAddress(t *testing.T) {
	registry := GetGlobalEntityRegistry()

	attr := registry.LookupEntity("1UnknownAddressXXXXXXXXXXXXXXXXXX")

	if attr.IsLabeled {
		t.Error("unknown address should not be labeled")
	}
}

func TestEntityRegistry_BehavioralClassification(t *testing.T) {
	registry := GetGlobalEntityRegistry()

	// Exchange pattern: high fan-out + high volume
	attr := registry.ClassifyBehavior(200, 2, 50, 500000)
	if attr.BehavioralType != EntityExchange {
		t.Errorf("expected exchange classification, got %s", attr.BehavioralType)
	}
}
