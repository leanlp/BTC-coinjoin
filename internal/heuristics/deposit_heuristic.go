package heuristics

import (
	"math"
	"sync"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Deposit Address Heuristic
// ═══════════════════════════════════════════════════════════════════════
//
// Exchanges use a 2-tier address model:
//   Tier 1: Per-user deposit addresses (unique, one-time)
//   Tier 2: Hot wallet consolidation addresses (few, reused)
//
// The heuristic: if an address receives exactly 1 incoming tx
// and immediately forwards ALL funds to a known consolidation
// address pattern → it's a deposit address.
//
// This links the depositor's identity to the exchange's KYC records.

// DepositPattern describes a detected exchange deposit flow
type DepositPattern struct {
	DepositAddress      string  `json:"depositAddress"`
	ConsolidationTarget string  `json:"consolidationTarget"`
	Value               int64   `json:"value"`
	IsOneTimeAddress    bool    `json:"isOneTimeAddress"`
	Confidence          float64 `json:"confidence"`
}

// DepositHeuristicEngine tracks address usage to detect deposit patterns
type DepositHeuristicEngine struct {
	mu           sync.RWMutex
	addrTxCount  map[string]int   // address → number of times seen as output
	addrForwards map[string]int   // address → number of times it appears as input forwarding
	hotWallets   map[string]int   // candidate hot wallets (high inbound count)
}

var (
	globalDepositEngine *DepositHeuristicEngine
	depositEngineOnce   sync.Once
)

func GetGlobalDepositEngine() *DepositHeuristicEngine {
	depositEngineOnce.Do(func() {
		globalDepositEngine = &DepositHeuristicEngine{
			addrTxCount:  make(map[string]int),
			addrForwards: make(map[string]int),
			hotWallets:   make(map[string]int),
		}
	})
	return globalDepositEngine
}

// RecordTransaction updates address usage statistics
func (de *DepositHeuristicEngine) RecordTransaction(tx models.Transaction) {
	de.mu.Lock()
	defer de.mu.Unlock()

	for _, out := range tx.Outputs {
		if out.Address != "" {
			de.addrTxCount[out.Address]++
		}
	}
	for _, in := range tx.Inputs {
		if in.Address != "" {
			de.addrForwards[in.Address]++
		}
	}
}

// DetectDepositPattern checks if a tx looks like a deposit sweep
func (de *DepositHeuristicEngine) DetectDepositPattern(tx models.Transaction) []DepositPattern {
	de.mu.RLock()
	defer de.mu.RUnlock()

	var patterns []DepositPattern

	// Deposit sweep: few inputs (1-3), few outputs (1-2), where
	// input addresses were used only once as a recipient
	if len(tx.Inputs) > 3 || len(tx.Outputs) > 2 {
		return nil
	}

	for _, in := range tx.Inputs {
		if in.Address == "" {
			continue
		}
		receiveCount := de.addrTxCount[in.Address]
		forwardCount := de.addrForwards[in.Address]

		// One-time deposit: received exactly once, forwarding now
		if receiveCount == 1 && forwardCount <= 1 {
			for _, out := range tx.Outputs {
				if out.Address == "" || out.Address == in.Address {
					continue
				}
				pattern := DepositPattern{
					DepositAddress:      in.Address,
					ConsolidationTarget: out.Address,
					Value:               in.Value,
					IsOneTimeAddress:    true,
					Confidence:          0.7,
				}

				// Higher confidence if target receives many deposits
				targetInbound := de.addrTxCount[out.Address]
				if targetInbound > 10 {
					pattern.Confidence = 0.9
				} else if targetInbound > 5 {
					pattern.Confidence = 0.8
				}

				patterns = append(patterns, pattern)
			}
		}
	}

	return patterns
}

// ═══════════════════════════════════════════════════════════════════════
// SIGHASH Flag Analysis
// ═══════════════════════════════════════════════════════════════════════

// SigHashType represents Bitcoin signature hash types
type SigHashType uint8

const (
	SigHashAll          SigHashType = 0x01
	SigHashNone         SigHashType = 0x02
	SigHashSingle       SigHashType = 0x03
	SigHashAnyoneCanPay SigHashType = 0x80
)

// SigHashAnalysis holds SIGHASH analysis results
type SigHashAnalysis struct {
	DominantType  string  `json:"dominantType"`
	HasUnusual    bool    `json:"hasUnusual"`
	UnusualInputs int     `json:"unusualInputs"`
	Types         map[string]int `json:"types"`
	RiskBoost     float64 `json:"riskBoost"`
}

// AnalyzeSigHash inspects scriptSig/witness for SIGHASH flag anomalies
func AnalyzeSigHash(tx models.Transaction) SigHashAnalysis {
	result := SigHashAnalysis{
		DominantType: "SIGHASH_ALL",
		Types:        make(map[string]int),
	}

	for _, in := range tx.Inputs {
		sigType := classifySigHash(in.ScriptSig)
		result.Types[sigType]++

		if sigType != "SIGHASH_ALL" {
			result.HasUnusual = true
			result.UnusualInputs++
		}
	}

	// Find dominant type
	maxCount := 0
	for t, count := range result.Types {
		if count > maxCount {
			maxCount = count
			result.DominantType = t
		}
	}

	// Risk boost for unusual SIGHASH usage
	if result.HasUnusual {
		unusual := float64(result.UnusualInputs) / float64(len(tx.Inputs))
		result.RiskBoost = unusual * 0.15
	}

	return result
}

func classifySigHash(scriptSig string) string {
	if len(scriptSig) < 2 {
		return "SIGHASH_ALL"
	}

	// In DER-encoded signatures, the last byte is the SIGHASH flag
	// For simplified analysis, check common patterns
	lastByte := scriptSig[len(scriptSig)-2:]
	switch lastByte {
	case "01":
		return "SIGHASH_ALL"
	case "02":
		return "SIGHASH_NONE"
	case "03":
		return "SIGHASH_SINGLE"
	case "81":
		return "SIGHASH_ALL|ANYONECANPAY"
	case "82":
		return "SIGHASH_NONE|ANYONECANPAY"
	case "83":
		return "SIGHASH_SINGLE|ANYONECANPAY"
	default:
		return "SIGHASH_ALL"
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Mixer Service Fingerprinting (Non-CoinJoin)
// ═══════════════════════════════════════════════════════════════════════

// MixerType identifies the type of mixing service
type MixerType string

const (
	MixerChipMixer   MixerType = "chipmixer"
	MixerFogNapier   MixerType = "fog_napier"
	MixerSinbad      MixerType = "sinbad"
	MixerBlender     MixerType = "blender"
	MixerGeneric     MixerType = "generic_mixer"
	MixerNone        MixerType = "none"
)

// MixerFingerprint holds the result of mixer detection
type MixerFingerprint struct {
	IsMixer     bool      `json:"isMixer"`
	Type        MixerType `json:"type"`
	Confidence  float64   `json:"confidence"`
	Indicators  []string  `json:"indicators"`
}

// DetectMixerService identifies non-CoinJoin mixer patterns
func DetectMixerService(tx models.Transaction) MixerFingerprint {
	result := MixerFingerprint{Type: MixerNone}

	var indicators []string

	// ChipMixer pattern: outputs are powers-of-2 BTC denominations
	// (0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128 BTC)
	chipDenoms := map[int64]bool{
		100000: true, 200000: true, 400000: true, 800000: true,
		1600000: true, 3200000: true, 6400000: true, 12800000: true,
		25600000: true, 51200000: true, 102400000: true,
	}
	chipCount := 0
	for _, out := range tx.Outputs {
		if chipDenoms[out.Value] {
			chipCount++
		}
	}
	if chipCount >= 3 {
		indicators = append(indicators, "power_of_2_denominations")
		result.Type = MixerChipMixer
	}

	// Generic mixer: many equal outputs + timing delay patterns
	if len(tx.Outputs) >= 3 {
		valueCounts := make(map[int64]int)
		for _, out := range tx.Outputs {
			valueCounts[out.Value]++
		}
		for _, count := range valueCounts {
			if count >= 3 && count == len(tx.Outputs) {
				indicators = append(indicators, "all_equal_outputs")
			}
		}
	}

	// Single input → multiple outputs of fixed round amounts
	if len(tx.Inputs) == 1 && len(tx.Outputs) >= 5 {
		roundCount := 0
		for _, out := range tx.Outputs {
			if out.Value > 0 && out.Value%100000 == 0 {
				roundCount++
			}
		}
		if roundCount >= 4 {
			indicators = append(indicators, "round_amount_distribution")
		}
	}

	// Fog/Sinbad pattern: OP_RETURN with service identifier
	for _, out := range tx.Outputs {
		if out.Value == 0 && out.ScriptPubKey != "" {
			indicators = append(indicators, "op_return_service_tag")
		}
	}

	if len(indicators) >= 2 {
		result.IsMixer = true
		result.Indicators = indicators
		result.Confidence = math.Min(float64(len(indicators))*0.25, 0.90)
		if result.Type == MixerNone {
			result.Type = MixerGeneric
		}
	}

	return result
}
