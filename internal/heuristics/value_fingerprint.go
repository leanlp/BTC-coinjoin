package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Value Fingerprinting Module
//
// Specific satoshi amounts uniquely identify services, exchanges, and
// protocol patterns. This module detects:
//
//   1. Known exchange withdrawal fees:
//      - Binance:  0.0005 BTC (50000 sats) network fee
//      - Coinbase: 0.00001 BTC flat (varies)
//      - Kraken:   0.00015 BTC (15000 sats)
//
//   2. Round BTC denominations (human-initiated payments):
//      - 0.001, 0.01, 0.05, 0.1, 0.5, 1.0 BTC
//
//   3. Protocol-specific amounts:
//      - Lightning channel: round mBTC (100000, 500000, 1000000 sats)
//      - Whirlpool pools: 100000, 1000000, 5000000, 50000000 sats
//
//   4. Output value entropy (Shannon):
//      - Low entropy → few distinct values → mixing or batching
//      - High entropy → many unique values → normal spending
//
// References:
//   - Meiklejohn et al., "A Fistful of Bitcoins" (2013)
//   - Erdin et al., "How to Not Get Caught" (ESORICS 2023)
//   - Möser, "Anonymity of Bitcoin Transactions" (2013)

// Known exchange withdrawal fee amounts (in satoshis)
var knownServiceFees = map[string][]int64{
	"binance":  {50000, 40000, 30000, 20000}, // Binance BTC withdrawal tiers
	"coinbase": {1000, 2000, 5000, 10000},    // Coinbase (variable)
	"kraken":   {15000, 10000},               // Kraken BTC withdrawal
	"ftx":      {0},                          // FTX (free, before collapse)
	"gemini":   {0, 1000},                    // Gemini (10 free/mo)
	"bitfinex": {4000, 6000},                 // Bitfinex
}

// Round BTC denomination thresholds (in satoshis)
var roundBTCAmounts = []int64{
	100000,    // 0.001 BTC
	500000,    // 0.005 BTC
	1000000,   // 0.01 BTC
	5000000,   // 0.05 BTC
	10000000,  // 0.1 BTC
	50000000,  // 0.5 BTC
	100000000, // 1.0 BTC
	200000000, // 2.0 BTC
	500000000, // 5.0 BTC
}

// AnalyzeValuePatterns performs comprehensive value fingerprinting on outputs
func AnalyzeValuePatterns(tx models.Transaction) models.ValuePatternResult {
	result := models.ValuePatternResult{
		KnownServiceFee: "none",
	}

	// 1. Check for round BTC amounts in outputs
	for _, out := range tx.Outputs {
		if isRoundBTCAmount(out.Value) {
			result.HasRoundBTC = true
		}
		if isRoundSatsAmount(out.Value) {
			result.HasRoundSats = true
		}
	}

	// 2. Check for known service fee patterns
	result.KnownServiceFee = matchKnownServiceFee(tx)

	// 3. Compute Shannon entropy of output values
	result.OutputValueEntropy = computeOutputShannon(tx.Outputs)

	// 4. Find dominant denomination
	valueCounts := make(map[int64]int)
	for _, out := range tx.Outputs {
		valueCounts[out.Value]++
	}
	bestCount := 0
	for val, count := range valueCounts {
		if count > bestCount {
			bestCount = count
			result.DominantDenomination = val
		}
	}

	// 5. Unique value ratio (what fraction of outputs are unique?)
	if len(tx.Outputs) > 0 {
		result.UniqueValueRatio = math.Round(float64(len(valueCounts))*100/float64(len(tx.Outputs))) / 100
	}

	return result
}

// isRoundBTCAmount checks if a value matches a psychologically-round BTC amount
func isRoundBTCAmount(sats int64) bool {
	for _, round := range roundBTCAmounts {
		if sats == round {
			return true
		}
	}
	return false
}

// isRoundSatsAmount checks if a value is a "round" satoshi amount
// (multiples of 10000, 50000, or 100000)
func isRoundSatsAmount(sats int64) bool {
	if sats <= 0 {
		return false
	}
	return sats%100000 == 0 || sats%50000 == 0 || sats%10000 == 0
}

// matchKnownServiceFee checks if the fee amount matches a known exchange pattern
func matchKnownServiceFee(tx models.Transaction) string {
	if tx.Fee <= 0 {
		return "none"
	}

	for service, fees := range knownServiceFees {
		for _, knownFee := range fees {
			if knownFee == 0 {
				continue
			}
			// Allow ±5% tolerance for fee variations
			tolerance := knownFee / 20
			if tolerance < 100 {
				tolerance = 100
			}
			if tx.Fee >= knownFee-tolerance && tx.Fee <= knownFee+tolerance {
				return service
			}
		}
	}

	// Check for exchange-like fee patterns:
	// Exact multiples of 1000 sats with fee in 10000-100000 range
	if tx.Fee >= 10000 && tx.Fee <= 100000 && tx.Fee%1000 == 0 {
		return "exchange-generic"
	}

	return "none"
}

// computeOutputShannon computes Shannon entropy of output value distribution
// H = -Σ p(x) * log₂(p(x))
func computeOutputShannon(outputs []models.TxOut) float64 {
	if len(outputs) == 0 {
		return 0
	}

	valueCounts := make(map[int64]int)
	for _, out := range outputs {
		valueCounts[out.Value]++
	}

	total := float64(len(outputs))
	entropy := 0.0
	for _, count := range valueCounts {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return math.Round(entropy*100) / 100
}

// DetectExchangeWithdrawal combines fee pattern + output value to
// identify likely exchange withdrawal transactions
func DetectExchangeWithdrawal(tx models.Transaction) (bool, string) {
	// Exchange withdrawals typically:
	// 1. Have 1-3 inputs (from hot wallet)
	// 2. Have many outputs (batched)
	// 3. Fee matches known exchange schedule
	if len(tx.Inputs) > 5 || len(tx.Outputs) < 3 {
		return false, ""
	}

	serviceFee := matchKnownServiceFee(tx)
	if serviceFee != "none" && serviceFee != "exchange-generic" {
		return true, serviceFee
	}

	// Check for batch payout pattern with exchange-like fee rounding
	if len(tx.Outputs) >= 5 && tx.Fee > 0 {
		feeRate := float64(tx.Fee) / float64(tx.Vsize)
		if feeRate > 0 && math.Mod(feeRate, 1.0) < 0.01 {
			return true, "exchange-generic"
		}
	}

	return false, ""
}
