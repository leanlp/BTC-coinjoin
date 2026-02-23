package heuristics

import (
	"strings"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Coinbase & Mining Pool Attribution
//
// Coinbase transactions are uniquely identifiable:
//   - Single input with null txid (0x00...00) and index 0xFFFFFFFF
//   - scriptSig contains block height (BIP34) and pool markers
//   - First output is the block reward + collected fees
//   - Outputs are pool-specific: Foundry sends to 1 address,
//     AntPool distributes to multiple
//
// Pool identification from coinbase markers:
//   "Foundry USA"  → /Foundry USA Pool/
//   "/AntPool/"    → AntPool (Bitmain)
//   "/ViaBTC/"     → ViaBTC
//   "/F2Pool/"     → F2Pool
//   "/SlushPool/"  → Braiins Pool
//   "/MARA Pool/"  → Marathon Digital
//
// References:
//   - BIP34: Block v2, Height in Coinbase
//   - Romiti et al., "Cross-Layer Deanonymization in Bitcoin" (USENIX 2021)
//   - blockchain.com/pools (live pool distribution)

// CoinbaseResult holds mining pool analysis results
type CoinbaseResult struct {
	IsCoinbase     bool    `json:"isCoinbase"`
	PoolName       string  `json:"poolName"`       // Identified mining pool
	PoolConfidence float64 `json:"poolConfidence"` // 0.0 to 1.0
	BlockReward    int64   `json:"blockReward"`    // Total block reward (subsidy + fees)
	OutputCount    int     `json:"outputCount"`    // Distribution pattern
	PayoutType     string  `json:"payoutType"`     // "single"/"multi"/"pps"/"fpps"
}

// Known mining pool markers (found in coinbase scriptSig)
var poolMarkers = map[string]string{
	"foundry usa": "Foundry USA",
	"/foundry/":   "Foundry USA",
	"antpool":     "AntPool",
	"/antpool/":   "AntPool",
	"viabtc":      "ViaBTC",
	"/viabtc/":    "ViaBTC",
	"f2pool":      "F2Pool",
	"/f2pool/":    "F2Pool",
	"slush":       "Braiins Pool",
	"braiins":     "Braiins Pool",
	"/slushpool/": "Braiins Pool",
	"mara pool":   "MARA Pool",
	"/mara pool/": "MARA Pool",
	"binance":     "Binance Pool",
	"/binance/":   "Binance Pool",
	"poolin":      "Poolin",
	"/poolin/":    "Poolin",
	"btc.com":     "BTC.com",
	"/btc.com/":   "BTC.com",
	"luxor":       "Luxor",
	"/luxor/":     "Luxor",
	"sbicrypto":   "SBI Crypto",
	"ocean":       "OCEAN",
	"/ocean.xyz/": "OCEAN",
	"spider pool": "SpiderPool",
	"emcd":        "EMCD",
}

// AnalyzeCoinbaseTx identifies if a transaction is a coinbase and
// attributes it to a mining pool.
func AnalyzeCoinbaseTx(tx models.Transaction) CoinbaseResult {
	result := CoinbaseResult{
		PayoutType: "unknown",
	}

	if !isCoinbaseTx(tx) {
		return result
	}

	result.IsCoinbase = true
	result.OutputCount = len(tx.Outputs)

	// Calculate block reward
	for _, out := range tx.Outputs {
		result.BlockReward += out.Value
	}

	// Identify pool from scriptSig marker
	if len(tx.Inputs) > 0 {
		result.PoolName, result.PoolConfidence = identifyPool(tx.Inputs[0].ScriptSig)
	}

	// Classify payout type from output pattern
	result.PayoutType = classifyPayoutType(tx)

	return result
}

// isCoinbaseTx checks if a transaction is a coinbase (block reward)
func isCoinbaseTx(tx models.Transaction) bool {
	if len(tx.Inputs) != 1 {
		return false
	}

	// Coinbase input has null txid and index 0xFFFFFFFF
	in := tx.Inputs[0]
	if in.Txid == "" || in.Txid == "0000000000000000000000000000000000000000000000000000000000000000" {
		return true
	}
	if in.Vout == 4294967295 { // 0xFFFFFFFF
		return true
	}

	return false
}

// identifyPool matches coinbase scriptSig against known pool markers
func identifyPool(scriptSig string) (string, float64) {
	if scriptSig == "" {
		return "unknown", 0
	}

	lower := strings.ToLower(scriptSig)

	// Try direct hex-decoded string matching
	decoded := hexToASCII(lower)

	for marker, poolName := range poolMarkers {
		if strings.Contains(decoded, marker) {
			return poolName, 0.95
		}
		if strings.Contains(lower, marker) {
			return poolName, 0.85
		}
	}

	return "unknown", 0
}

// hexToASCII converts hex string to ASCII (best-effort)
func hexToASCII(hex string) string {
	var result strings.Builder
	for i := 0; i+1 < len(hex); i += 2 {
		b := hexByte(hex[i], hex[i+1])
		if b >= 32 && b <= 126 { // Printable ASCII
			result.WriteByte(b)
		}
	}
	return strings.ToLower(result.String())
}

// hexByte converts two hex characters to a byte
func hexByte(hi, lo byte) byte {
	return (hexNibble(hi) << 4) | hexNibble(lo)
}

// hexNibble converts a hex character to its 4-bit value
func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

// classifyPayoutType categorizes the pool's reward distribution
func classifyPayoutType(tx models.Transaction) string {
	switch {
	case len(tx.Outputs) == 1:
		return "single" // Solo miner or pool with delayed payouts
	case len(tx.Outputs) <= 3:
		return "fpps" // Full Pay Per Share (few outputs)
	case len(tx.Outputs) <= 10:
		return "pps" // Pay Per Share (moderate outputs)
	default:
		return "multi" // Multi-output pool payout
	}
}

// IsCoinbaseSpend checks if a transaction spends coinbase outputs.
// Coinbase outputs require 100 confirmations (maturity) before spending.
func IsCoinbaseSpend(tx models.Transaction, blockHeight int) bool {
	// Heuristic: if an input's origin tx has a null-like txid prefix,
	// it may be spending coinbase. In practice, this requires UTXO lookup.
	for _, in := range tx.Inputs {
		if strings.HasPrefix(in.Txid, "000000") {
			return true
		}
	}
	return false
}
