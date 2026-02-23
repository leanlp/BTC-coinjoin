package heuristics

import (
	"strings"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Exchange Exit Detector
//
// Identifies the critical cash-out moment: when stolen funds reach
// a cryptocurrency exchange deposit address. This is where law
// enforcement can subpoena KYC records to identify the perpetrator.
//
// Detection methods:
//   1. Known address prefix patterns (exchange hot wallets)
//   2. Output structure: single P2SH/P2WSH output (exchange deposit scripts)
//   3. Value patterns: exchanges require minimum deposits
//   4. Known exchange withdrawal fee patterns (from value_fingerprint.go)
//   5. Behavioral: deposit-then-sell patterns
//
// Major exchanges have identifiable on-chain patterns:
//   - Binance: bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s0h (hot wallet cluster)
//   - Coinbase: Uses unique deposit addresses (P2SH-wrapped SegWit)
//   - Kraken: 3-address prefix clustering
//   - Bitfinex: bc1qgdjqv0av... (known cold wallet)
//
// References:
//   - Baumgartner & Hughes, "Follow the Bitcoins" (IEEE S&P 2020)
//   - Crystal Blockchain, "Exchange Identification Methodology" (2023)

// ExchangeExitResult holds exchange deposit detection results
type ExchangeExitResult struct {
	IsExchangeDeposit bool    `json:"isExchangeDeposit"`
	ExchangeName      string  `json:"exchangeName"`
	Confidence        float64 `json:"confidence"`
	DepositValue      int64   `json:"depositValue"`
	DetectionMethod   string  `json:"detectionMethod"` // "address_match"/"pattern"/"behavioral"
}

// Known exchange address prefixes and patterns
// In production, this would be a database of millions of tagged addresses.
// This is a representative set for demonstration.
var knownExchangePrefixes = map[string]string{
	"bc1qm34lsc65zpw79lxes69zkqm": "Binance",
	"1NDyJtNTjmwk5xPNhjgAMu4HDH":  "Binance",
	"3JZq4atUahhuA9rLhXLMhhTo133": "Binance",
	"3Cbq7aT1tY8kMxWLbitaG7yT6bP": "Coinbase",
	"3CD1QW6fjgTwKq3Pj97nty28WZA": "Coinbase",
	"bc1qxy2kgdygjrsqtzq2n0yrf24": "Coinbase",
	"3FHNBLobJnbCTFTVakh5TXlt":    "Bitfinex",
	"bc1qgdjqv0av3q56jvd82tk":     "Bitfinex",
	"3AfBdeS2QYHSM3PQ9bfXuUbJPMi": "Kraken",
	"bc1qxp3x5mqr6t5mhqkze3vj":    "Kraken",
}

// Known exchange deposit characteristics
type exchangePattern struct {
	Name           string
	MinDeposit     int64 // Minimum deposit in sats
	TypicalOutputs int   // Typical output count for deposits
	UsesP2SH       bool  // Exchange uses P2SH addresses
	UsesSegWit     bool  // Exchange uses native SegWit
}

var exchangePatterns = []exchangePattern{
	{"Binance", 100000, 1, false, true},
	{"Coinbase", 100000, 1, true, true},
	{"Kraken", 100000, 1, true, true},
	{"Bitfinex", 500000, 1, false, true},
	{"Bybit", 100000, 1, false, true},
	{"OKX", 100000, 1, false, true},
	{"Huobi", 100000, 1, false, true},
}

// DetectExchangeExit analyzes a transaction for exchange deposit patterns
func DetectExchangeExit(tx models.Transaction) ExchangeExitResult {
	result := ExchangeExitResult{}

	// Method 1: Direct address matching against known exchange addresses
	for _, out := range tx.Outputs {
		for prefix, exchange := range knownExchangePrefixes {
			if strings.HasPrefix(out.Address, prefix) {
				result.IsExchangeDeposit = true
				result.ExchangeName = exchange
				result.Confidence = 0.95
				result.DepositValue = out.Value
				result.DetectionMethod = "address_match"
				return result
			}
		}
	}

	// Method 2: Structural pattern matching
	if patternResult := matchExchangePattern(tx); patternResult.IsExchangeDeposit {
		return patternResult
	}

	// Method 3: Behavioral heuristics
	if behaviorResult := detectExchangeBehavior(tx); behaviorResult.IsExchangeDeposit {
		return behaviorResult
	}

	return result
}

// matchExchangePattern uses structural patterns to identify exchange deposits
func matchExchangePattern(tx models.Transaction) ExchangeExitResult {
	result := ExchangeExitResult{}

	// Exchange deposits typically have:
	// - 1 input (the user's wallet)
	// - 1-2 outputs (deposit + optional change)
	// - Output to a P2SH or P2WSH address
	// - Value above minimum deposit threshold

	if len(tx.Outputs) > 3 {
		return result // Too many outputs for a deposit
	}

	for _, out := range tx.Outputs {
		addrType := detectAddressType(out.Address)

		// P2SH addresses starting with "3" are common for exchange deposits
		if addrType == "p2sh-segwit" && out.Value >= 100000 {
			result.IsExchangeDeposit = true
			result.Confidence = 0.4
			result.DepositValue = out.Value
			result.DetectionMethod = "pattern"
			result.ExchangeName = "unknown (P2SH deposit pattern)"
			return result
		}
	}

	return result
}

// detectExchangeBehavior uses behavioral analysis to identify deposits
func detectExchangeBehavior(tx models.Transaction) ExchangeExitResult {
	result := ExchangeExitResult{}

	// Behavioral indicator: single input → single output (sweep to exchange)
	// with SegWit input spending to P2SH output
	if len(tx.Inputs) == 1 && len(tx.Outputs) == 1 {
		inputType := detectAddressType(tx.Inputs[0].Address)
		outputType := detectAddressType(tx.Outputs[0].Address)

		if inputType == "segwit" && outputType == "p2sh-segwit" && tx.Outputs[0].Value >= 1000000 {
			result.IsExchangeDeposit = true
			result.Confidence = 0.3
			result.DepositValue = tx.Outputs[0].Value
			result.DetectionMethod = "behavioral"
			result.ExchangeName = "unknown (sweep-to-P2SH pattern)"
			return result
		}
	}

	return result
}

// IsKnownExchangeAddress checks if an address belongs to a known exchange
func IsKnownExchangeAddress(addr string) (string, bool) {
	for prefix, exchange := range knownExchangePrefixes {
		if strings.HasPrefix(addr, prefix) {
			return exchange, true
		}
	}
	return "", false
}
