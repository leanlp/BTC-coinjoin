package heuristics

import (
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Darknet Market Pattern Detection
// ═══════════════════════════════════════════════════════════════════════

// DarknetPattern describes a detected darknet market interaction
type DarknetPattern struct {
	IsMarketRelated bool    `json:"isMarketRelated"`
	PatternType     string  `json:"patternType"` // "withdrawal_fee", "structured_amount", "tumbler_output"
	Confidence      float64 `json:"confidence"`
	Details         string  `json:"details"`
}

// Known darknet market withdrawal fee values (satoshis)
var knownMarketFees = map[int64]string{
	50000:  "generic_market",    // Common 0.0005 BTC fee
	100000: "generic_market",    // Common 0.001 BTC fee
	30000:  "hydra_pattern",     // Hydra-style withdrawal fee
	25000:  "alphabay_pattern",  // AlphaBay-style withdrawal fee
}

// DetectDarknetPatterns looks for transaction patterns typical of darknet markets
func DetectDarknetPatterns(tx models.Transaction) []DarknetPattern {
	var patterns []DarknetPattern

	// Pattern 1: Known withdrawal fee deduction
	// Market withdrawals: user_amount + fixed_fee → 2 outputs
	if len(tx.Outputs) == 2 {
		for _, out := range tx.Outputs {
			if market, ok := knownMarketFees[out.Value]; ok {
				patterns = append(patterns, DarknetPattern{
					IsMarketRelated: true,
					PatternType:     "withdrawal_fee",
					Confidence:      0.4, // Low confidence — fee alone isn't definitive
					Details:         "output matches known " + market + " withdrawal fee",
				})
			}
		}
	}

	// Pattern 2: Structured amounts (round BTC values common in market listings)
	// Market prices are often set in round BTC (0.01, 0.05, 0.1 BTC)
	roundCount := 0
	for _, out := range tx.Outputs {
		if out.Value > 0 {
			btcValue := float64(out.Value) / 100000000.0
			if btcValue == 0.01 || btcValue == 0.02 || btcValue == 0.05 ||
				btcValue == 0.1 || btcValue == 0.25 || btcValue == 0.5 {
				roundCount++
			}
		}
	}
	if roundCount >= 2 {
		patterns = append(patterns, DarknetPattern{
			IsMarketRelated: true,
			PatternType:     "structured_amount",
			Confidence:      0.3,
			Details:         "multiple outputs match common market pricing",
		})
	}

	// Pattern 3: Tumbler output pattern (many equal small outputs)
	if len(tx.Outputs) >= 5 {
		valueCounts := make(map[int64]int)
		for _, out := range tx.Outputs {
			valueCounts[out.Value]++
		}
		for val, count := range valueCounts {
			if count >= 4 && val < 1000000 { // < 0.01 BTC
				patterns = append(patterns, DarknetPattern{
					IsMarketRelated: true,
					PatternType:     "tumbler_output",
					Confidence:      0.5,
					Details:         "multiple equal small outputs suggest tumbling",
				})
				break
			}
		}
	}

	return patterns
}



// ═══════════════════════════════════════════════════════════════════════
// CoinJoin ML Classifier (Rule-Based Decision Tree)
// ═══════════════════════════════════════════════════════════════════════

// ClassificationResult holds ML classification output
type ClassificationResult struct {
	IsCoinJoin  bool    `json:"isCoinJoin"`
	Confidence  float64 `json:"confidence"`
	TxType      string  `json:"txType"` // "coinjoin", "payment", "consolidation", "batch_payout", "unknown"
	Explanation string  `json:"explanation"`
}

// ClassifyTransaction uses a rule-based decision tree on extracted features
func ClassifyTransaction(f TxFeatureVector) ClassificationResult {
	// Rule 1: CoinJoin — high equal outputs + multiple inputs
	if f.EqualOutputRatio >= 0.5 && f.MaxEqualOutputs >= 3 && f.InputCount >= 3 {
		conf := 0.85
		if f.MixedScriptTypes {
			conf = 0.92
		}
		if f.OutputGini < 0.2 {
			conf = 0.95
		}
		return ClassificationResult{IsCoinJoin: true, Confidence: conf, TxType: "coinjoin",
			Explanation: "equal outputs + multi-input pattern"}
	}

	// Rule 2: Consolidation — many inputs → 1 output
	if f.InputCount >= 5 && f.OutputCount <= 2 {
		return ClassificationResult{Confidence: 0.90, TxType: "consolidation",
			Explanation: "many-to-one UTXO consolidation"}
	}

	// Rule 3: Batch payout — 1 input → many round outputs
	if f.InputCount <= 2 && f.OutputCount >= 5 && f.RoundOutputRatio >= 0.5 {
		return ClassificationResult{Confidence: 0.85, TxType: "batch_payout",
			Explanation: "single source distributing to many recipients"}
	}

	// Rule 4: Normal payment — simple 1→2 with change
	if f.InputCount <= 2 && f.OutputCount <= 2 {
		conf := 0.80
		if f.HasLikelyChange {
			conf = 0.90
		}
		return ClassificationResult{Confidence: conf, TxType: "payment",
			Explanation: "standard payment with change"}
	}

	// Rule 5: CoinJoin by composite score
	if f.CoinJoinLikelihood > 0.5 {
		return ClassificationResult{IsCoinJoin: true, Confidence: f.CoinJoinLikelihood, TxType: "coinjoin",
			Explanation: "composite CoinJoin score exceeds threshold"}
	}

	return ClassificationResult{Confidence: 0.5, TxType: "unknown", Explanation: "no clear pattern"}
}


