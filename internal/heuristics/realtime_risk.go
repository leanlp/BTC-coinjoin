package heuristics

import (
	"math"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Real-Time Risk Scorer
//
// Composites ALL signals from the 28-step pipeline into a single
// threat assessment for every mempool transaction. This is what
// analysts see on the SOC dashboard — a unified risk verdict.
//
// Risk composition:
//   Base score starts at 0 (clean)
//   Each signal adds weighted risk points
//   Watchlist hit = immediate escalation
//   CoinJoin + high value = automatic critical
//
// Severity levels:
//   info     (0-10):   Normal transaction, no action
//   low      (11-30):  Minor flags, log only
//   medium   (31-50):  Notable patterns, review recommended
//   high     (51-75):  Suspicious activity, alert team
//   critical (76-100): Immediate action required

// ThreatAssessment is the real-time risk verdict for a transaction
type ThreatAssessment struct {
	TxID              string   `json:"txid"`
	RiskScore         int      `json:"riskScore"`         // 0-100
	Severity          string   `json:"severity"`          // info/low/medium/high/critical
	Signals           []string `json:"signals"`           // Contributing risk signals
	RecommendedAction string   `json:"recommendedAction"` // "none"/"log"/"review"/"alert"/"escalate"
	IsWatchlistHit    bool     `json:"isWatchlistHit"`
	IsCoinJoin        bool     `json:"isCoinJoin"`
	ValueBTC          float64  `json:"valueBtc"`
}

// ScoreTransaction produces a real-time threat assessment from analysis results
func ScoreTransaction(tx models.Transaction, result models.PrivacyAnalysisResult, watchlistHits []WatchlistHit) ThreatAssessment {
	assessment := ThreatAssessment{
		TxID: tx.Txid,
	}

	riskScore := 0
	var signals []string

	// ─── Total transaction value ─────────────────────────────────────
	totalIn := int64(0)
	for _, in := range tx.Inputs {
		totalIn += in.Value
	}
	totalOut := int64(0)
	for _, out := range tx.Outputs {
		totalOut += out.Value
	}

	// Prefer the larger observed side to remain robust when prevout input
	// lookups are missing and input values are partially zeroed.
	totalValue := totalOut
	if totalIn > totalOut {
		totalValue = totalIn
	}
	assessment.ValueBTC = float64(totalValue) / 100000000.0

	// High-value transactions get extra scrutiny
	if totalValue > 100000000 { // > 1 BTC
		riskScore += 5
		signals = append(signals, "high_value_tx")
	}
	if totalValue > 1000000000 { // > 10 BTC
		riskScore += 10
		signals = append(signals, "very_high_value_tx")
	}

	// ─── Watchlist hits = immediate escalation ───────────────────────
	if len(watchlistHits) > 0 {
		assessment.IsWatchlistHit = true
		for _, hit := range watchlistHits {
			switch hit.Category {
			case "theft":
				riskScore += 50
				signals = append(signals, "watchlist:theft:"+hit.Label)
			case "sanctioned":
				riskScore += 60
				signals = append(signals, "watchlist:sanctioned:"+hit.Label)
			case "suspect":
				riskScore += 40
				signals = append(signals, "watchlist:suspect:"+hit.Label)
			default:
				riskScore += 20
				signals = append(signals, "watchlist:"+hit.Category+":"+hit.Label)
			}
		}
	}

	// ─── CoinJoin detection ──────────────────────────────────────────
	flags := result.HeuristicFlags

	if (flags&uint64(FlagIsWhirlpoolStruct)) > 0 ||
		(flags&uint64(FlagIsWasabiSuspect)) > 0 ||
		(flags&uint64(FlagLikelyCollabConstruct)) > 0 {
		assessment.IsCoinJoin = true
		riskScore += 15
		signals = append(signals, "coinjoin_detected")
	}

	// ─── Post-mix leakage ────────────────────────────────────────────
	if (flags & uint64(FlagPostMixLeakage)) > 0 {
		riskScore += 20
		signals = append(signals, "post_mix_leakage")
	}

	// ─── High traceability ───────────────────────────────────────────
	if (flags & uint64(FlagHighTraceability)) > 0 {
		riskScore += 10
		signals = append(signals, "high_traceability")
	}

	// ─── Dust attack ─────────────────────────────────────────────────
	if (flags & uint64(FlagDustAttackSuspect)) > 0 {
		riskScore += 15
		signals = append(signals, "dust_attack")
	}

	// ─── Taint / High risk ───────────────────────────────────────────
	taintLevel, taintHighRisk := CheckInputsForTaint(tx)
	if taintLevel > 0 {
		// Continuous taint contribution (0-25 points), robust to partial contamination.
		riskScore += int(math.Round(math.Min(25.0, taintLevel*25.0)))
		signals = append(signals, "taint_exposure")
	}
	if (flags & uint64(FlagHighRisk)) > 0 {
		riskScore += 30
		signals = append(signals, "tainted_funds")
	} else if taintHighRisk {
		// Safety net if analysis flags are stale but taint map has high confidence intel.
		riskScore += 25
		signals = append(signals, "taint_high_risk")
	}

	// ─── Bot behavior ────────────────────────────────────────────────
	if (flags & uint64(FlagBotBehavior)) > 0 {
		riskScore += 10
		signals = append(signals, "bot_pattern")
	}

	// ─── Ancient UTXO movement ───────────────────────────────────────
	if (flags & uint64(FlagAncientUTXO)) > 0 {
		riskScore += 8
		signals = append(signals, "ancient_utxo_movement")
	}

	// ─── Known service pattern ───────────────────────────────────────
	if (flags & uint64(FlagKnownServicePattern)) > 0 {
		riskScore += 5
		signals = append(signals, "known_service_pattern")
	}

	// ─── Low privacy score (includes address reuse, change detection) ────
	if result.PrivacyScore < 30 {
		riskScore += 3
		signals = append(signals, "low_privacy_score")
	}

	// ─── Lightning channel ───────────────────────────────────────────
	if (flags & uint64(FlagLightningChannel)) > 0 {
		riskScore -= 5 // LN is privacy-enhancing
		signals = append(signals, "lightning_channel")
	}

	// ─── Consolidation ───────────────────────────────────────────────
	if (flags & uint64(FlagStrategicConsolidation)) > 0 {
		riskScore += 5
		signals = append(signals, "consolidation")
	}

	// ─── Compound escalation: CoinJoin + watchlist + high value ──────
	if assessment.IsCoinJoin && assessment.IsWatchlistHit && totalValue > 100000000 {
		riskScore += 20
		signals = append(signals, "compound_escalation")
	}

	// Cap at 100
	if riskScore > 100 {
		riskScore = 100
	}
	if riskScore < 0 {
		riskScore = 0
	}

	assessment.RiskScore = riskScore
	assessment.Signals = signals
	assessment.Severity = classifySeverity(riskScore)
	assessment.RecommendedAction = recommendAction(riskScore)

	return assessment
}

// classifySeverity maps risk score to severity level
func classifySeverity(score int) string {
	switch {
	case score <= 10:
		return "info"
	case score <= 30:
		return "low"
	case score <= 50:
		return "medium"
	case score <= 75:
		return "high"
	default:
		return "critical"
	}
}

// recommendAction maps risk score to recommended action
func recommendAction(score int) string {
	switch {
	case score <= 10:
		return "none"
	case score <= 30:
		return "log"
	case score <= 50:
		return "review"
	case score <= 75:
		return "alert"
	default:
		return "escalate"
	}
}
