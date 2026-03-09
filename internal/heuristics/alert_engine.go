package heuristics

import (
	"sync"
	"time"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// Customizable Risk Indicator Engine
// ═══════════════════════════════════════════════════════════════════════

type RiskCategory string

const (
	RiskDarknet    RiskCategory = "darknet"
	RiskRansomware RiskCategory = "ransomware"
	RiskScam       RiskCategory = "scam"
	RiskMixer      RiskCategory = "mixer"
	RiskSanctioned RiskCategory = "sanctioned"
	RiskGambling   RiskCategory = "gambling"
	RiskHighRisk   RiskCategory = "high_risk_jurisdiction"
)

type RiskIndicator struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Category RiskCategory `json:"category"`
	Severity float64      `json:"severity"`
	Enabled  bool         `json:"enabled"`
}

type RiskProfile struct {
	OverallScore   float64                  `json:"overallScore"`
	RiskLevel      string                   `json:"riskLevel"`
	TriggeredRules []TriggeredRule          `json:"triggeredRules"`
	Categories     map[RiskCategory]float64 `json:"categories"`
}

type TriggeredRule struct {
	IndicatorID string  `json:"indicatorId"`
	Name        string  `json:"name"`
	Severity    float64 `json:"severity"`
	Details     string  `json:"details"`
}

type RiskEngine struct {
	mu         sync.RWMutex
	indicators map[string]RiskIndicator
}

var (
	globalRiskEngine *RiskEngine
	riskEngineOnce   sync.Once
)

func GetGlobalRiskEngine() *RiskEngine {
	riskEngineOnce.Do(func() {
		globalRiskEngine = &RiskEngine{indicators: defaultIndicators()}
	})
	return globalRiskEngine
}

func defaultIndicators() map[string]RiskIndicator {
	return map[string]RiskIndicator{
		"high_value":      {ID: "high_value", Name: "High Value Transaction", Category: RiskHighRisk, Severity: 0.3, Enabled: true},
		"mixer_detected":  {ID: "mixer_detected", Name: "Mixer Service Detected", Category: RiskMixer, Severity: 0.7, Enabled: true},
		"coinjoin":        {ID: "coinjoin", Name: "CoinJoin Transaction", Category: RiskMixer, Severity: 0.5, Enabled: true},
		"sanctioned_addr": {ID: "sanctioned_addr", Name: "Sanctioned Address", Category: RiskSanctioned, Severity: 1.0, Enabled: true},
		"structuring":     {ID: "structuring", Name: "Structuring Detected", Category: RiskScam, Severity: 0.8, Enabled: true},
		"dust_attack":     {ID: "dust_attack", Name: "Dust Attack", Category: RiskScam, Severity: 0.4, Enabled: true},
		"consolidation":   {ID: "consolidation", Name: "Suspicious Consolidation", Category: RiskScam, Severity: 0.5, Enabled: true},
	}
}

func (re *RiskEngine) AddIndicator(ind RiskIndicator) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.indicators[ind.ID] = ind
}

func (re *RiskEngine) RemoveIndicator(id string) {
	re.mu.Lock()
	defer re.mu.Unlock()
	delete(re.indicators, id)
}

func (re *RiskEngine) ToggleIndicator(id string, enabled bool) {
	re.mu.Lock()
	defer re.mu.Unlock()
	if ind, ok := re.indicators[id]; ok {
		ind.Enabled = enabled
		re.indicators[id] = ind
	}
}

func (re *RiskEngine) EvaluateRisk(tx models.Transaction, result *models.PrivacyAnalysisResult) RiskProfile {
	re.mu.RLock()
	defer re.mu.RUnlock()

	profile := RiskProfile{Categories: make(map[RiskCategory]float64)}

	for _, ind := range re.indicators {
		if !ind.Enabled {
			continue
		}
		triggered, details := re.checkIndicator(ind, tx, result)
		if triggered {
			profile.TriggeredRules = append(profile.TriggeredRules, TriggeredRule{
				IndicatorID: ind.ID, Name: ind.Name, Severity: ind.Severity, Details: details,
			})
			profile.Categories[ind.Category] += ind.Severity
		}
	}

	if len(profile.TriggeredRules) > 0 {
		maxSev := 0.0
		totalSev := 0.0
		for _, r := range profile.TriggeredRules {
			totalSev += r.Severity
			if r.Severity > maxSev {
				maxSev = r.Severity
			}
		}
		avg := totalSev / float64(len(profile.TriggeredRules))
		cf := 1.0 + float64(len(profile.TriggeredRules)-1)*0.1
		if cf > 2.0 {
			cf = 2.0
		}
		profile.OverallScore = (maxSev*0.6 + avg*0.4*cf) * 100
		if profile.OverallScore > 100 {
			profile.OverallScore = 100
		}
	}

	switch {
	case profile.OverallScore >= 80:
		profile.RiskLevel = "critical"
	case profile.OverallScore >= 50:
		profile.RiskLevel = "high"
	case profile.OverallScore >= 25:
		profile.RiskLevel = "medium"
	default:
		profile.RiskLevel = "low"
	}

	return profile
}

func (re *RiskEngine) checkIndicator(ind RiskIndicator, tx models.Transaction, result *models.PrivacyAnalysisResult) (bool, string) {
	if result == nil {
		return false, ""
	}
	switch ind.ID {
	case "high_value":
		total := int64(0)
		for _, out := range tx.Outputs {
			total += out.Value
		}
		if total > 100000000 {
			return true, "value exceeds 1 BTC"
		}
	case "mixer_detected":
		if result.HeuristicFlags&uint64(FlagMixerService) > 0 {
			return true, "mixer service detected"
		}
	case "coinjoin":
		if result.HeuristicFlags&uint64(FlagCoinJoinDetected) > 0 || result.AnonSet >= 3 {
			return true, "CoinJoin detected"
		}
	case "sanctioned_addr":
		if result.HeuristicFlags&uint64(FlagSanctionedEntity) > 0 {
			return true, "sanctioned entity"
		}
	case "structuring":
		if result.HeuristicFlags&uint64(FlagLaunderingPattern) > 0 {
			return true, "laundering pattern"
		}
	case "dust_attack":
		for _, out := range tx.Outputs {
			if out.Value > 0 && out.Value < 546 {
				return true, "dust output"
			}
		}
	case "consolidation":
		if result.HeuristicFlags&uint64(FlagConsolidation) > 0 {
			return true, "suspicious consolidation"
		}
	}
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════
// Real-Time Alert System (uses RiskAlert to avoid conflict with Alert)
// ═══════════════════════════════════════════════════════════════════════

type RiskAlertLevel string

const (
	RiskAlertInfo     RiskAlertLevel = "info"
	RiskAlertWarning  RiskAlertLevel = "warning"
	RiskAlertHigh     RiskAlertLevel = "high"
	RiskAlertCritical RiskAlertLevel = "critical"
)

// RiskAlert represents a triggered risk alert (distinct from Alert in alert_system.go)
type RiskAlert struct {
	ID        string         `json:"id"`
	Level     RiskAlertLevel `json:"level"`
	TxID      string         `json:"txid"`
	Message   string         `json:"message"`
	Category  RiskCategory   `json:"category"`
	Score     float64        `json:"score"`
	Timestamp time.Time      `json:"timestamp"`
}

type RiskAlertRule struct {
	ID      string             `json:"id"`
	Name    string             `json:"name"`
	Level   RiskAlertLevel     `json:"level"`
	Cond    RiskAlertCondition `json:"condition"`
	Enabled bool               `json:"enabled"`
}

type RiskAlertCondition struct {
	MinRiskScore float64      `json:"minRiskScore,omitempty"`
	Category     RiskCategory `json:"category,omitempty"`
	MinValue     int64        `json:"minValue,omitempty"`
}

type RiskAlertEngine struct {
	mu     sync.RWMutex
	rules  []RiskAlertRule
	alerts []RiskAlert
}

var (
	globalRiskAlertEngine *RiskAlertEngine
	riskAlertEngineOnce   sync.Once
)

func GetGlobalRiskAlertEngine() *RiskAlertEngine {
	riskAlertEngineOnce.Do(func() {
		globalRiskAlertEngine = &RiskAlertEngine{
			rules: []RiskAlertRule{
				{ID: "sanctions_hit", Name: "Sanctioned Entity", Level: RiskAlertCritical, Enabled: true,
					Cond: RiskAlertCondition{MinRiskScore: 90}},
				{ID: "high_risk", Name: "High Risk Transaction", Level: RiskAlertHigh, Enabled: true,
					Cond: RiskAlertCondition{MinRiskScore: 70}},
				{ID: "mixer_usage", Name: "Mixing Service Used", Level: RiskAlertWarning, Enabled: true,
					Cond: RiskAlertCondition{Category: RiskMixer, MinRiskScore: 40}},
				{ID: "whale", Name: "Large Transaction", Level: RiskAlertInfo, Enabled: true,
					Cond: RiskAlertCondition{MinValue: 1000000000}},
			},
		}
	})
	return globalRiskAlertEngine
}

func (ae *RiskAlertEngine) AddRule(rule RiskAlertRule) {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	ae.rules = append(ae.rules, rule)
}

func (ae *RiskAlertEngine) ProcessTransaction(tx models.Transaction, riskProfile RiskProfile) []RiskAlert {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	var triggered []RiskAlert
	now := time.Now()
	totalValue := int64(0)
	for _, out := range tx.Outputs {
		totalValue += out.Value
	}

	for _, rule := range ae.rules {
		if !rule.Enabled {
			continue
		}
		if ae.matchesCond(rule.Cond, riskProfile, totalValue) {
			alert := RiskAlert{
				ID: rule.ID, Level: rule.Level, TxID: tx.Txid,
				Message: rule.Name, Score: riskProfile.OverallScore, Timestamp: now,
			}
			triggered = append(triggered, alert)
			ae.alerts = append(ae.alerts, alert)
		}
	}
	return triggered
}

func (ae *RiskAlertEngine) matchesCond(cond RiskAlertCondition, profile RiskProfile, totalValue int64) bool {
	if cond.MinRiskScore > 0 && profile.OverallScore < cond.MinRiskScore {
		return false
	}
	if cond.MinValue > 0 && totalValue < cond.MinValue {
		return false
	}
	if cond.Category != "" {
		if _, exists := profile.Categories[cond.Category]; !exists {
			return false
		}
	}
	return true
}

func (ae *RiskAlertEngine) GetAlerts(limit int) []RiskAlert {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	if limit <= 0 || limit > len(ae.alerts) {
		limit = len(ae.alerts)
	}
	start := len(ae.alerts) - limit
	if start < 0 {
		start = 0
	}
	result := make([]RiskAlert, limit)
	copy(result, ae.alerts[start:])
	return result
}

func (ae *RiskAlertEngine) AlertCount() int {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	return len(ae.alerts)
}
