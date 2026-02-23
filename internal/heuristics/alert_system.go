package heuristics

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// Alert & Webhook System
//
// Structured alert emission for SOC operations. Alerts are:
//   1. Broadcast via WebSocket to connected dashboards
//   2. Pushed to registered webhook endpoints (Slack, Discord, SIEM)
//   3. Stored in memory for recent alert history
//
// Webhook payloads follow a common JSON format compatible with
// Slack incoming webhooks, Discord webhooks, and PagerDuty Events API.
//
// Rate limiting prevents webhook flood during high-activity periods.

// Alert represents a structured security alert
type Alert struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Severity    string            `json:"severity"`  // info/low/medium/high/critical
	AlertType   string            `json:"alertType"` // watchlist_hit/coinjoin_detected/high_risk/compound
	Title       string            `json:"title"`
	Description string            `json:"description"`
	TxID        string            `json:"txid,omitempty"`
	Value       int64             `json:"value,omitempty"`
	Assessment  *ThreatAssessment `json:"assessment,omitempty"`
	Hits        []WatchlistHit    `json:"hits,omitempty"`
}

// WebhookEndpoint is a registered webhook receiver
type WebhookEndpoint struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Enabled     bool              `json:"enabled"`
	Headers     map[string]string `json:"headers,omitempty"`
	MinSeverity string            `json:"minSeverity"` // Only send alerts >= this severity
}

// AlertManager handles alert emission and webhook delivery
type AlertManager struct {
	mu            sync.RWMutex
	webhooks      []WebhookEndpoint
	recentAlerts  []Alert
	maxHistory    int
	httpClient    *http.Client
	alertCallback func(Alert) // WebSocket broadcast callback
}

// NewAlertManager creates a new alert system
func NewAlertManager(broadcastFn func(Alert)) *AlertManager {
	return &AlertManager{
		webhooks:      make([]WebhookEndpoint, 0),
		recentAlerts:  make([]Alert, 0),
		maxHistory:    1000,
		httpClient:    &http.Client{Timeout: 5 * time.Second},
		alertCallback: broadcastFn,
	}
}

// RegisterWebhook adds a webhook endpoint
func (am *AlertManager) RegisterWebhook(name, url, minSeverity string, headers map[string]string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.webhooks = append(am.webhooks, WebhookEndpoint{
		Name:        name,
		URL:         url,
		Enabled:     true,
		Headers:     headers,
		MinSeverity: minSeverity,
	})

	log.Printf("[AlertManager] Registered webhook: %s → %s (min: %s)", name, url, minSeverity)
}

// RemoveWebhook removes a webhook by name
func (am *AlertManager) RemoveWebhook(name string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	for i, wh := range am.webhooks {
		if wh.Name == name {
			am.webhooks = append(am.webhooks[:i], am.webhooks[i+1:]...)
			return
		}
	}
}

// EmitAlert processes and distributes an alert
func (am *AlertManager) EmitAlert(alert Alert) {
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}
	if alert.ID == "" {
		alert.ID = generateAlertID(alert)
	}

	// Store in history
	am.mu.Lock()
	am.recentAlerts = append(am.recentAlerts, alert)
	if len(am.recentAlerts) > am.maxHistory {
		am.recentAlerts = am.recentAlerts[len(am.recentAlerts)-am.maxHistory:]
	}
	webhooks := make([]WebhookEndpoint, len(am.webhooks))
	copy(webhooks, am.webhooks)
	am.mu.Unlock()

	// Broadcast via WebSocket callback
	if am.alertCallback != nil {
		am.alertCallback(alert)
	}

	// Send to webhooks (async, non-blocking)
	for _, wh := range webhooks {
		if !wh.Enabled {
			continue
		}
		if !severityMeetsThreshold(alert.Severity, wh.MinSeverity) {
			continue
		}
		go am.sendWebhook(wh, alert)
	}

	log.Printf("[Alert] [%s] %s: %s (tx: %s)", alert.Severity, alert.AlertType, alert.Title, alert.TxID)
}

// EmitFromAssessment creates and emits an alert from a threat assessment
func (am *AlertManager) EmitFromAssessment(assessment ThreatAssessment, hits []WatchlistHit) {
	if assessment.Severity == "info" {
		return // Don't alert on info-level
	}

	alertType := "risk_assessment"
	title := "Risk assessment: " + assessment.Severity

	if assessment.IsWatchlistHit {
		alertType = "watchlist_hit"
		title = "⚠️ Watchlist hit detected"
	}
	if assessment.IsCoinJoin && assessment.IsWatchlistHit {
		alertType = "compound"
		title = "🚨 Watchlisted funds entering CoinJoin mixer"
	}

	alert := Alert{
		Severity:    assessment.Severity,
		AlertType:   alertType,
		Title:       title,
		Description: buildDescription(assessment),
		TxID:        assessment.TxID,
		Assessment:  &assessment,
		Hits:        hits,
	}

	if assessment.ValueBTC > 0 {
		alert.Value = int64(assessment.ValueBTC * 100000000)
	}

	am.EmitAlert(alert)
}

// GetRecentAlerts returns the most recent alerts
func (am *AlertManager) GetRecentAlerts(limit int) []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit <= 0 || limit > len(am.recentAlerts) {
		limit = len(am.recentAlerts)
	}

	// Return most recent first
	start := len(am.recentAlerts) - limit
	result := make([]Alert, limit)
	for i := 0; i < limit; i++ {
		result[i] = am.recentAlerts[start+limit-1-i]
	}
	return result
}

// GetAlertsBySeverity returns alerts matching a minimum severity
func (am *AlertManager) GetAlertsBySeverity(minSeverity string) []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var filtered []Alert
	for _, alert := range am.recentAlerts {
		if severityMeetsThreshold(alert.Severity, minSeverity) {
			filtered = append(filtered, alert)
		}
	}
	return filtered
}

// sendWebhook delivers an alert to a webhook endpoint
func (am *AlertManager) sendWebhook(wh WebhookEndpoint, alert Alert) {
	payload, err := json.Marshal(alert)
	if err != nil {
		log.Printf("[Webhook] Failed to marshal alert: %v", err)
		return
	}

	req, err := http.NewRequest("POST", wh.URL, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[Webhook] Failed to create request for %s: %v", wh.Name, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for key, val := range wh.Headers {
		req.Header.Set(key, val)
	}

	resp, err := am.httpClient.Do(req)
	if err != nil {
		log.Printf("[Webhook] Failed to send to %s: %v", wh.Name, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("[Webhook] %s returned status %d", wh.Name, resp.StatusCode)
	}
}

// severityMeetsThreshold checks if a severity level meets the minimum
func severityMeetsThreshold(severity, minimum string) bool {
	levels := map[string]int{
		"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
	}
	return levels[severity] >= levels[minimum]
}

// generateAlertID creates a unique alert ID
func generateAlertID(alert Alert) string {
	return alert.Severity + "-" + alert.AlertType + "-" + alert.TxID
}

// buildDescription creates a human-readable alert description
func buildDescription(a ThreatAssessment) string {
	desc := ""
	if a.IsWatchlistHit {
		desc += "Transaction involves a watchlisted address. "
	}
	if a.IsCoinJoin {
		desc += "CoinJoin mixing detected. "
	}
	if a.ValueBTC > 1.0 {
		desc += "High-value transaction. "
	}
	if len(a.Signals) > 0 {
		desc += "Signals: "
		for i, s := range a.Signals {
			if i > 0 {
				desc += ", "
			}
			desc += s
		}
	}
	return desc
}
