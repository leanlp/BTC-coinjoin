package heuristics

import (
	"strings"
	"sync"
	"time"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ═══════════════════════════════════════════════════════════════════════
// SAR Auto-Generation (Suspicious Activity Report)
// ═══════════════════════════════════════════════════════════════════════
//
// Financial institutions must file SARs with FinCEN when they detect
// suspicious activity. This module auto-generates SAR-ready narratives
// from analysis results.
//
// BSA/AML requirements:
//   - File within 30 days of detection
//   - Include: activity description, subjects, amounts, dates, why suspicious
//
// This generator creates structured reports that compliance officers
// can review and submit through BSA E-Filing.

// SARReport holds a generated Suspicious Activity Report
type SARReport struct {
	ReportID         string    `json:"reportId"`
	GeneratedAt      time.Time `json:"generatedAt"`
	ActivityType     string    `json:"activityType"`     // BSA activity code
	ActivityDate     time.Time `json:"activityDate"`
	TotalAmount      float64   `json:"totalAmount"`      // In BTC
	TotalAmountUSD   float64   `json:"totalAmountUsd"`   // In USD (if price available)
	Addresses        []string  `json:"addresses"`
	TransactionIDs   []string  `json:"transactionIds"`
	Narrative        string    `json:"narrative"`         // Human-readable description
	RiskLevel        string    `json:"riskLevel"`
	Indicators       []string  `json:"indicators"`       // Why this is suspicious
	RecommendedAction string   `json:"recommendedAction"`
	Status           string    `json:"status"`           // "draft", "pending_review", "filed"
}

// SARGenerator creates SAR reports from analysis results
type SARGenerator struct {
	mu        sync.RWMutex
	reports   []SARReport
	nextID    int
	btcPrice  float64 // Current BTC/USD price for value estimation
}

var (
	globalSARGenerator *SARGenerator
	sarGeneratorOnce   sync.Once
)

func GetGlobalSARGenerator() *SARGenerator {
	sarGeneratorOnce.Do(func() {
		globalSARGenerator = &SARGenerator{btcPrice: 85000} // Default price
	})
	return globalSARGenerator
}

// SetBTCPrice updates the BTC/USD price for USD conversion
func (sg *SARGenerator) SetBTCPrice(price float64) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	sg.btcPrice = price
}

// GenerateSAR creates a SAR report from a suspicious transaction
func (sg *SARGenerator) GenerateSAR(tx models.Transaction, result *models.PrivacyAnalysisResult, riskProfile RiskProfile) *SARReport {
	sg.mu.Lock()
	defer sg.mu.Unlock()

	if riskProfile.RiskLevel == "low" {
		return nil // No SAR needed for low-risk
	}

	sg.nextID++

	// Collect addresses
	var addresses []string
	seen := make(map[string]bool)
	for _, in := range tx.Inputs {
		if in.Address != "" && !seen[in.Address] {
			addresses = append(addresses, in.Address)
			seen[in.Address] = true
		}
	}
	for _, out := range tx.Outputs {
		if out.Address != "" && !seen[out.Address] {
			addresses = append(addresses, out.Address)
			seen[out.Address] = true
		}
	}

	// Calculate value
	totalSats := int64(0)
	for _, out := range tx.Outputs {
		totalSats += out.Value
	}
	btcAmount := float64(totalSats) / 100000000.0

	// Build indicator list
	var indicators []string
	for _, rule := range riskProfile.TriggeredRules {
		indicators = append(indicators, rule.Name+": "+rule.Details)
	}

	// Generate narrative
	narrative := buildSARNarrative(tx, result, riskProfile, btcAmount)

	// Determine activity type (BSA codes)
	activityType := classifyBSAActivity(riskProfile)

	report := &SARReport{
		ReportID:         "SAR-" + itoa(sg.nextID),
		GeneratedAt:      time.Now(),
		ActivityType:     activityType,
		ActivityDate:     time.Now(),
		TotalAmount:      btcAmount,
		TotalAmountUSD:   btcAmount * sg.btcPrice,
		Addresses:        addresses,
		TransactionIDs:   []string{tx.Txid},
		Narrative:        narrative,
		RiskLevel:        riskProfile.RiskLevel,
		Indicators:       indicators,
		RecommendedAction: sarRecommendAction(riskProfile),
		Status:           "draft",
	}

	sg.reports = append(sg.reports, *report)
	return report
}

func buildSARNarrative(tx models.Transaction, result *models.PrivacyAnalysisResult, profile RiskProfile, btcAmount float64) string {
	var parts []string
	parts = append(parts, "Suspicious cryptocurrency transaction detected.")
	parts = append(parts, "Transaction "+tx.Txid+" involves "+itoa(len(tx.Inputs))+" inputs and "+itoa(len(tx.Outputs))+" outputs.")

	if btcAmount > 0 {
		parts = append(parts, "Approximate value: "+formatBTC(btcAmount)+" BTC.")
	}

	if profile.RiskLevel == "critical" {
		parts = append(parts, "CRITICAL RISK: Transaction flagged for immediate review.")
	}

	for cat, score := range profile.Categories {
		if score > 0 {
			parts = append(parts, "Risk category '"+string(cat)+"' triggered with severity "+formatFloat(score)+".")
		}
	}

	if result != nil && result.AnonSet > 1 {
		parts = append(parts, "CoinJoin mixing detected with anonymity set of "+itoa(result.AnonSet)+".")
	}

	return strings.Join(parts, " ")
}

func classifyBSAActivity(profile RiskProfile) string {
	for cat := range profile.Categories {
		switch cat {
		case RiskMixer:
			return "money_laundering"
		case RiskRansomware:
			return "computer_intrusion"
		case RiskSanctioned:
			return "sanctions_violation"
		case RiskScam:
			return "wire_fraud"
		case RiskDarknet:
			return "narcotics_trafficking"
		}
	}
	return "suspicious_transaction"
}

func sarRecommendAction(profile RiskProfile) string {
	switch profile.RiskLevel {
	case "critical":
		return "FILE SAR IMMEDIATELY. Notify BSA officer and freeze associated accounts."
	case "high":
		return "File SAR within 24 hours. Conduct enhanced due diligence."
	case "medium":
		return "Review and monitor. File SAR if additional indicators emerge."
	default:
		return "Continue monitoring."
	}
}

func formatBTC(btc float64) string {
	// Simple formatting without fmt import
	whole := int64(btc)
	frac := int64((btc - float64(whole)) * 100000000)
	if frac < 0 {
		frac = -frac
	}
	return itoa(int(whole)) + "." + padLeft(itoa(int(frac)), 8)
}

func formatFloat(f float64) string {
	whole := int(f)
	frac := int((f - float64(whole)) * 100)
	return itoa(whole) + "." + padLeft(itoa(frac), 2)
}

func padLeft(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

// GetReports returns generated SAR reports
func (sg *SARGenerator) GetReports(status string) []SARReport {
	sg.mu.RLock()
	defer sg.mu.RUnlock()

	if status == "" {
		return sg.reports
	}
	var filtered []SARReport
	for _, r := range sg.reports {
		if r.Status == status {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// ═══════════════════════════════════════════════════════════════════════
// Jurisdiction Risk Mapping (FATF Grey/Blacklist)
// ═══════════════════════════════════════════════════════════════════════
//
// Country-level risk scoring based on:
//   - FATF Grey List (monitored jurisdictions)
//   - FATF Blacklist (high-risk jurisdictions)
//   - EU High-Risk Third Countries
//   - US State Department lists

// JurisdictionRisk holds country-level risk data
type JurisdictionRisk struct {
	CountryCode  string  `json:"countryCode"`  // ISO 3166-1 alpha-2
	CountryName  string  `json:"countryName"`
	RiskScore    float64 `json:"riskScore"`    // 0-100
	FATFStatus   string  `json:"fatfStatus"`   // "compliant", "grey_list", "black_list"
	EUSanctioned bool    `json:"euSanctioned"`
	Reasons      []string `json:"reasons"`
}

// JurisdictionEngine provides country-level risk assessment
type JurisdictionEngine struct {
	countries map[string]JurisdictionRisk
}

var (
	globalJurisdictionEngine *JurisdictionEngine
	jurisdictionEngineOnce   sync.Once
)

func GetGlobalJurisdictionEngine() *JurisdictionEngine {
	jurisdictionEngineOnce.Do(func() {
		globalJurisdictionEngine = &JurisdictionEngine{
			countries: loadFATFData(),
		}
	})
	return globalJurisdictionEngine
}

// loadFATFData populates with current FATF grey/blacklist (as of 2025)
func loadFATFData() map[string]JurisdictionRisk {
	data := make(map[string]JurisdictionRisk)

	// FATF Blacklist (Call for Action) — as of Feb 2025
	blacklist := []struct {
		code, name string
		reasons    []string
	}{
		{"KP", "North Korea", []string{"nuclear proliferation financing", "sanctions evasion"}},
		{"IR", "Iran", []string{"terrorism financing", "money laundering deficiencies"}},
		{"MM", "Myanmar", []string{"strategic AML/CFT deficiencies"}},
	}
	for _, c := range blacklist {
		data[c.code] = JurisdictionRisk{
			CountryCode: c.code, CountryName: c.name,
			RiskScore: 95, FATFStatus: "black_list", Reasons: c.reasons,
		}
	}

	// FATF Grey List (Increased Monitoring) — as of Feb 2025
	greylist := []struct {
		code, name string
	}{
		{"BF", "Burkina Faso"}, {"CM", "Cameroon"}, {"CD", "Congo (DRC)"},
		{"HR", "Croatia"}, {"HT", "Haiti"}, {"KE", "Kenya"},
		{"ML", "Mali"}, {"MZ", "Mozambique"}, {"NA", "Namibia"},
		{"NG", "Nigeria"}, {"PH", "Philippines"}, {"SN", "Senegal"},
		{"SS", "South Sudan"}, {"SY", "Syria"}, {"TZ", "Tanzania"},
		{"VE", "Venezuela"}, {"VN", "Vietnam"}, {"YE", "Yemen"},
	}
	for _, c := range greylist {
		data[c.code] = JurisdictionRisk{
			CountryCode: c.code, CountryName: c.name,
			RiskScore: 65, FATFStatus: "grey_list",
			Reasons: []string{"strategic AML/CFT deficiencies under monitoring"},
		}
	}

	// EU High-Risk Third Countries (Commission Delegated Regulation)
	euHighRisk := []string{"AF", "BB", "BF", "KH", "KY", "CD", "GI", "HT",
		"JM", "JO", "ML", "MZ", "MM", "PA", "PH", "SN", "SS", "SY",
		"TT", "UG", "AE", "VU", "YE"}
	for _, code := range euHighRisk {
		if jr, exists := data[code]; exists {
			jr.EUSanctioned = true
			data[code] = jr
		} else {
			data[code] = JurisdictionRisk{
				CountryCode: code, RiskScore: 55,
				FATFStatus: "eu_high_risk", EUSanctioned: true,
				Reasons: []string{"EU high-risk third country"},
			}
		}
	}

	return data
}

// GetRisk returns the jurisdiction risk for a country
func (je *JurisdictionEngine) GetRisk(countryCode string) *JurisdictionRisk {
	code := strings.ToUpper(countryCode)
	if jr, ok := je.countries[code]; ok {
		return &jr
	}
	return nil
}

// IsHighRisk returns whether a country is on any high-risk list
func (je *JurisdictionEngine) IsHighRisk(countryCode string) bool {
	jr := je.GetRisk(countryCode)
	if jr == nil {
		return false
	}
	return jr.FATFStatus == "black_list" || jr.FATFStatus == "grey_list" || jr.EUSanctioned
}

// CountryCount returns the number of tracked jurisdictions
func (je *JurisdictionEngine) CountryCount() int {
	return len(je.countries)
}

// ═══════════════════════════════════════════════════════════════════════
// FATF Travel Rule Helper
// ═══════════════════════════════════════════════════════════════════════
//
// The FATF Travel Rule requires VASPs to share originator and
// beneficiary information for transfers > 1,000 USD/EUR.

// TravelRuleCheck determines if a transaction requires Travel Rule compliance
type TravelRuleCheck struct {
	RequiresCompliance bool    `json:"requiresCompliance"`
	Threshold          float64 `json:"thresholdUSD"` // 1000 USD (FATF recommendation)
	EstimatedValueUSD  float64 `json:"estimatedValueUsd"`
	Reason             string  `json:"reason"`
}

// CheckTravelRule evaluates if a tx triggers FATF Travel Rule obligations
func CheckTravelRule(tx models.Transaction, btcPriceUSD float64) TravelRuleCheck {
	totalSats := int64(0)
	for _, out := range tx.Outputs {
		totalSats += out.Value
	}
	btcAmount := float64(totalSats) / 100000000.0
	usdValue := btcAmount * btcPriceUSD

	threshold := 1000.0 // FATF recommended threshold

	if usdValue >= threshold {
		return TravelRuleCheck{
			RequiresCompliance: true,
			Threshold:          threshold,
			EstimatedValueUSD:  usdValue,
			Reason:             "transaction value exceeds FATF Travel Rule threshold",
		}
	}

	return TravelRuleCheck{
		RequiresCompliance: false,
		Threshold:          threshold,
		EstimatedValueUSD:  usdValue,
	}
}
