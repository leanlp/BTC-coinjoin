package heuristics

// AlertLevelForRole maps investigation/watchlist roles to alert severity.
func AlertLevelForRole(role string) string {
	switch role {
	case "theft", "sanctioned":
		return "critical"
	case "exchange", "suspect":
		return "high"
	case "service":
		return "medium"
	default:
		return "low"
	}
}

// TaintLevelForRole maps investigation/watchlist roles to baseline taint level.
func TaintLevelForRole(role string) float64 {
	switch role {
	case "theft", "sanctioned":
		return 1.0
	case "suspect":
		return 0.7
	case "service":
		return 0.4
	default:
		return 0.2
	}
}
