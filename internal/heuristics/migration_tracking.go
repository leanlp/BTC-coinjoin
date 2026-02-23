package heuristics

import (
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Address Type Migration Tracking
//
// When entities migrate from legacy→SegWit→Taproot, the address format
// changes but the entity is the same. Detecting this migration provides:
//
//   1. Entity continuity: same entity, different address format
//   2. Technology adoption: which wallets have upgraded
//   3. Privacy assessment: Taproot adoption improves privacy
//
// Migration signals:
//   - Mixed input types: legacy + segwit in same tx = transitioning entity
//   - Change output format: change goes to newer format = wallet upgrade
//   - Temporal trend: older UTXOs are legacy, newer are segwit/taproot
//
// References:
//   - Bitcoin Optech, "Bech32 Adoption" tracking (2019-present)
//   - Pérez-Solà et al., "Analysis of Bitcoin's Full Transaction Graph" (2019)

// MigrationResult holds address type migration analysis
type MigrationResult struct {
	LegacyRatio    float64 `json:"legacyRatio"`    // Fraction of inputs from legacy addresses
	SegWitRatio    float64 `json:"segwitRatio"`    // Fraction from native SegWit (bech32)
	TaprootRatio   float64 `json:"taprootRatio"`   // Fraction from Taproot (bech32m)
	P2SHRatio      float64 `json:"p2shRatio"`      // Fraction from P2SH-SegWit (wrapped)
	MigrationStage string  `json:"migrationStage"` // "legacy"/"transitioning"/"native-segwit"/"taproot-adopter"
	HasMixedTypes  bool    `json:"hasMixedTypes"`  // Multiple address types in inputs
	ChangeFormat   string  `json:"changeFormat"`   // Address type used for change output
}

// DetectAddressMigration analyzes the address format distribution
// across transaction inputs and outputs to detect migration patterns.
func DetectAddressMigration(tx models.Transaction) MigrationResult {
	result := MigrationResult{
		MigrationStage: "unknown",
	}

	if len(tx.Inputs) == 0 {
		return result
	}

	// Count address types in inputs
	typeCounts := map[string]int{
		"legacy":      0,
		"segwit":      0,
		"taproot":     0,
		"p2sh-segwit": 0,
		"unknown":     0,
	}

	for _, in := range tx.Inputs {
		addrType := detectAddressType(in.Address)
		typeCounts[addrType]++
	}

	totalInputs := float64(len(tx.Inputs))
	result.LegacyRatio = float64(typeCounts["legacy"]) / totalInputs
	result.SegWitRatio = float64(typeCounts["segwit"]) / totalInputs
	result.TaprootRatio = float64(typeCounts["taproot"]) / totalInputs
	result.P2SHRatio = float64(typeCounts["p2sh-segwit"]) / totalInputs

	// Check for mixed types (sign of migration)
	nonZeroTypes := 0
	for addrType, count := range typeCounts {
		if addrType != "unknown" && count > 0 {
			nonZeroTypes++
		}
	}
	result.HasMixedTypes = nonZeroTypes > 1

	// Classify migration stage
	result.MigrationStage = classifyMigrationStage(result)

	// Detect change output format (indicates current wallet default)
	result.ChangeFormat = detectChangeFormat(tx)

	return result
}

// classifyMigrationStage determines where the entity is in the
// adoption curve based on address type distribution.
func classifyMigrationStage(m MigrationResult) string {
	switch {
	case m.TaprootRatio > 0.5:
		return "taproot-adopter" // Majority Taproot
	case m.TaprootRatio > 0 && (m.SegWitRatio > 0 || m.LegacyRatio > 0):
		return "transitioning" // Mixed with Taproot
	case m.SegWitRatio > 0.5:
		return "native-segwit" // Majority native SegWit
	case m.SegWitRatio > 0 && m.LegacyRatio > 0:
		return "transitioning" // Legacy + SegWit mix
	case m.P2SHRatio > 0.5:
		return "wrapped-segwit" // Using P2SH-wrapped SegWit
	case m.LegacyRatio > 0.5:
		return "legacy" // Still on legacy addresses
	default:
		return "unknown"
	}
}

// detectChangeFormat identifies the address type used for the change output.
// The change output format reveals the wallet's current default format.
func detectChangeFormat(tx models.Transaction) string {
	if len(tx.Outputs) < 2 {
		return "unknown"
	}

	// Heuristic: the smallest output in a non-CoinJoin tx is often change
	// (though this is imperfect)
	smallestIdx := 0
	smallestVal := tx.Outputs[0].Value
	for i, out := range tx.Outputs {
		if out.Value < smallestVal && out.Value > 0 {
			smallestVal = out.Value
			smallestIdx = i
		}
	}

	return detectAddressType(tx.Outputs[smallestIdx].Address)
}

// ComputeFormatDistribution returns a summary of address format
// usage across all inputs and outputs for visualization.
func ComputeFormatDistribution(tx models.Transaction) map[string]int {
	dist := map[string]int{
		"legacy":      0,
		"segwit":      0,
		"taproot":     0,
		"p2sh-segwit": 0,
	}

	for _, in := range tx.Inputs {
		addrType := detectAddressType(in.Address)
		if _, ok := dist[addrType]; ok {
			dist[addrType]++
		}
	}

	for _, out := range tx.Outputs {
		addrType := detectAddressType(out.Address)
		if _, ok := dist[addrType]; ok {
			dist[addrType]++
		}
	}

	return dist
}
