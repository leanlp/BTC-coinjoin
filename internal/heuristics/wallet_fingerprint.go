package heuristics

import (
	"sort"
	"strings"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// WalletFingerprint captures the structural signals that identify
// which wallet software created a transaction. These signals are
// used by Chainalysis Reactor and Elliptic Navigator to attribute
// transactions to specific wallet implementations.
type WalletFingerprint struct {
	WalletFamily      string  `json:"walletFamily"` // "bitcoin_core", "electrum", "wasabi", "samourai", etc.
	Confidence        float64 `json:"confidence"`
	IsBIP69           bool    `json:"isBip69"`           // Lexicographic input/output ordering
	InputScriptTypes  string  `json:"inputScriptTypes"`  // Dominant input script type
	OutputScriptTypes string  `json:"outputScriptTypes"` // Dominant output script type
	HasMixedTypes     bool    `json:"hasMixedTypes"`     // Mixed script types in a single tx
	IsConsolidation   bool    `json:"isConsolidation"`   // Many inputs → 1 output (UTXO cleanup)
	IsBatched         bool    `json:"isBatched"`         // 1 input → many outputs (exchange payout)
}

// WhirlpoolPoolInfo identifies the specific Whirlpool pool denomination
type WhirlpoolPoolInfo struct {
	PoolID          string `json:"poolId"` // "0.5btc", "0.05btc", "0.01btc", "0.001btc"
	DenomSats       int64  `json:"denomSats"`
	NumParticipants int    `json:"numParticipants"`
	IsSurge         bool   `json:"isSurge"`        // Surge cycle (>5 participants)
	CoordinatorFee  int64  `json:"coordinatorFee"` // Detected SC fee output
}

// Whirlpool standard pool denominations (in satoshis)
var whirlpoolPools = map[string]int64{
	"0.5btc":   50000000, // 0.5 BTC
	"0.05btc":  5000000,  // 0.05 BTC
	"0.01btc":  1000000,  // 0.01 BTC
	"0.001btc": 100000,   // 0.001 BTC
}

// DetectWalletFingerprint analyzes structural transaction properties to
// identify which wallet software likely created it.
//
// Methodology based on:
//   - Erdin et al. "How to Not Get Caught: Analyzing Current and Proposed
//     Anti-Censorship Techniques in Bitcoin" (2022)
//   - Möser & Narayanan "Obfuscation in Bitcoin: Techniques and Politics" (2017)
//   - Ficsór et al. "WabiSabi: Centrally Coordinated CoinJoins with Variable
//     Denomination Outputs" (2021)
func DetectWalletFingerprint(tx models.Transaction) WalletFingerprint {
	fp := WalletFingerprint{}

	// ─── 1. BIP69 Ordering Detection ─────────────────────────────────
	// BIP69 specifies lexicographic ordering of inputs (by txid:vout)
	// and outputs (by value, then scriptPubKey).
	// Wallets that implement BIP69: Electrum, some Bitcoin Core versions,
	// Samourai Wallet (Whirlpool uses BIP69).
	fp.IsBIP69 = checkBIP69Ordering(tx)

	// ─── 2. Script Type Analysis ─────────────────────────────────────
	inputTypes := make(map[string]int)
	for _, in := range tx.Inputs {
		t := classifyAddressType(in.Address)
		if t != "" {
			inputTypes[t]++
		}
	}
	outputTypes := make(map[string]int)
	for _, out := range tx.Outputs {
		t := classifyAddressType(out.Address)
		if t != "" {
			outputTypes[t]++
		}
	}

	// Dominant types
	fp.InputScriptTypes = dominantType(inputTypes)
	fp.OutputScriptTypes = dominantType(outputTypes)
	fp.HasMixedTypes = len(inputTypes) > 1 || len(outputTypes) > 1

	// ─── 3. Transaction Pattern Classification ───────────────────────
	// Consolidation: many inputs, 1 output (UTXO hygiene)
	if len(tx.Inputs) >= 5 && len(tx.Outputs) == 1 {
		fp.IsConsolidation = true
	}
	// Batched payment: 1 input, many outputs (exchange payout)
	if len(tx.Inputs) == 1 && len(tx.Outputs) >= 5 {
		fp.IsBatched = true
	}

	// ─── 4. Wallet Family Attribution ────────────────────────────────
	// Score-based attribution using structural signals
	scores := map[string]float64{
		"bitcoin_core": 0,
		"electrum":     0,
		"wasabi":       0,
		"samourai":     0,
		"sparrow":      0,
		"exchange":     0,
	}

	// Bitcoin Core: Native SegWit (bech32) inputs, no BIP69 (random ordering since v0.19)
	if fp.InputScriptTypes == "p2wpkh" && !fp.IsBIP69 {
		scores["bitcoin_core"] += 0.3
	}
	if fp.InputScriptTypes == "p2wpkh" && fp.OutputScriptTypes == "p2wpkh" {
		scores["bitcoin_core"] += 0.2
	}

	// Electrum: Native SegWit, implements BIP69
	if fp.IsBIP69 && fp.InputScriptTypes == "p2wpkh" {
		scores["electrum"] += 0.4
	}

	// Samourai/Whirlpool: BIP69, Taproot or SegWit, specific pool topology
	if fp.IsBIP69 {
		scores["samourai"] += 0.2
	}

	// Wasabi: Mixed output types, many equal-denomination outputs
	if fp.HasMixedTypes && len(tx.Outputs) >= 10 {
		scores["wasabi"] += 0.3
	}

	// Sparrow: Taproot-first wallet
	if fp.InputScriptTypes == "p2tr" {
		scores["sparrow"] += 0.3
	}
	if fp.InputScriptTypes == "p2tr" && fp.OutputScriptTypes == "p2tr" {
		scores["sparrow"] += 0.2
	}

	// Exchange: Batched payouts with mixed output types
	if fp.IsBatched {
		scores["exchange"] += 0.5
	}
	if fp.IsConsolidation {
		scores["exchange"] += 0.3
	}

	// Legacy P2PKH inputs suggest old wallets
	if fp.InputScriptTypes == "p2pkh" {
		scores["bitcoin_core"] += 0.1 // Could also be old Electrum
	}

	// P2SH-P2WPKH (wrapped SegWit) — common in Trezor, Ledger
	if fp.InputScriptTypes == "p2sh" {
		scores["bitcoin_core"] += 0.05 // generic
	}

	// ─── 5. nLockTime & nSequence Analysis (Phase 13) ─────────────────
	// Bitcoin Core: sets nLockTime = current_block_height (anti-fee-sniping)
	// Electrum: nLockTime = 0 but signals RBF via nSequence
	// Samourai: nLockTime = 0, no RBF, version 1

	// nLockTime signal
	if tx.LockTime > 0 && tx.LockTime < 500_000_000 {
		// Block height-based locktime = anti-fee-sniping (Bitcoin Core)
		scores["bitcoin_core"] += 0.25
	}
	if tx.LockTime == 0 {
		// Most non-Core wallets use nLockTime = 0
		scores["electrum"] += 0.1
		scores["samourai"] += 0.1
	}

	// RBF signaling via nSequence (BIP125)
	hasRBF := false
	for _, in := range tx.Inputs {
		if in.Sequence > 0 && in.Sequence < 0xFFFFFFFE {
			hasRBF = true
			break
		}
	}
	if hasRBF {
		// Electrum always signals RBF, Core does randomly
		scores["electrum"] += 0.15
		scores["bitcoin_core"] += 0.1
	} else {
		// No RBF = Samourai, old wallets, or privacy-focused wallets
		scores["samourai"] += 0.1
	}

	// Version 2 with relative timelocks (BIP68/CSV)
	if tx.Version == 2 {
		scores["bitcoin_core"] += 0.05
		scores["electrum"] += 0.05
	}
	if tx.Version == 1 {
		scores["samourai"] += 0.1
	}

	// Find highest scoring wallet
	bestWallet := "unknown"
	bestScore := 0.0
	for wallet, score := range scores {
		if score > bestScore {
			bestScore = score
			bestWallet = wallet
		}
	}

	if bestScore >= 0.2 {
		fp.WalletFamily = bestWallet
		fp.Confidence = bestScore
	} else {
		fp.WalletFamily = "unknown"
		fp.Confidence = 0
	}

	return fp
}

// IdentifyWhirlpoolPool detects the specific Whirlpool pool denomination
// for a transaction that has already been flagged as FlagIsWhirlpoolStruct.
//
// Pool identification methodology:
//   - Match the dominant equal-value output against known pool denominations
//   - Allow ±1% tolerance for coordinator fee variations
//   - Identify Surge cycles (>5 participants)
//   - Detect the coordinator fee output (Samourai SC fee)
func IdentifyWhirlpoolPool(tx models.Transaction) *WhirlpoolPoolInfo {
	if len(tx.Outputs) < 5 {
		return nil
	}

	// Find the dominant output value (most outputs with identical value)
	valueCounts := make(map[int64]int)
	for _, out := range tx.Outputs {
		if out.Value > 0 {
			valueCounts[out.Value]++
		}
	}

	dominantValue := int64(0)
	dominantCount := 0
	for val, count := range valueCounts {
		if count > dominantCount {
			dominantValue = val
			dominantCount = count
		}
	}

	if dominantCount < 5 {
		return nil // Not enough equal outputs for a Whirlpool mix
	}

	// Match against known pool denominations with ±1% tolerance
	for poolID, poolDenom := range whirlpoolPools {
		tolerance := poolDenom / 100 // 1%
		if dominantValue >= poolDenom-tolerance && dominantValue <= poolDenom+tolerance {
			info := &WhirlpoolPoolInfo{
				PoolID:          poolID,
				DenomSats:       dominantValue,
				NumParticipants: dominantCount,
				IsSurge:         dominantCount > 5,
			}

			// Detect coordinator fee output (typically much smaller than pool denom)
			for _, out := range tx.Outputs {
				if out.Value != dominantValue && out.Value > 0 && out.Value < poolDenom/10 {
					info.CoordinatorFee = out.Value
					break
				}
			}

			return info
		}
	}

	return nil
}

// checkBIP69Ordering verifies if inputs and outputs follow BIP69 lexicographic ordering.
// BIP69: Inputs sorted by (txid ASC, vout ASC), outputs sorted by (value ASC, scriptPubKey ASC).
func checkBIP69Ordering(tx models.Transaction) bool {
	if len(tx.Inputs) <= 1 && len(tx.Outputs) <= 1 {
		return true // Trivially ordered
	}

	// Check input ordering: sorted by txid (ascending), then vout (ascending)
	inputsSorted := true
	for i := 1; i < len(tx.Inputs); i++ {
		prev := tx.Inputs[i-1]
		curr := tx.Inputs[i]
		if prev.Txid > curr.Txid || (prev.Txid == curr.Txid && prev.Vout > curr.Vout) {
			inputsSorted = false
			break
		}
	}

	// Check output ordering: sorted by value (ascending), then scriptPubKey (ascending)
	outputsSorted := true
	for i := 1; i < len(tx.Outputs); i++ {
		prev := tx.Outputs[i-1]
		curr := tx.Outputs[i]
		if prev.Value > curr.Value || (prev.Value == curr.Value && prev.ScriptPubKey > curr.ScriptPubKey) {
			outputsSorted = false
			break
		}
	}

	return inputsSorted && outputsSorted
}

// dominantType returns the most common address type from a frequency map
func dominantType(types map[string]int) string {
	best := ""
	bestCount := 0
	for t, c := range types {
		if c > bestCount {
			best = t
			bestCount = c
		}
	}
	return best
}

// detectAddressType is a helper used by watchlist.go and other modules.
// Reuses classifyAddressType from change_detection.go for consistency.
func detectAddressType(addr string) string {
	t := classifyAddressType(addr)
	switch t {
	case "p2tr":
		return "taproot"
	case "p2wpkh":
		return "segwit"
	case "p2sh":
		return "p2sh-segwit"
	case "p2pkh":
		return "legacy"
	default:
		return "unknown"
	}
}

// SortOutputsByValue sorts outputs by value for BIP69 compliance checking.
// This is exported for use by the test suite.
func SortOutputsByValue(outputs []models.TxOut) []models.TxOut {
	sorted := make([]models.TxOut, len(outputs))
	copy(sorted, outputs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Value == sorted[j].Value {
			return strings.Compare(sorted[i].ScriptPubKey, sorted[j].ScriptPubKey) < 0
		}
		return sorted[i].Value < sorted[j].Value
	})
	return sorted
}
