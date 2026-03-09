package heuristics

import (
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Compound Wallet Fingerprint Engine
//
// Combines nVersion, nLockTime, and nSequence into a single compound
// fingerprint that dramatically improves wallet software attribution.
//
// Each wallet has a unique combination of these three fields:
//
// | Wallet        | nVersion | nLockTime     | nSequence    |
// |---------------|----------|---------------|--------------|
// | Bitcoin Core  | 2        | current_height| 0xfffffffe   |
// | Electrum      | 2        | current_height| 0xfffffffe   |
// | Ledger Live   | 1        | 0             | 0xffffffff   |
// | Trezor        | 1        | 0             | 0xffffffff   |
// | Wasabi 2.0    | 1        | current_height| 0xfffffffe   |
// | Samourai      | 2        | current_height| 0xfffffffe   |
// | Sparrow       | 2        | current_height| 0xfffffffe   |
// | BlueWallet    | 2        | 0             | 0xfffffffe   |
//
// By using ALL THREE fields simultaneously, we can distinguish wallets
// that look identical when checking individual fields.
//
// References:
//   - 0xB10C, "Bitcoin Transaction Monitor" (2024)
//   - ishaana.com, "Bitcoin Wallet Fingerprinting" (2024)

// CompoundFingerprint captures the 3-field wallet signature
type CompoundFingerprint struct {
	NVersion       int32  `json:"nVersion"`
	NLockTimeType  string `json:"nLockTimeType"`  // "zero"/"height"/"timestamp"
	NSequenceType  string `json:"nSequenceType"`  // "final"/"rbf_signal"/"relative_timelock"
	HasRBF         bool   `json:"hasRBF"`
	HasRelTimeLock bool   `json:"hasRelTimeLock"`
}

// WalletMatch represents a wallet identification result
type WalletMatch struct {
	WalletName  string  `json:"walletName"`
	Confidence  float64 `json:"confidence"`
	MatchedOn   string  `json:"matchedOn"` // Which fields matched
}

// knownCompoundFingerprints maps (nVersion, nLockTimeType, nSequenceType) → wallet candidates
type walletFP struct {
	name       string
	nVersion   int32
	lockType   string
	seqType    string
	confidence float64
}

var knownFingerprints = []walletFP{
	// nVersion=2, nLockTime=height, nSequence=RBF
	{"bitcoin-core", 2, "height", "rbf_signal", 0.40},
	{"electrum", 2, "height", "rbf_signal", 0.35},
	{"samourai", 2, "height", "rbf_signal", 0.15},
	{"sparrow", 2, "height", "rbf_signal", 0.10},

	// nVersion=1, nLockTime=0, nSequence=final
	{"ledger", 1, "zero", "final", 0.50},
	{"trezor", 1, "zero", "final", 0.45},

	// nVersion=1, nLockTime=height, nSequence=RBF (Wasabi signature!)
	{"wasabi", 1, "height", "rbf_signal", 0.85},

	// nVersion=2, nLockTime=0, nSequence=RBF (BlueWallet signature!)
	{"bluewallet", 2, "zero", "rbf_signal", 0.80},

	// nVersion=2, nLockTime=0, nSequence=final
	{"exodus", 2, "zero", "final", 0.60},

	// nVersion=1, nLockTime=0, nSequence=RBF
	{"coinbase-wallet", 1, "zero", "rbf_signal", 0.55},
}

// AnalyzeCompoundFingerprint extracts the compound wallet fingerprint
// from a transaction and returns the best wallet match.
func AnalyzeCompoundFingerprint(tx models.Transaction) []WalletMatch {
	fp := extractFingerprint(tx)

	var matches []WalletMatch

	for _, known := range knownFingerprints {
		if known.nVersion == fp.NVersion &&
			known.lockType == fp.NLockTimeType &&
			known.seqType == fp.NSequenceType {
			matches = append(matches, WalletMatch{
				WalletName: known.name,
				Confidence: known.confidence,
				MatchedOn:  "nVersion+nLockTime+nSequence",
			})
		}
	}

	// If no exact match, try partial matches (weaker)
	if len(matches) == 0 {
		for _, known := range knownFingerprints {
			score := 0.0
			matched := ""

			if known.nVersion == fp.NVersion {
				score += 0.15
				matched += "nVersion+"
			}
			if known.lockType == fp.NLockTimeType {
				score += 0.10
				matched += "nLockTime+"
			}
			if known.seqType == fp.NSequenceType {
				score += 0.10
				matched += "nSequence+"
			}

			if score > 0.20 {
				matches = append(matches, WalletMatch{
					WalletName: known.name,
					Confidence: score,
					MatchedOn:  matched,
				})
			}
		}
	}

	return matches
}

// GetBestWalletMatch returns the highest-confidence wallet match
func GetBestWalletMatch(tx models.Transaction) (string, float64) {
	matches := AnalyzeCompoundFingerprint(tx)
	if len(matches) == 0 {
		return "unknown", 0
	}

	best := matches[0]
	for _, m := range matches[1:] {
		if m.Confidence > best.Confidence {
			best = m
		}
	}

	return best.WalletName, best.Confidence
}

func extractFingerprint(tx models.Transaction) CompoundFingerprint {
	fp := CompoundFingerprint{
		NVersion: tx.Version,
	}

	// Classify nLockTime
	switch {
	case tx.LockTime == 0:
		fp.NLockTimeType = "zero"
	case tx.LockTime < 500000000: // Block height
		fp.NLockTimeType = "height"
	default: // Unix timestamp
		fp.NLockTimeType = "timestamp"
	}

	// Classify nSequence (check first input as representative)
	if len(tx.Inputs) > 0 {
		seq := tx.Inputs[0].Sequence

		switch {
		case seq == 0xffffffff:
			fp.NSequenceType = "final"
			fp.HasRBF = false
		case seq < 0xfffffffe:
			// Check for relative timelock (BIP68)
			if seq&(1<<31) == 0 { // Bit 31 not set = relative timelock active
				fp.NSequenceType = "relative_timelock"
				fp.HasRelTimeLock = true
				fp.HasRBF = true // Relative timelocks also signal RBF
			} else {
				fp.NSequenceType = "rbf_signal"
				fp.HasRBF = true
			}
		default: // 0xfffffffe
			fp.NSequenceType = "rbf_signal"
			fp.HasRBF = true
		}
	}

	return fp
}
