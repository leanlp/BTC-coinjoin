package heuristics

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Script Fingerprint Engine (Phase 18)
//
// Parses raw script data from transaction inputs and outputs to extract
// structural signatures that identify wallet software, hardware wallets,
// and non-standard constructions.
//
// Detection capabilities:
//   - Address type distribution (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
//   - Timelocks (CLTV via nLockTime, CSV via nSequence)
//   - Multisig configurations (M-of-N from redeemScript)
//   - OP_RETURN payloads (Omni Layer, OpenAssets, arbitrary data)
//   - nSequence analysis (RBF signaling, finality, timelocks)
//   - Witness version detection (v0 SegWit, v1 Taproot)
//   - Wallet family inference from combined script patterns
//
// References:
//   - BlockSci, "A Platform for Blockchain Analytics" (IEEE S&P 2020)
//   - Biryukov & Tikhomirov, "Deanonymization and linkability" (WPES 2019)

// OP codes relevant for script analysis
const (
	opReturn          = 0x6a
	opCheckMultiSig   = 0xae
	opCheckLockTime   = 0xb1
	opCheckSequence   = 0xb2
	opHash160         = 0xa9
	opEqual           = 0x87
)

// nSequence constants for RBF and timelock analysis
const (
	sequenceFinal       = uint32(0xFFFFFFFF) // nSequence = final (no RBF)
	sequenceRBFEnabled  = uint32(0xFFFFFFFD) // Standard RBF signal (BIP125)
	sequenceCSVFlag     = uint32(1 << 22)    // BIT 22: CSV relative timelock
	sequenceCSVTypeBit  = uint32(1 << 22)    // same — indicates block-based or time-based
	sequenceLockMask    = uint32(0x0000FFFF) // Lower 16 bits: timelock value
)

// AnalyzeScriptFingerprint performs deep script-level analysis on a transaction.
func AnalyzeScriptFingerprint(tx models.Transaction) models.ScriptFingerprintResult {
	result := models.ScriptFingerprintResult{
		InputScriptTypes:  make(map[string]int),
		OutputScriptTypes: make(map[string]int),
	}

	// 1. Analyze input scripts
	hasECDSA := false
	hasSchnorr := false

	for _, in := range tx.Inputs {
		addrType := classifyScriptAddressType(in.Address)
		result.InputScriptTypes[addrType]++

		// Detect witness version from address prefix
		if strings.HasPrefix(in.Address, "bc1p") {
			hasSchnorr = true
			addUniqueInt(&result.WitnessVersions, 1)
		} else if strings.HasPrefix(in.Address, "bc1q") {
			hasECDSA = true
			addUniqueInt(&result.WitnessVersions, 0)
		} else {
			hasECDSA = true
		}

		// Analyze ScriptSig for opcode patterns
		if in.ScriptSig != "" {
			analyzeScriptSigOpcodes(in.ScriptSig, &result)
		}
	}

	// 2. Analyze output scripts
	for _, out := range tx.Outputs {
		addrType := classifyScriptAddressType(out.Address)
		result.OutputScriptTypes[addrType]++

		// Detect OP_RETURN payloads from ScriptPubKey
		if out.ScriptPubKey != "" {
			scriptBytes, err := hex.DecodeString(out.ScriptPubKey)
			if err == nil && len(scriptBytes) > 0 && scriptBytes[0] == opReturn {
				if len(scriptBytes) > 1 {
					result.OPReturnPayloads = append(result.OPReturnPayloads, hex.EncodeToString(scriptBytes[1:]))
				}
			}
		}
	}

	// 3. Determine signature scheme
	switch {
	case hasSchnorr && hasECDSA:
		result.SignatureScheme = "mixed"
	case hasSchnorr:
		result.SignatureScheme = "schnorr"
	default:
		result.SignatureScheme = "ecdsa"
	}

	// 4. Analyze nSequence across all inputs for RBF and timelock signals
	result.NSequenceAnalysis = analyzeNSequence(tx.Inputs)

	// 5. Analyze timelock from nLockTime
	if tx.LockTime > 0 {
		result.HasTimeLock = true
		if tx.LockTime < 500_000_000 {
			result.TimeLockType = "cltv"
			result.TimeLockValue = tx.LockTime
		} else {
			result.TimeLockType = "cltv" // Unix timestamp-based CLTV
			result.TimeLockValue = tx.LockTime
		}
	}

	// 6. Infer wallet signature from combined signals
	result.WalletSignature = inferWalletFromScript(tx, result)

	return result
}

// classifyScriptAddressType returns the address type string for script analysis.
func classifyScriptAddressType(addr string) string {
	switch {
	case strings.HasPrefix(addr, "bc1p"):
		return "p2tr"
	case strings.HasPrefix(addr, "bc1q"):
		if len(addr) == 42 {
			return "p2wpkh"
		}
		return "p2wsh"
	case strings.HasPrefix(addr, "3"):
		return "p2sh"
	case strings.HasPrefix(addr, "1"):
		return "p2pkh"
	default:
		return "unknown"
	}
}

// analyzeScriptSigOpcodes parses hex-encoded scriptSig for multisig patterns.
func analyzeScriptSigOpcodes(scriptHex string, result *models.ScriptFingerprintResult) {
	scriptBytes, err := hex.DecodeString(scriptHex)
	if err != nil || len(scriptBytes) < 2 {
		return
	}

	// Look for OP_CHECKMULTISIG (0xAE) in the script
	for i, b := range scriptBytes {
		if b == opCheckMultiSig && i >= 2 {
			// Extract M and N from the opcodes before OP_CHECKMULTISIG
			// Standard encoding: OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
			n := int(scriptBytes[i-1])
			// Walk backwards to find M
			if n >= 1 && n <= 15 {
				// Count pubkeys between M and N
				m := findMultisigM(scriptBytes[:i], n)
				if m > 0 && m <= n {
					config := fmt.Sprintf("%d-of-%d", m, n)
					result.MultisigConfigs = appendUniqueStr(result.MultisigConfigs, config)
				}
			}
		}
	}

	if len(result.MultisigConfigs) > 0 {
		result.NonStandardScripts++
	}
}

// findMultisigM attempts to extract the M value from a multisig script fragment.
func findMultisigM(scriptPrefix []byte, n int) int {
	if len(scriptPrefix) < 1 {
		return 0
	}
	// In standard multisig, M is the first small integer opcode (OP_1 through OP_16)
	// OP_1 = 0x51, OP_2 = 0x52, ... OP_16 = 0x60
	for _, b := range scriptPrefix {
		if b >= 0x51 && b <= 0x60 {
			m := int(b) - 0x50
			if m >= 1 && m <= n {
				return m
			}
		}
	}
	return 0
}

// analyzeNSequence classifies the nSequence behavior across all inputs.
func analyzeNSequence(inputs []models.TxIn) string {
	allFinal := true
	anyRBF := false
	anyCSV := false

	for _, in := range inputs {
		seq := in.Sequence
		if seq == sequenceFinal {
			continue
		}
		allFinal = false

		// BIP-125 RBF: any sequence < 0xFFFFFFFE signals opt-in RBF
		if seq < sequenceFinal-1 { // < 0xFFFFFFFE
			anyRBF = true
		}

		// BIP-68 CSV: bit 31 must be UNSET for relative timelock enforcement.
		// If bit 31 is set, sequence number is NOT interpreted as a relative lock-time.
		bit31Set := seq&(1<<31) != 0
		if !bit31Set && seq != 0 {
			// Lower 16 bits encode the lock value; bit 22 determines blocks vs time
			lockValue := seq & sequenceLockMask
			if lockValue > 0 {
				anyCSV = true
			}
		}
	}

	switch {
	case allFinal:
		return "final"
	case anyCSV:
		return "timelock"
	case anyRBF:
		return "rbf-enabled"
	default:
		return "mixed"
	}
}

// inferWalletFromScript uses combined script signals to identify wallet software.
func inferWalletFromScript(tx models.Transaction, fp models.ScriptFingerprintResult) string {
	// Bitcoin Core: native segwit, RBF enabled, anti-fee-sniping via nLockTime
	if fp.InputScriptTypes["p2wpkh"] > 0 &&
		fp.NSequenceAnalysis == "rbf-enabled" &&
		tx.LockTime > 0 && tx.LockTime < 900_000 {
		return "bitcoin-core"
	}

	// Electrum: native segwit, RBF enabled, but no anti-fee-sniping
	if fp.InputScriptTypes["p2wpkh"] > 0 &&
		fp.NSequenceAnalysis == "rbf-enabled" &&
		tx.LockTime == 0 {
		return "electrum"
	}

	// Ledger: typically P2SH-wrapped segwit (address prefix "3")
	if fp.InputScriptTypes["p2sh"] > 0 &&
		fp.InputScriptTypes["p2wpkh"] == 0 &&
		fp.NSequenceAnalysis == "final" {
		return "ledger"
	}

	// Trezor: mix of P2SH and native segwit, final sequences
	if fp.InputScriptTypes["p2sh"] > 0 &&
		fp.InputScriptTypes["p2wpkh"] > 0 &&
		fp.NSequenceAnalysis == "final" {
		return "trezor"
	}

	// Taproot wallets (P2TR inputs or outputs)
	if fp.InputScriptTypes["p2tr"] > 0 {
		return "taproot-wallet"
	}

	return "unknown"
}

// addUniqueInt appends a value to a slice if not already present.
func addUniqueInt(slice *[]int, val int) {
	for _, v := range *slice {
		if v == val {
			return
		}
	}
	*slice = append(*slice, val)
}

// appendUniqueStr appends a string to a slice if not already present.
func appendUniqueStr(slice []string, val string) []string {
	for _, v := range slice {
		if v == val {
			return slice
		}
	}
	return append(slice, val)
}
