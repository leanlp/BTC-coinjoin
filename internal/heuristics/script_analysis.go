package heuristics

import (
	"strings"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Script Template Deep Inspection Module
//
// Goes beyond address prefix to analyze the internal structure of
// scripts and witnesses. This reveals:
//
//   - Multisig patterns: 2-of-3 (standard), 3-of-5 (corporate custody)
//   - HTLC timelocks: Lightning Network channel opens/closes
//   - OP_RETURN payloads: Omni Layer, OpenAssets, timestamp proofs
//   - Tapscript complexity: key-path vs script-path spending
//   - Witness version: v0 (SegWit), v1 (Taproot), legacy
//
// Script patterns are the deepest layer of wallet fingerprinting.
// Even wallets that randomize everything else (ordering, fee, locktime)
// cannot hide their script template structure.
//
// References:
//   - Harding (2019), "Bitcoin Script History" (Bitcoin Optech)
//   - Pérez-Solà et al., "The Bitcoin P2P Network" (FC 2019)
//   - Towns (2021), "BIP341/342: Taproot/Tapscript Spending Rules"

// AnalyzeScriptTemplates performs deep inspection of all transaction scripts
func AnalyzeScriptTemplates(tx models.Transaction) models.ScriptAnalysis {
	result := models.ScriptAnalysis{
		DominantWitness: "legacy",
	}

	// 1. Analyze input scripts for multisig patterns
	for _, in := range tx.Inputs {
		// Check ScriptSig for P2SH multisig redeem script patterns
		if isMultisigScript(in.ScriptSig) {
			result.HasMultisig = true
			m, n := extractMultisigMN(in.ScriptSig)
			if m > 0 && n > 0 {
				result.MultisigM = m
				result.MultisigN = n
			}
		}

		// Check for HTLC patterns in ScriptSig
		if isHTLCScript(in.ScriptSig) {
			result.HasHTLC = true
		}
	}

	// 2. Analyze output scripts for OP_RETURN and other patterns
	for _, out := range tx.Outputs {
		if isOPReturn(out.ScriptPubKey) {
			result.HasOPReturn = true
			result.OPReturnProtocol = classifyOPReturn(out.ScriptPubKey)
			result.OPReturnSize = estimateOPReturnSize(out.ScriptPubKey)
		}

		// Check for multisig in output scripts (bare multisig)
		if isMultisigScript(out.ScriptPubKey) {
			result.HasMultisig = true
			m, n := extractMultisigMN(out.ScriptPubKey)
			if m > 0 && n > 0 {
				result.MultisigM = m
				result.MultisigN = n
			}
		}
	}

	// 3. Determine dominant witness version from addresses
	result.DominantWitness = detectDominantWitnessVersion(tx)

	// 4. Estimate tapscript complexity
	result.TapscriptDepth = estimateTapscriptDepth(tx)

	return result
}

// isMultisigScript checks if a script contains multisig opcodes.
// Pattern: OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
// In hex: 52..52ae (2-of-2) or 52..53ae (2-of-3)
func isMultisigScript(script string) bool {
	if len(script) < 10 {
		return false
	}
	lower := strings.ToLower(script)
	// OP_CHECKMULTISIG = 0xae, OP_CHECKMULTISIGVERIFY = 0xaf
	return strings.Contains(lower, "ae") && (strings.HasPrefix(lower, "51") ||
		strings.HasPrefix(lower, "52") || strings.HasPrefix(lower, "53") ||
		strings.HasPrefix(lower, "54") || strings.HasPrefix(lower, "55"))
}

// extractMultisigMN parses the M-of-N values from a multisig script
// OP_1=0x51, OP_2=0x52, ..., OP_16=0x60
func extractMultisigMN(script string) (int, int) {
	if len(script) < 4 {
		return 0, 0
	}
	lower := strings.ToLower(script)

	// First byte: OP_M (0x51-0x60 = OP_1 through OP_16)
	mByte := lower[:2]
	m := parseOpN(mByte)

	// Find OP_CHECKMULTISIG (0xae) and get the byte before it for N
	aeIdx := strings.LastIndex(lower, "ae")
	if aeIdx < 2 {
		return 0, 0
	}
	nByte := lower[aeIdx-2 : aeIdx]
	n := parseOpN(nByte)

	if m > 0 && n > 0 && m <= n {
		return m, n
	}
	return 0, 0
}

// parseOpN converts OP_N hex to integer (0x51=1, 0x52=2, ..., 0x60=16)
func parseOpN(hex string) int {
	switch hex {
	case "51":
		return 1
	case "52":
		return 2
	case "53":
		return 3
	case "54":
		return 4
	case "55":
		return 5
	case "56":
		return 6
	case "57":
		return 7
	case "58":
		return 8
	case "59":
		return 9
	case "5a":
		return 10
	case "5b":
		return 11
	case "5c":
		return 12
	case "5d":
		return 13
	case "5e":
		return 14
	case "5f":
		return 15
	case "60":
		return 16
	default:
		return 0
	}
}

// isHTLCScript checks for Hash Timelock Contract patterns.
// HTLC scripts contain OP_IF ... OP_HASH160 <hash> OP_EQUALVERIFY ...
// OP_ELSE ... OP_CHECKLOCKTIMEVERIFY ... OP_ENDIF
func isHTLCScript(script string) bool {
	lower := strings.ToLower(script)
	// Key opcodes: OP_IF(63), OP_HASH160(a9), OP_CHECKLOCKTIMEVERIFY(b1) or OP_CSV(b2)
	hasIf := strings.Contains(lower, "63")
	hasHash := strings.Contains(lower, "a9")
	hasTimelock := strings.Contains(lower, "b1") || strings.Contains(lower, "b2")
	return hasIf && hasHash && hasTimelock
}

// isOPReturn checks if a scriptPubKey starts with OP_RETURN (0x6a)
func isOPReturn(scriptPubKey string) bool {
	return strings.HasPrefix(strings.ToLower(scriptPubKey), "6a")
}

// classifyOPReturn identifies the protocol using OP_RETURN data
func classifyOPReturn(scriptPubKey string) string {
	lower := strings.ToLower(scriptPubKey)
	if len(lower) < 6 {
		return "unknown"
	}

	// Extract data after OP_RETURN (6a) and length byte
	data := lower[4:] // Skip 6a + length byte

	switch {
	case strings.HasPrefix(data, "6f6d6e69"):
		return "omni" // Omni Layer (Tether USDT)
	case strings.HasPrefix(data, "4f41"):
		return "openassets" // OpenAssets protocol
	case strings.HasPrefix(data, "455843"):
		return "exchain" // Exchange chain marker
	case strings.HasPrefix(data, "53504b"):
		return "counterparty" // Counterparty protocol
	case strings.HasPrefix(data, "69643a"):
		return "blockstack" // Blockstack naming
	case len(data) >= 40 && len(data) <= 80:
		return "timestamp" // Likely a document hash/timestamp
	default:
		return "unknown"
	}
}

// estimateOPReturnSize estimates the size of OP_RETURN data in bytes
func estimateOPReturnSize(scriptPubKey string) int {
	// Each hex pair = 1 byte, subtract OP_RETURN opcode (1 byte)
	dataLen := len(scriptPubKey) - 2
	if dataLen < 0 {
		return 0
	}
	return dataLen / 2
}

// detectDominantWitnessVersion determines the most common witness
// version across transaction inputs
func detectDominantWitnessVersion(tx models.Transaction) string {
	versions := map[string]int{"legacy": 0, "v0": 0, "v1": 0}

	for _, in := range tx.Inputs {
		addrType := detectAddressType(in.Address)
		switch addrType {
		case "taproot":
			versions["v1"]++
		case "segwit", "p2sh-segwit":
			versions["v0"]++
		default:
			versions["legacy"]++
		}
	}

	best := "legacy"
	bestCount := 0
	for version, count := range versions {
		if count > bestCount {
			bestCount = count
			best = version
		}
	}
	return best
}

// estimateTapscriptDepth estimates the tapscript tree complexity.
// Key-path spends = depth 0 (most private)
// Script-path spends reveal tree structure (depth 1+)
// Detection is based on witness size heuristics.
func estimateTapscriptDepth(tx models.Transaction) int {
	for _, in := range tx.Inputs {
		if detectAddressType(in.Address) == "taproot" {
			// Taproot key-path: 64-byte Schnorr signature
			// Script-path: > 64 bytes (includes control block + script)
			// We estimate from ScriptSig/witness size
			if len(in.ScriptSig) > 128 { // > 64 bytes in hex
				return 1 // At least depth 1 (script-path)
			}
		}
	}
	return 0 // Key-path only (optimal privacy)
}
