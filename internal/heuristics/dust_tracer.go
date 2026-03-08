package heuristics

import (
	"sync"
	"time"

	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// Dust Attack Full Tracing Engine
//
// Goes beyond dust DETECTION (which we already have in dust_analysis.go)
// to implement full dust attack TRACING:
//
//   1. Attacker sends 546 sats (dust) to Target address
//   2. Target later consolidates (spends dust + other UTXOs in one tx)
//   3. All input addresses are now LINKED via CIOH
//   4. Attacker can now track Target's entire wallet
//
// This module monitors the full lifecycle:
//   - Phase 1: Detect dust output creation (attacker → target)
//   - Phase 2: Monitor for dust consolidation (target spends the dust)
//   - Phase 3: Record the cluster link created by consolidation
//   - Phase 4: Alert on the exposure (all addresses now linked)
//
// References:
//   - Trezor, "UTXO Management for Privacy" (2024)
//   - Chainalysis dust attack analysis methodology
//   - FATF, "Virtual Assets Red Flag Indicators" (2020)

// DustThreshold is the maximum value considered "dust" (in sats)
const DustThreshold = 1000 // 1000 sats ≈ $0.60

// DustAttackPhase represents the lifecycle stage of a dust attack
type DustAttackPhase string

const (
	DustPhaseDeployed     DustAttackPhase = "deployed"      // Dust sent to target
	DustPhaseConsolidated DustAttackPhase = "consolidated"   // Target merged dust with other UTXOs
	DustPhaseExposed      DustAttackPhase = "exposed"        // Wallet cluster revealed
)

// DustAttackRecord tracks a single dust attack through its lifecycle
type DustAttackRecord struct {
	DustTxID        string          `json:"dustTxid"`         // Tx that created the dust
	DustOutputIndex int             `json:"dustOutputIndex"`  // Output index of the dust
	DustValue       int64           `json:"dustValue"`        // Value of dust (sats)
	TargetAddress   string          `json:"targetAddress"`    // Address that received the dust
	AttackerAddress string          `json:"attackerAddress"`  // Suspected attacker's change address
	Phase           DustAttackPhase `json:"phase"`
	DeployedAt      time.Time       `json:"deployedAt"`
	ConsolidatedAt  time.Time       `json:"consolidatedAt,omitempty"`
	ConsolidationTx string          `json:"consolidationTx,omitempty"` // Tx where target spent the dust
	ExposedAddresses []string       `json:"exposedAddresses,omitempty"` // Addresses revealed by consolidation
	ExposureCount   int             `json:"exposureCount"`    // Number of addresses exposed
}

// DustTracer monitors dust attacks through their full lifecycle
type DustTracer struct {
	mu       sync.RWMutex
	// Map of target address → dust attacks targeting that address
	attacks  map[string][]DustAttackRecord
	// Map of dust outpoint (txid:vout) → attack record for fast lookup
	outpoints map[string]*DustAttackRecord
}

var (
	globalDustTracer *DustTracer
	dustTracerOnce   sync.Once
)

// GetGlobalDustTracer returns the singleton dust attack tracer
func GetGlobalDustTracer() *DustTracer {
	dustTracerOnce.Do(func() {
		globalDustTracer = &DustTracer{
			attacks:   make(map[string][]DustAttackRecord),
			outpoints: make(map[string]*DustAttackRecord),
		}
	})
	return globalDustTracer
}

// Phase1_DetectDustDeployment scans a transaction for dust outputs
// and records them as potential dust attacks
func (dt *DustTracer) Phase1_DetectDustDeployment(tx models.Transaction) []DustAttackRecord {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	var detected []DustAttackRecord

	for i, out := range tx.Outputs {
		if out.Value > 0 && out.Value <= DustThreshold && out.Address != "" {
			// This is a potential dust attack deployment
			record := DustAttackRecord{
				DustTxID:        tx.Txid,
				DustOutputIndex: i,
				DustValue:       out.Value,
				TargetAddress:   out.Address,
				Phase:           DustPhaseDeployed,
				DeployedAt:      time.Now(),
			}

			// If there's a change output (larger value), record attacker's address
			for _, other := range tx.Outputs {
				if other.Value > DustThreshold && other.Address != out.Address {
					record.AttackerAddress = other.Address
					break
				}
			}

			outpoint := tx.Txid + ":" + string(rune(i+'0'))
			dt.outpoints[outpoint] = &record
			dt.attacks[out.Address] = append(dt.attacks[out.Address], record)
			detected = append(detected, record)
		}
	}

	return detected
}

// Phase2_DetectConsolidation checks if a transaction spends any tracked dust outputs.
// When the target consolidates dust with other UTXOs, all input addresses are exposed.
func (dt *DustTracer) Phase2_DetectConsolidation(tx models.Transaction) []DustAttackRecord {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	var consolidated []DustAttackRecord

	for _, in := range tx.Inputs {
		if in.Address == "" {
			continue
		}

		// Check if this address has pending dust attacks
		attacks, exists := dt.attacks[in.Address]
		if !exists {
			continue
		}

		for idx := range attacks {
			if attacks[idx].Phase != DustPhaseDeployed {
				continue
			}

			// The target is spending! Collect all input addresses (CIOH link)
			exposedAddrs := make(map[string]bool)
			for _, input := range tx.Inputs {
				if input.Address != "" {
					exposedAddrs[input.Address] = true
				}
			}

			var exposed []string
			for addr := range exposedAddrs {
				exposed = append(exposed, addr)
			}

			attacks[idx].Phase = DustPhaseConsolidated
			attacks[idx].ConsolidatedAt = time.Now()
			attacks[idx].ConsolidationTx = tx.Txid
			attacks[idx].ExposedAddresses = exposed
			attacks[idx].ExposureCount = len(exposed)

			// If multiple inputs → the attack was successful
			if len(exposed) > 1 {
				attacks[idx].Phase = DustPhaseExposed
			}

			consolidated = append(consolidated, attacks[idx])
		}
	}

	return consolidated
}

// GetActiveAttacks returns all dust attacks targeting an address
func (dt *DustTracer) GetActiveAttacks(address string) []DustAttackRecord {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.attacks[address]
}

// GetExposedAttacks returns all attacks that successfully exposed addresses
func (dt *DustTracer) GetExposedAttacks() []DustAttackRecord {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	var exposed []DustAttackRecord
	for _, attacks := range dt.attacks {
		for _, a := range attacks {
			if a.Phase == DustPhaseExposed {
				exposed = append(exposed, a)
			}
		}
	}
	return exposed
}

// GetStats returns summary statistics for the dust tracer
func (dt *DustTracer) GetStats() (total, deployed, consolidated, exposed int) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	for _, attacks := range dt.attacks {
		for _, a := range attacks {
			total++
			switch a.Phase {
			case DustPhaseDeployed:
				deployed++
			case DustPhaseConsolidated:
				consolidated++
			case DustPhaseExposed:
				exposed++
			}
		}
	}
	return
}
