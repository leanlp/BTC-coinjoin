package scanner

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/rawblock/coinjoin-engine/internal/bitcoin"
	"github.com/rawblock/coinjoin-engine/internal/db"
	"github.com/rawblock/coinjoin-engine/internal/heuristics"
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// BlockScanner iterates confirmed blocks and applies heuristic analysis
// to every transaction, persisting CoinJoin detections to the isolated database.
// This provides the retroactive coverage that differentiates Tier-1 analytics
// platforms from mempool-only listeners.
type BlockScanner struct {
	btcClient *bitcoin.Client
	dbStore   *db.PostgresStore
	alertFunc func(alert CoinJoinAlert) // Optional broadcast callback

	// Progress tracking (atomic for safe concurrent reads)
	currentHeight  atomic.Int64
	totalScanned   atomic.Int64
	totalCoinJoins atomic.Int64
	isRunning      atomic.Bool
}

// CoinJoinAlert represents a real-time notification emitted when a CoinJoin is detected
type CoinJoinAlert struct {
	Txid           string  `json:"txid"`
	BlockHeight    int     `json:"blockHeight"`
	MixerType      string  `json:"mixerType"`
	AnonSet        int     `json:"anonSet"`
	NumInputs      int     `json:"numInputs"`
	NumOutputs     int     `json:"numOutputs"`
	TotalValueBTC  float64 `json:"totalValueBtc"`
	HeuristicFlags uint64  `json:"heuristicFlags"`
	Timestamp      string  `json:"timestamp"`
}

// ScanProgress represents the scanner's current state for the API
type ScanProgress struct {
	IsRunning      bool  `json:"isRunning"`
	CurrentHeight  int64 `json:"currentHeight"`
	TotalScanned   int64 `json:"totalScanned"`
	TotalCoinJoins int64 `json:"totalCoinJoins"`
}

func NewBlockScanner(btcClient *bitcoin.Client, dbStore *db.PostgresStore, alertFunc func(CoinJoinAlert)) *BlockScanner {
	return &BlockScanner{
		btcClient: btcClient,
		dbStore:   dbStore,
		alertFunc: alertFunc,
	}
}

// GetProgress returns the current scanning progress (thread-safe)
func (s *BlockScanner) GetProgress() ScanProgress {
	return ScanProgress{
		IsRunning:      s.isRunning.Load(),
		CurrentHeight:  s.currentHeight.Load(),
		TotalScanned:   s.totalScanned.Load(),
		TotalCoinJoins: s.totalCoinJoins.Load(),
	}
}

// ScanRange processes a specific block range asynchronously.
// It analyzes every transaction in each block and persists CoinJoin detections.
func (s *BlockScanner) ScanRange(ctx context.Context, startHeight, endHeight int64) {
	if s.isRunning.Load() {
		log.Println("[BlockScanner] Scan already in progress, ignoring duplicate request")
		return
	}

	s.isRunning.Store(true)
	s.totalScanned.Store(0)
	s.totalCoinJoins.Store(0)

	go func() {
		defer s.isRunning.Store(false)

		log.Printf("[BlockScanner] Starting historical scan: blocks %d → %d (%d blocks)",
			startHeight, endHeight, endHeight-startHeight+1)

		for height := startHeight; height <= endHeight; height++ {
			select {
			case <-ctx.Done():
				log.Printf("[BlockScanner] Scan cancelled at block %d", height)
				return
			default:
			}

			s.currentHeight.Store(height)
			s.scanBlock(ctx, height)

			// Log progress every 100 blocks
			scanned := s.totalScanned.Load()
			if scanned%100 == 0 && scanned > 0 {
				log.Printf("[BlockScanner] Progress: block %d | scanned %d txs | found %d CoinJoins",
					height, scanned, s.totalCoinJoins.Load())
			}
		}

		log.Printf("[BlockScanner] ✅ Scan complete: %d transactions analyzed, %d CoinJoins detected",
			s.totalScanned.Load(), s.totalCoinJoins.Load())
	}()
}

// scanBlock fetches a single block and analyzes every transaction
func (s *BlockScanner) scanBlock(ctx context.Context, height int64) {
	// Get block hash for this height
	hash, err := s.btcClient.RPC.GetBlockHash(height)
	if err != nil {
		log.Printf("[BlockScanner] Error getting block hash for height %d: %v", height, err)
		return
	}

	// Use GetBlockVerbose which returns transaction IDs as strings
	block, err := s.btcClient.GetBlockVerbose(hash)
	if err != nil {
		log.Printf("[BlockScanner] Error getting block %d: %v", height, err)
		return
	}

	for _, txidStr := range block.Tx {
		// Skip coinbase (first tx in block)
		if txidStr == block.Tx[0] {
			continue
		}

		// Fetch the full transaction
		txHash, err := chainhash.NewHashFromStr(txidStr)
		if err != nil {
			continue
		}
		rawTx, err := s.btcClient.GetRawTransaction(txHash)
		if err != nil {
			continue
		}

		// Only analyze transactions with ≥2 inputs and ≥2 outputs (interesting topology)
		if len(rawTx.Vin) < 2 || len(rawTx.Vout) < 2 {
			s.totalScanned.Add(1)
			continue
		}

		// Map to internal format
		tx := models.Transaction{
			Txid:    rawTx.Txid,
			Inputs:  make([]models.TxIn, len(rawTx.Vin)),
			Outputs: make([]models.TxOut, len(rawTx.Vout)),
			Weight:  int(rawTx.Weight),
			Vsize:   int(rawTx.Vsize),
		}

		var totalIn, totalOut int64

		for i, vin := range rawTx.Vin {
			if vin.Txid == "" {
				continue
			}
			// Fetch previous transaction for input value and address
			prevHash, _ := chainhash.NewHashFromStr(vin.Txid)
			prevTx, err := s.btcClient.GetRawTransaction(prevHash)
			var inValue float64
			var inAddr string
			if err == nil && int(vin.Vout) < len(prevTx.Vout) {
				inValue = prevTx.Vout[vin.Vout].Value
				if len(prevTx.Vout[vin.Vout].ScriptPubKey.Addresses) > 0 {
					inAddr = prevTx.Vout[vin.Vout].ScriptPubKey.Addresses[0]
				}
			}
			valSats := int64(inValue * 100000000)
			tx.Inputs[i] = models.TxIn{
				Txid:    vin.Txid,
				Vout:    vin.Vout,
				Value:   valSats,
				Address: inAddr,
			}
			totalIn += valSats
		}

		for i, vout := range rawTx.Vout {
			valSats := int64(vout.Value * 100000000)
			var outAddr string
			if len(vout.ScriptPubKey.Addresses) > 0 {
				outAddr = vout.ScriptPubKey.Addresses[0]
			}
			tx.Outputs[i] = models.TxOut{
				Value:        valSats,
				Address:      outAddr,
				ScriptPubKey: vout.ScriptPubKey.Hex,
			}
			totalOut += valSats
		}

		tx.Fee = totalIn - totalOut
		if tx.Fee < 0 {
			tx.Fee = 0
		}

		// Run the heuristics engine
		result := heuristics.AnalyzeTx(tx)
		s.totalScanned.Add(1)

		// Persist only CoinJoin-flagged transactions
		isCoinJoin := (result.HeuristicFlags&uint64(heuristics.FlagIsWhirlpoolStruct)) > 0 ||
			(result.HeuristicFlags&uint64(heuristics.FlagIsWasabiSuspect)) > 0 ||
			(result.HeuristicFlags&uint64(heuristics.FlagLikelyCollabConstruct)) > 0 ||
			(result.HeuristicFlags&uint64(heuristics.FlagIsJoinMarketBond)) > 0

		if isCoinJoin {
			if s.dbStore != nil {
				if err := s.dbStore.SaveAnalysisResult(ctx, int(height), result); err != nil {
					log.Printf("[BlockScanner] DB persist error at block %d tx %s: %v", height, rawTx.Txid, err)
				}
			}
			s.totalCoinJoins.Add(1)

			// Determine mixer type for alert
			mixerType := "CoinJoin"
			if (result.HeuristicFlags & uint64(heuristics.FlagIsWhirlpoolStruct)) > 0 {
				mixerType = "Whirlpool"
			} else if (result.HeuristicFlags & uint64(heuristics.FlagIsWasabiSuspect)) > 0 {
				mixerType = "WabiSabi"
			} else if (result.HeuristicFlags & uint64(heuristics.FlagIsJoinMarketBond)) > 0 {
				mixerType = "JoinMarket"
			}

			// Emit real-time alert
			if s.alertFunc != nil {
				s.alertFunc(CoinJoinAlert{
					Txid:           rawTx.Txid,
					BlockHeight:    int(height),
					MixerType:      mixerType,
					AnonSet:        result.AnonSet,
					NumInputs:      len(tx.Inputs),
					NumOutputs:     len(tx.Outputs),
					TotalValueBTC:  float64(totalIn) / 100000000.0,
					HeuristicFlags: result.HeuristicFlags,
					Timestamp:      time.Now().Format(time.RFC3339),
				})
			}
		}
	}
}
