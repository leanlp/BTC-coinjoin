package mempool

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/rawblock/coinjoin-engine/internal/api"
	"github.com/rawblock/coinjoin-engine/internal/bitcoin"
	"github.com/rawblock/coinjoin-engine/internal/db"
	"github.com/rawblock/coinjoin-engine/internal/heuristics"
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

type Poller struct {
	btcClient *bitcoin.Client
	wsHub     *api.Hub
	dbStore   *db.PostgresStore
	seenTXs   map[string]bool
}

// StreamPayload represents the real-time data sent to the dashboard UI
type StreamPayload struct {
	TxID           string                  `json:"txid"`
	NumInputs      int                     `json:"numInputs"`
	NumOutputs     int                     `json:"numOutputs"`
	TotalIn        int64                   `json:"totalIn"`
	TotalOut       int64                   `json:"totalOut"`
	Fee            int64                   `json:"fee"`
	VSize          int                     `json:"vsize"`
	PrivacyScore   int                     `json:"privacyScore"`
	AnonSet        int                     `json:"anonSet"`
	ProcessingTime float64                 `json:"processingTimeMs"`
	CUDAOffloaded  bool                    `json:"cudaOffloaded"`
	HeuristicFlags uint64                  `json:"heuristicFlags"`
	Inference      *models.InferenceResult `json:"inference,omitempty"`
}

func NewPoller(btcClient *bitcoin.Client, wsHub *api.Hub, dbStore *db.PostgresStore) *Poller {
	return &Poller{
		btcClient: btcClient,
		wsHub:     wsHub,
		dbStore:   dbStore,
		seenTXs:   make(map[string]bool),
	}
}

func (p *Poller) Run(ctx context.Context) {
	log.Println("Starting Mempool CUDA Analytics Poller...")

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// Keep map clean by resetting seen every hour just to prevent infinite memory growth
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping Mempool Poller...")
			return
		case <-cleanupTicker.C:
			p.seenTXs = make(map[string]bool)
		case <-ticker.C:
			// Fetch current mempool hashes (verbose=false)
			mempool, err := p.btcClient.GetRawMempool()
			if err != nil {
				log.Printf("[Poller] Error fetching mempool: %v", err)
				continue
			}

			// Get current block height for accurate DB persistence
			currentHeight := 0
			if count, err := p.btcClient.RPC.GetBlockCount(); err == nil {
				currentHeight = int(count)
			}

			// Process up to 5 new transactions per tick to avoid lagging the node too much
			processedCount := 0
			for _, txidStr := range mempool {
				if p.seenTXs[txidStr] {
					continue
				}

				p.seenTXs[txidStr] = true

				hash, err := chainhash.NewHashFromStr(txidStr)
				if err != nil {
					continue
				}
				rawTx, err := p.btcClient.GetRawTransaction(hash)
				if err != nil {
					continue
				}

				// Only process interesting transactions (>2 inputs/outputs) to limit noise on the dashboard and trigger heuristics
				if len(rawTx.Vin) < 2 || len(rawTx.Vout) < 2 {
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
					// Fetch previous transaction to get input value AND address
					prevHash, _ := chainhash.NewHashFromStr(vin.Txid)
					prevTx, err := p.btcClient.GetRawTransaction(prevHash)
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
						Value:   valSats,
						Address: outAddr,
					}
					totalOut += valSats
				}

				fee := totalIn - totalOut
				if fee < 0 {
					fee = 0
				}

				// Measure CUDA / Engine processing time
				start := time.Now()

				// Re-using the engine's core analysis
				result := heuristics.AnalyzeTx(tx)

				elapsed := float64(time.Since(start).Microseconds()) / 1000.0

				// Check if CUDA was likely used (heuristic: threshold topology usually triggers it)
				// Now unconditionally true since we moved all processing to the GPU
				isCuda := true

				// Persist CoinJoin detections to the isolated database
				if p.dbStore != nil {
					// Check if this transaction has any CoinJoin-related flags
					isCoinJoinFlag := (result.HeuristicFlags&uint64(heuristics.FlagIsWhirlpoolStruct)) > 0 ||
						(result.HeuristicFlags&uint64(heuristics.FlagIsWasabiSuspect)) > 0 ||
						(result.HeuristicFlags&uint64(heuristics.FlagLikelyCollabConstruct)) > 0 ||
						(result.HeuristicFlags&uint64(heuristics.FlagIsJoinMarketBond)) > 0

					if isCoinJoinFlag {
						if err := p.dbStore.SaveAnalysisResult(ctx, currentHeight, result); err != nil {
							log.Printf("[Poller] Failed to persist CoinJoin detection to DB: %v", err)
						} else {
							log.Printf("[Poller] 🔍 CoinJoin detected and persisted: %s (flags: %d, anonset: %d)",
								tx.Txid, result.HeuristicFlags, result.AnonSet)
						}
					}
				}

				payload := StreamPayload{
					TxID:           tx.Txid,
					NumInputs:      len(tx.Inputs),
					NumOutputs:     len(tx.Outputs),
					TotalIn:        totalIn,
					TotalOut:       totalOut,
					Fee:            fee,
					VSize:          tx.Vsize,
					PrivacyScore:   result.PrivacyScore,
					AnonSet:        result.AnonSet,
					ProcessingTime: elapsed,
					CUDAOffloaded:  isCuda,
					HeuristicFlags: result.HeuristicFlags,
					Inference:      result.Inference,
				}

				payloadBytes, _ := json.Marshal(payload)
				p.wsHub.Broadcast(payloadBytes)

				processedCount++
				if processedCount >= 5 {
					break
				}
			}
		}
	}
}
