package api

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/gin-gonic/gin"
	"github.com/rawblock/coinjoin-engine/internal/bitcoin"
	"github.com/rawblock/coinjoin-engine/internal/db"
	"github.com/rawblock/coinjoin-engine/internal/heuristics"
	"github.com/rawblock/coinjoin-engine/internal/scanner"
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

type APIHandler struct {
	dbStore      *db.PostgresStore
	btcClient    *bitcoin.Client
	wsHub        *Hub
	blockScanner *scanner.BlockScanner
}

func SetupRouter(dbStore *db.PostgresStore, btcClient *bitcoin.Client, wsHub *Hub, blockScanner *scanner.BlockScanner) *gin.Engine {
	r := gin.Default()

	// Enable CORS — configurable via ALLOWED_ORIGINS env var
	// Production: ALLOWED_ORIGINS=https://rawblock.net,https://www.rawblock.net
	// Development: ALLOWED_ORIGINS=http://localhost:3000 (or leave empty for *)
	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	r.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if allowedOrigins == "" || allowedOrigins == "*" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			// Check if the request origin is in the allowed list
			for _, allowed := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(allowed) == origin {
					c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
		}
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	handler := &APIHandler{dbStore: dbStore, btcClient: btcClient, wsHub: wsHub, blockScanner: blockScanner}

	api := r.Group("/api/v1")
	{
		api.GET("/analyze/:txid", handler.handleAnalyzeTx)
		api.POST("/cluster/evaluate", handler.handleEvaluateCluster)
		api.GET("/mixers", handler.handleGetMixers)
		api.GET("/health", handler.handleHealth)
		api.GET("/stream", wsHub.Subscribe)

		// Historical Block Scanner
		api.POST("/scan", handler.handleStartScan)
		api.GET("/scan/progress", handler.handleScanProgress)
	}

	// Serve Static Dashboard
	r.Static("/dashboard", "./public")

	return r
}

func (h *APIHandler) handleAnalyzeTx(c *gin.Context) {
	txid := c.Param("txid")

	var tx models.Transaction

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	if txid == "whirlpool" || txid == "mix" {
		// Generate a perfect 5x5 Whirlpool Mix
		tx = models.Transaction{
			Txid:    txid,
			Inputs:  make([]models.TxIn, 5),
			Outputs: make([]models.TxOut, 5),
		}

		for i := 0; i < 5; i++ {
			tx.Inputs[i] = models.TxIn{Value: int64((rng.Float64()*0.4 + 0.06) * 100000000), Address: "bc1q_in"}
			tx.Outputs[i] = models.TxOut{Value: 5000000, Address: "bc1q_out"}
		}

	} else {
		// Fetch Real Transaction from Bitcoin RPC
		if h.btcClient == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Bitcoin RPC not configured"})
			return
		}

		hash, err := chainhash.NewHashFromStr(txid)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid txid format"})
			return
		}

		rawTx, err := h.btcClient.GetRawTransaction(hash)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tx from node", "details": err.Error()})
			return
		}

		tx = models.Transaction{
			Txid:    rawTx.Txid,
			Inputs:  make([]models.TxIn, len(rawTx.Vin)),
			Outputs: make([]models.TxOut, len(rawTx.Vout)),
			Weight:  int(rawTx.Weight),
			Vsize:   int(rawTx.Vsize),
		}

		// Calculate Fee: Sum(Inputs) - Sum(Outputs)
		var totalIn, totalOut float64

		// Note: GetRawTransactionVerbose does not return input values directly (vin just has txid/vout).
		// For true forensics we'd need to look up previous outputs.
		// For testing the CUDA engine math, we'll try to fetch input values if needed,
		// but since we are doing deep forensics, we MUST fetch prevouts.
		for i, vin := range rawTx.Vin {
			if vin.Txid == "" {
				continue // Coinbase
			}

			// Fetch previous transaction to get the input value
			prevHash, _ := chainhash.NewHashFromStr(vin.Txid)
			prevTx, err := h.btcClient.GetRawTransaction(prevHash)
			var inValue float64
			var inAddr string
			if err == nil && int(vin.Vout) < len(prevTx.Vout) {
				inValue = prevTx.Vout[vin.Vout].Value
				if len(prevTx.Vout[vin.Vout].ScriptPubKey.Addresses) > 0 {
					inAddr = prevTx.Vout[vin.Vout].ScriptPubKey.Addresses[0]
				}
			}

			totalIn += inValue
			tx.Inputs[i] = models.TxIn{
				Txid:    vin.Txid,
				Vout:    vin.Vout,
				Value:   int64(inValue * 100000000), // Convert BTC to Satoshis
				Address: inAddr,
			}
		}

		for i, vout := range rawTx.Vout {
			totalOut += vout.Value
			var outAddr string
			if len(vout.ScriptPubKey.Addresses) > 0 {
				outAddr = vout.ScriptPubKey.Addresses[0]
			}
			tx.Outputs[i] = models.TxOut{
				Value:   int64(vout.Value * 100000000),
				Address: outAddr,
			}
		}

		tx.Fee = int64((totalIn - totalOut) * 100000000)
	}

	// 2. Run the Heuristics Engine Analysis
	result := heuristics.AnalyzeTx(tx)

	// 3. Persist to DB if connected
	if h.dbStore != nil {
		// Get real block height from Bitcoin Core instead of hardcoding
		blockHeight := 0
		if h.btcClient != nil {
			if count, err := h.btcClient.RPC.GetBlockCount(); err == nil {
				blockHeight = int(count)
			}
		}
		if err := h.dbStore.SaveAnalysisResult(context.Background(), blockHeight, result); err != nil {
			log.Printf("Failed to save analysis result to DB: %v", err)
		}
	}

	// 4. Return JSON payload
	c.JSON(http.StatusOK, gin.H{
		"tx":       tx,
		"analysis": result,
	})
}

// handleEvaluateCluster accepts a set of evidence edges and runs factor-graph
// inference to determine if clustering is warranted.
func (h *APIHandler) handleEvaluateCluster(c *gin.Context) {
	var req struct {
		Edges []models.EvidenceEdge `json:"edges"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	shouldCluster, posteriorLLR := heuristics.ComputeClusterPosterior(req.Edges)
	inference := heuristics.EvaluateFactorGraph(req.Edges)

	c.JSON(http.StatusOK, gin.H{
		"shouldCluster": shouldCluster,
		"posteriorLLR":  posteriorLLR,
		"inference":     inference,
	})
}

// handleHealth returns engine status and capabilities for service discovery
func (h *APIHandler) handleHealth(c *gin.Context) {
	dbConnected := h.dbStore != nil

	c.JSON(http.StatusOK, gin.H{
		"status":     "operational",
		"engine":     "RawBlock Forensics Engine v3.0",
		"snapshotId": heuristics.CurrentSnapshotID,
		"capabilities": gin.H{
			"mitm_solver":     true,
			"cpsat_solver":    true,
			"factor_graph":    true,
			"shadow_mode":     true,
			"anonset_windows": true,
			"ari_vi_metrics":  true,
		},
		"dbConnected": dbConnected,
	})
}

// handleGetMixers returns the historically indexed WabiSabi and Whirlpool CoinJoin transactions.
func (h *APIHandler) handleGetMixers(c *gin.Context) {
	if h.dbStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not connected"})
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

	mixers, totalCount, err := h.dbStore.GetMixers(c.Request.Context(), page, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch historical mixers", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":       mixers,
		"totalCount": totalCount,
		"page":       page,
		"limit":      limit,
	})
}

// handleStartScan launches a historical block scan in the background.
// POST /api/v1/scan { "startHeight": 850000, "endHeight": 850100 }
func (h *APIHandler) handleStartScan(c *gin.Context) {
	if h.blockScanner == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Block scanner not initialized"})
		return
	}

	var req struct {
		StartHeight int64 `json:"startHeight"`
		EndHeight   int64 `json:"endHeight"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body. Expected: {startHeight, endHeight}"})
		return
	}

	// Validate range
	if req.StartHeight <= 0 || req.EndHeight <= 0 || req.StartHeight > req.EndHeight {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid block range"})
		return
	}

	// Validate against chain tip
	if h.btcClient != nil {
		if chainTip, err := h.btcClient.RPC.GetBlockCount(); err == nil {
			if req.EndHeight > chainTip {
				req.EndHeight = chainTip
			}
		}
	}

	// Launch scan in background
	ctx := context.Background()
	h.blockScanner.ScanRange(ctx, req.StartHeight, req.EndHeight)

	c.JSON(http.StatusOK, gin.H{
		"status":      "scan_started",
		"startHeight": req.StartHeight,
		"endHeight":   req.EndHeight,
		"totalBlocks": req.EndHeight - req.StartHeight + 1,
	})
}

// handleScanProgress returns the current progress of the block scanner.
func (h *APIHandler) handleScanProgress(c *gin.Context) {
	if h.blockScanner == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Block scanner not initialized"})
		return
	}
	progress := h.blockScanner.GetProgress()
	c.JSON(http.StatusOK, progress)
}

// broadcastCoinJoinAlert sends a CoinJoin detection alert via the WebSocket hub.
// This is wired as the alertFunc callback for the BlockScanner.
func BroadcastCoinJoinAlert(wsHub *Hub) func(scanner.CoinJoinAlert) {
	return func(alert scanner.CoinJoinAlert) {
		payload := gin.H{
			"type":  "coinjoin_alert",
			"alert": alert,
		}
		alertBytes, _ := json.Marshal(payload)
		wsHub.Broadcast(alertBytes)
		log.Printf("[ALERT] 🔍 %s CoinJoin detected: %s (block %d, anonset %d, %.4f BTC)",
			alert.MixerType, alert.Txid, alert.BlockHeight, alert.AnonSet, alert.TotalValueBTC)
	}
}
