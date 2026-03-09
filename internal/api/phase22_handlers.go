package api

import (
	"net/http"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/gin-gonic/gin"
	"github.com/rawblock/coinjoin-engine/internal/heuristics"
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ============================================================
// Phase 22: ML, Risk & Compliance API Handlers
// ============================================================

// fetchAndConvertTx fetches a raw tx from the Bitcoin node and converts
// it to models.Transaction. Returns nil, error-response if lookup fails.
func (h *APIHandler) fetchAndConvertTx(c *gin.Context, txid string) *models.Transaction {
	if h.btcClient == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Bitcoin RPC not configured"})
		return nil
	}
	hash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid txid format"})
		return nil
	}
	rawTx, err := h.btcClient.GetRawTransaction(hash)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Transaction not found", "txid": txid})
		return nil
	}

	tx := models.Transaction{
		Txid:      rawTx.Txid,
		Inputs:    make([]models.TxIn, len(rawTx.Vin)),
		Outputs:   make([]models.TxOut, len(rawTx.Vout)),
		Weight:    int(rawTx.Weight),
		Vsize:     int(rawTx.Vsize),
		Version:   int32(rawTx.Version),
		LockTime:  rawTx.LockTime,
		BlockTime: rawTx.Blocktime,
	}

	for i, vin := range rawTx.Vin {
		if vin.Txid == "" {
			continue
		}
		prevHash, _ := chainhash.NewHashFromStr(vin.Txid)
		prevTx, pErr := h.btcClient.GetRawTransaction(prevHash)
		var inValue float64
		var inAddr string
		if pErr == nil && int(vin.Vout) < len(prevTx.Vout) {
			inValue = prevTx.Vout[vin.Vout].Value
			if len(prevTx.Vout[vin.Vout].ScriptPubKey.Addresses) > 0 {
				inAddr = prevTx.Vout[vin.Vout].ScriptPubKey.Addresses[0]
			}
		}
		scriptSigHex := ""
		if vin.ScriptSig != nil {
			scriptSigHex = vin.ScriptSig.Hex
		}
		tx.Inputs[i] = models.TxIn{
			Txid:      vin.Txid,
			Vout:      vin.Vout,
			Value:     btcToSats(inValue),
			Address:   inAddr,
			ScriptSig: scriptSigHex,
			Sequence:  vin.Sequence,
		}
	}

	for i, vout := range rawTx.Vout {
		addr := ""
		if len(vout.ScriptPubKey.Addresses) > 0 {
			addr = vout.ScriptPubKey.Addresses[0]
		}
		tx.Outputs[i] = models.TxOut{
			Value:        btcToSats(vout.Value),
			Address:      addr,
			ScriptPubKey: vout.ScriptPubKey.Hex,
		}
	}

	return &tx
}

// handleClassify runs the ML classifier on a transaction
// GET /api/v1/ml/classify/:txid
func (h *APIHandler) handleClassify(c *gin.Context) {
	txid := c.Param("txid")
	tx := h.fetchAndConvertTx(c, txid)
	if tx == nil {
		return
	}

	features := heuristics.ExtractFeatures(*tx)
	classification := heuristics.ClassifyTransaction(features)

	c.JSON(http.StatusOK, gin.H{
		"txid":           txid,
		"classification": classification,
		"features": gin.H{
			"inputCount":         features.InputCount,
			"outputCount":        features.OutputCount,
			"equalOutputRatio":   features.EqualOutputRatio,
			"maxEqualOutputs":    features.MaxEqualOutputs,
			"outputGini":         features.OutputGini,
			"outputEntropy":      features.OutputEntropy,
			"feeRate":            features.FeeRate,
			"coinJoinLikelihood": features.CoinJoinLikelihood,
			"mixedScriptTypes":   features.MixedScriptTypes,
			"hasLikelyChange":    features.HasLikelyChange,
		},
	})
}

// handleRiskAssessment runs the risk engine on a transaction
// GET /api/v1/risk/:txid
func (h *APIHandler) handleRiskAssessment(c *gin.Context) {
	txid := c.Param("txid")
	tx := h.fetchAndConvertTx(c, txid)
	if tx == nil {
		return
	}

	result := heuristics.AnalyzeTx(*tx)
	riskEngine := heuristics.GetGlobalRiskEngine()
	profile := riskEngine.EvaluateRisk(*tx, &result)
	darknetPatterns := heuristics.DetectDarknetPatterns(*tx)
	mixerResult := heuristics.DetectMixerService(*tx)

	c.JSON(http.StatusOK, gin.H{
		"txid":            txid,
		"riskProfile":     profile,
		"darknetPatterns": darknetPatterns,
		"mixerDetection":  mixerResult,
		"privacyScore":    result.PrivacyScore,
		"heuristicFlags":  result.HeuristicFlags,
	})
}

// handleGetAlerts returns recent alerts from the alert engine
// GET /api/v1/alerts
func (h *APIHandler) handleGetAlerts(c *gin.Context) {
	alertEngine := heuristics.GetGlobalRiskAlertEngine()
	alerts := alertEngine.GetAlerts(100)
	c.JSON(http.StatusOK, gin.H{"alerts": alerts, "total": len(alerts)})
}

// handleJurisdictionCheck assesses jurisdiction risk for a country
// GET /api/v1/compliance/jurisdiction/:countryCode
func (h *APIHandler) handleJurisdictionCheck(c *gin.Context) {
	code := c.Param("countryCode")
	je := heuristics.GetGlobalJurisdictionEngine()
	risk := je.GetRisk(code)
	if risk == nil {
		c.JSON(http.StatusOK, gin.H{"countryCode": code, "status": "not_monitored", "riskScore": 0, "isHighRisk": false})
		return
	}
	c.JSON(http.StatusOK, risk)
}

// handleTravelRuleCheck checks FATF Travel Rule compliance
// GET /api/v1/compliance/travel-rule/:txid
func (h *APIHandler) handleTravelRuleCheck(c *gin.Context) {
	txid := c.Param("txid")
	tx := h.fetchAndConvertTx(c, txid)
	if tx == nil {
		return
	}
	btcPrice := 85000.0
	check := heuristics.CheckTravelRule(*tx, btcPrice)
	c.JSON(http.StatusOK, gin.H{"txid": txid, "travelRule": check, "btcPriceUsd": btcPrice})
}

// handleSARReports returns generated SAR reports
// GET /api/v1/compliance/sar
func (h *APIHandler) handleSARReports(c *gin.Context) {
	status := c.Query("status")
	sg := heuristics.GetGlobalSARGenerator()
	reports := sg.GetReports(status)
	c.JSON(http.StatusOK, gin.H{"reports": reports, "total": len(reports), "filter": status})
}

// handleEntityLookup checks if an address belongs to a known entity
// GET /api/v1/entity/:address
func (h *APIHandler) handleEntityLookup(c *gin.Context) {
	address := c.Param("address")
	registry := heuristics.GetGlobalEntityRegistry()
	attribution := registry.LookupEntity(address)
	c.JSON(http.StatusOK, gin.H{"address": address, "attribution": attribution})
}

// handleGenerateSAR generates a SAR for a specific transaction
// POST /api/v1/compliance/sar/:txid
func (h *APIHandler) handleGenerateSAR(c *gin.Context) {
	txid := c.Param("txid")
	tx := h.fetchAndConvertTx(c, txid)
	if tx == nil {
		return
	}
	result := heuristics.AnalyzeTx(*tx)
	riskEngine := heuristics.GetGlobalRiskEngine()
	profile := riskEngine.EvaluateRisk(*tx, &result)
	sg := heuristics.GetGlobalSARGenerator()
	report := sg.GenerateSAR(*tx, &result, profile)
	if report == nil {
		c.JSON(http.StatusOK, gin.H{"txid": txid, "message": "Transaction does not meet SAR threshold"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"txid": txid, "report": report})
}

// handleEngineStats returns current engine statistics
// GET /api/v1/stats
func (h *APIHandler) handleEngineStats(c *gin.Context) {
	je := heuristics.GetGlobalJurisdictionEngine()
	alertEngine := heuristics.GetGlobalRiskAlertEngine()
	alerts := alertEngine.GetAlerts(0)
	c.JSON(http.StatusOK, gin.H{
		"engine": gin.H{
			"version":       heuristics.CurrentSnapshotID,
			"pipelineSteps": 52,
			"flagBits":      55,
			"phase":         "Phase 22",
		},
		"coverage": gin.H{
			"industryTechniques": "74/102 (73%)",
			"jurisdictions":      je.CountryCount(),
			"alertsGenerated":    len(alerts),
		},
	})
}

// registerPhase22Routes wires Phase 22 API endpoints into the router
func registerPhase22Routes(auth *gin.RouterGroup, handler *APIHandler) {
	auth.GET("/ml/classify/:txid", handler.handleClassify)
	auth.GET("/risk/:txid", handler.handleRiskAssessment)
	auth.GET("/alerts", handler.handleGetAlerts)
	auth.GET("/entity/:address", handler.handleEntityLookup)
	auth.GET("/stats", handler.handleEngineStats)

	compliance := auth.Group("/compliance")
	{
		compliance.GET("/jurisdiction/:countryCode", handler.handleJurisdictionCheck)
		compliance.GET("/travel-rule/:txid", handler.handleTravelRuleCheck)
		compliance.GET("/sar", handler.handleSARReports)
		compliance.POST("/sar/:txid", handler.handleGenerateSAR)
	}
}
