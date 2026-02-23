package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rawblock/coinjoin-engine/internal/heuristics"
)

// ════════════════════════════════════════════════════════════════════
// Investigation API Handlers (Phase 18 — Incident Response)
// ════════════════════════════════════════════════════════════════════

// POST /api/v1/investigation
// Creates a new investigation case for fund tracing.
func (h *APIHandler) handleCreateInvestigation(c *gin.Context) {
	var req struct {
		Name           string   `json:"name" binding:"required"`
		Description    string   `json:"description"`
		TheftAddresses []string `json:"theftAddresses" binding:"required"`
		TotalStolen    int64    `json:"totalStolen"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	if len(req.TheftAddresses) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one theft address is required"})
		return
	}

	// Generate case ID from timestamp
	caseID := fmt.Sprintf("CASE-%d", time.Now().UnixNano())

	inv := h.invManager.CreateInvestigation(caseID, req.Name, req.Description, req.TheftAddresses, req.TotalStolen)

	c.JSON(http.StatusCreated, gin.H{
		"status":        "created",
		"investigation": inv,
	})
}

// GET /api/v1/investigation/:id
// Returns the full investigation details including flow graph.
func (h *APIHandler) handleGetInvestigation(c *gin.Context) {
	caseID := c.Param("id")

	inv := h.invManager.GetInvestigation(caseID)
	if inv == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Investigation not found"})
		return
	}

	c.JSON(http.StatusOK, inv)
}

// POST /api/v1/investigation/:id/trace
// Runs the fund flow trace for an investigation.
func (h *APIHandler) handleRunTrace(c *gin.Context) {
	caseID := c.Param("id")

	inv := h.invManager.GetInvestigation(caseID)
	if inv == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Investigation not found"})
		return
	}

	// Optional: accept trace config overrides
	var req struct {
		MaxHops         int     `json:"maxHops"`
		MinValue        int64   `json:"minValue"`
		PenetrateMixers *bool   `json:"penetrateMixers"`
		MinConfidence   float64 `json:"minConfidence"`
	}
	if err := c.ShouldBindJSON(&req); err == nil {
		if req.MaxHops > 0 {
			inv.TraceConfig.MaxHops = req.MaxHops
		}
		if req.MinValue > 0 {
			inv.TraceConfig.MinValue = req.MinValue
		}
		if req.PenetrateMixers != nil {
			inv.TraceConfig.PenetrateMixers = *req.PenetrateMixers
		}
		if req.MinConfidence > 0 {
			inv.TraceConfig.MinConfidence = req.MinConfidence
		}
	}

	// Execute the trace
	inv.RunTrace()

	summary := map[string]interface{}{
		"status": "trace_complete",
		"caseId": caseID,
	}

	if inv.FlowGraph != nil {
		summary["summary"] = inv.FlowGraph.Summary()
	}

	c.JSON(http.StatusOK, summary)
}

// GET /api/v1/investigation/:id/graph
// Returns the fund flow graph for visualization.
func (h *APIHandler) handleGetFlowGraph(c *gin.Context) {
	caseID := c.Param("id")

	inv := h.invManager.GetInvestigation(caseID)
	if inv == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Investigation not found"})
		return
	}

	if inv.FlowGraph == nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "No trace has been run yet. POST to /trace first.",
			"nodes":   []heuristics.FlowNode{},
			"edges":   []heuristics.FlowEdge{},
		})
		return
	}

	c.JSON(http.StatusOK, inv.FlowGraph)
}

// POST /api/v1/investigation/:id/tag
// Tags an address with investigator-provided metadata.
func (h *APIHandler) handleTagAddress(c *gin.Context) {
	caseID := c.Param("id")

	inv := h.invManager.GetInvestigation(caseID)
	if inv == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Investigation not found"})
		return
	}

	var req struct {
		Address  string `json:"address" binding:"required"`
		Label    string `json:"label" binding:"required"`
		Role     string `json:"role" binding:"required"` // theft/suspect/exchange/service/unknown
		Notes    string `json:"notes"`
		TaggedBy string `json:"taggedBy"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	inv.TagAddress(req.Address, req.Label, req.Role, req.Notes, req.TaggedBy)

	c.JSON(http.StatusOK, gin.H{
		"status":  "tagged",
		"address": req.Address,
		"label":   req.Label,
		"role":    req.Role,
	})
}

// GET /api/v1/investigation/:id/timeline
// Returns a chronological timeline of all investigation events.
func (h *APIHandler) handleGetTimeline(c *gin.Context) {
	caseID := c.Param("id")

	inv := h.invManager.GetInvestigation(caseID)
	if inv == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Investigation not found"})
		return
	}

	timeline := inv.GetTimeline()
	if timeline == nil {
		timeline = []heuristics.TimelineEvent{}
	}

	c.JSON(http.StatusOK, gin.H{
		"caseId": caseID,
		"events": timeline,
		"total":  len(timeline),
	})
}

// GET /api/v1/investigation/:id/exits
// Returns all identified exchange exit points where stolen funds
// were deposited — the key evidence for law enforcement subpoenas.
func (h *APIHandler) handleGetExchangeExits(c *gin.Context) {
	caseID := c.Param("id")

	inv := h.invManager.GetInvestigation(caseID)
	if inv == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Investigation not found"})
		return
	}

	exits := inv.GetExchangeExits()
	if exits == nil {
		exits = []heuristics.FlowNode{}
	}

	recovery := inv.ComputeRecovery()

	c.JSON(http.StatusOK, gin.H{
		"caseId":           caseID,
		"exchangeExits":    exits,
		"totalExits":       len(exits),
		"totalRecoverable": recovery,
		"totalStolen":      inv.TotalStolen,
		"recoveryRate":     safeDiv(float64(recovery), float64(inv.TotalStolen)),
	})
}

// safeDiv divides a by b, returning 0 if b is 0
func safeDiv(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return a / b
}
