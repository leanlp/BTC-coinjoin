package shadow

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rawblock/coinjoin-engine/internal/heuristics"
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// ShadowRunner executes experimental heuristics in parallel against production data.
// No new heuristic affects production clusters immediately.
// All new classifiers run in "shadow mode" for a multi-week observation window.
type ShadowRunner struct {
	pool            *pgxpool.Pool
	shadowSnapshotID int64
	productionFunc  func(tx models.Transaction) models.PrivacyAnalysisResult
	shadowFunc      func(tx models.Transaction) models.PrivacyAnalysisResult
}

// ShadowResult captures the diff between production and shadow heuristics.
type ShadowResult struct {
	Txid            string    `json:"txid"`
	ShadowFlags     uint64    `json:"shadowFlags"`
	ProductionFlags uint64    `json:"productionFlags"`
	DeltaAnonSet    int       `json:"deltaAnonset"`
	SnapshotID      int64     `json:"snapshotId"`
	CreatedAt       time.Time `json:"createdAt"`
}

// NewShadowRunner creates a runner that compares production vs experimental heuristics.
func NewShadowRunner(pool *pgxpool.Pool, shadowSnapshotID int64) *ShadowRunner {
	return &ShadowRunner{
		pool:            pool,
		shadowSnapshotID: shadowSnapshotID,
		productionFunc:  heuristics.AnalyzeTx,
		shadowFunc:      heuristics.AnalyzeTx, // Replace with experimental heuristic
	}
}

// RunShadowAnalysis executes both production and shadow heuristics on a transaction
// and persists the comparison to the shadow_results table.
func (sr *ShadowRunner) RunShadowAnalysis(ctx context.Context, tx models.Transaction) (*ShadowResult, error) {
	// Run production heuristics
	prodResult := sr.productionFunc(tx)

	// Run shadow (experimental) heuristics
	shadowResult := sr.shadowFunc(tx)

	result := &ShadowResult{
		Txid:            tx.Txid,
		ShadowFlags:     shadowResult.HeuristicFlags,
		ProductionFlags: prodResult.HeuristicFlags,
		DeltaAnonSet:    shadowResult.AnonSet - prodResult.AnonSet,
		SnapshotID:      sr.shadowSnapshotID,
		CreatedAt:       time.Now(),
	}

	// Log divergences for monitoring
	if result.ShadowFlags != result.ProductionFlags {
		log.Printf("[Shadow] DIVERGENCE on %s: prod_flags=0x%X shadow_flags=0x%X delta_anonset=%d",
			tx.Txid, result.ProductionFlags, result.ShadowFlags, result.DeltaAnonSet)
	}

	// Persist to shadow_results table (never to evidence_edge)
	if sr.pool != nil {
		err := sr.persistShadowResult(ctx, result)
		if err != nil {
			return result, err
		}
	}

	return result, nil
}

// persistShadowResult writes the shadow comparison to the database.
func (sr *ShadowRunner) persistShadowResult(ctx context.Context, result *ShadowResult) error {
	sql := `INSERT INTO shadow_results 
		(txid, shadow_flags, production_flags, delta_anonset, snapshot_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := sr.pool.Exec(ctx, sql,
		result.Txid,
		result.ShadowFlags,
		result.ProductionFlags,
		result.DeltaAnonSet,
		result.SnapshotID,
		result.CreatedAt,
	)
	return err
}

// GenerateDriftReport computes the divergence rate between shadow and production
// over all shadow results in the database.
func (sr *ShadowRunner) GenerateDriftReport(ctx context.Context) (totalRuns int, divergences int, avgDeltaAnonSet float64, err error) {
	sql := `SELECT 
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE shadow_flags != production_flags) as divergences,
		COALESCE(AVG(delta_anonset), 0) as avg_delta
	FROM shadow_results WHERE snapshot_id = $1`

	row := sr.pool.QueryRow(ctx, sql, sr.shadowSnapshotID)
	err = row.Scan(&totalRuns, &divergences, &avgDeltaAnonSet)
	return
}
