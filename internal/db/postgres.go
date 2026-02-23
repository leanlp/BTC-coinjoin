package db

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rawblock/coinjoin-engine/pkg/models"
)

// schemaSQL is compiled into the binary at build time.
// This ensures schema init works inside the Docker runtime image which
// does not copy internal/db/schema.sql into the final stage.
//
//go:embed schema.sql
var schemaSQL string

type PostgresStore struct {
	pool *pgxpool.Pool
}

// Connect initializes the connection pool to PostgreSQL using pgx
func Connect(connStr string) (*PostgresStore, error) {
	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %v", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping failed: %v", err)
	}

	log.Println("Successfully connected to PostgreSQL for Forensics Engine")
	return &PostgresStore{pool: pool}, nil
}

// Close gracefully closes the connection pool
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// InitSchema executes the embedded schema.sql DDL statements.
func (s *PostgresStore) InitSchema() error {
	_, err := s.pool.Exec(context.Background(), schemaSQL)
	if err != nil {
		return fmt.Errorf("failed to execute schema migrations: %v", err)
	}

	log.Println("Coinjoin Forensics Schema initialized")
	return nil
}

// SaveAnalysisResult persists the computed heuristics and the evidence graph
func (s *PostgresStore) SaveAnalysisResult(ctx context.Context, blockHeight int, result models.PrivacyAnalysisResult) error {
	// 1. Begin Transaction
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 2. Insert main heuristic row
	insertHeuristicSQL := `
		INSERT INTO tx_heuristics (block_height, txid, heuristic_flags, anonset_local)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (block_height, txid) DO UPDATE 
		SET heuristic_flags = EXCLUDED.heuristic_flags, anonset_local = EXCLUDED.anonset_local;
	`
	_, err = tx.Exec(ctx, insertHeuristicSQL, blockHeight, result.Txid, result.HeuristicFlags, result.AnonSet)
	if err != nil {
		return fmt.Errorf("failed to insert tx_heuristics: %v", err)
	}

	// 3. Batch insert the evidence edges
	if len(result.Edges) > 0 {
		insertEdgeSQL := `
			INSERT INTO evidence_edge 
			(created_height, src_node_id, dst_node_id, edge_type, llr_score, dependency_group, snapshot_id, audit_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
		`
		for _, edge := range result.Edges {
			auditHash := edge.AuditHash
			if auditHash == "" {
				// Backward compatibility for older edge generators.
				auditHash = edge.EdgeID
			}
			_, err = tx.Exec(ctx, insertEdgeSQL,
				blockHeight,
				edge.SrcNodeID,
				edge.DstNodeID,
				edge.EdgeType,
				edge.LLRScore,
				edge.DependencyGroup,
				edge.SnapshotID,
				auditHash,
			)
			if err != nil {
				return fmt.Errorf("failed to insert evidence edge: %v", err)
			}
		}
	}

	// 4. Commit transaction
	return tx.Commit(ctx)
}

// SaveAnonSetWindow persists the time-evolving anonymity set windows
func (s *PostgresStore) SaveAnonSetWindow(ctx context.Context, txid string, outputIndex int, anonsetLocal int) error {
	sql := `
		INSERT INTO anonset_windows (txid, output_index, anonset_local)
		VALUES ($1, $2, $3)
		ON CONFLICT (txid, output_index) DO UPDATE
		SET anonset_local = EXCLUDED.anonset_local, last_updated = NOW();
	`
	_, err := s.pool.Exec(ctx, sql, txid, outputIndex, anonsetLocal)
	return err
}

// UpdateAnonSetWindows updates a specific time window column for an output
func (s *PostgresStore) UpdateAnonSetWindows(ctx context.Context, txid string, outputIndex int, window string, value int) error {
	// Validate the window parameter to prevent SQL injection
	validWindows := map[string]bool{
		"anonset_1d": true, "anonset_7d": true, "anonset_30d": true, "anonset_365d": true,
	}
	if !validWindows[window] {
		return fmt.Errorf("invalid window: %s", window)
	}

	sql := fmt.Sprintf("UPDATE anonset_windows SET %s = $1, last_updated = NOW() WHERE txid = $2 AND output_index = $3", window)
	_, err := s.pool.Exec(ctx, sql, value, txid, outputIndex)
	return err
}

// GetMixers queries the heuristics table for any known CoinJoin transactions.
// It uses bitwise operations to match FlagIsWhirlpoolStruct (8) and FlagIsWasabiSuspect (8388608).
type MixerInfo struct {
	BlockHeight    int    `json:"blockHeight"`
	Txid           string `json:"txid"`
	HeuristicFlags int64  `json:"heuristicFlags"`
	AnonsetLocal   int    `json:"anonsetLocal"`
	MixerType      string `json:"mixerType"`
}

func (s *PostgresStore) GetMixers(ctx context.Context, page int, limit int) ([]MixerInfo, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit

	// Get total count first
	var totalCount int
	countSQL := `SELECT COUNT(*) FROM tx_heuristics WHERE (heuristic_flags & 8) > 0 OR (heuristic_flags & 8388608) > 0`
	err := s.pool.QueryRow(ctx, countSQL).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	dataSQL := `
		SELECT block_height, txid, heuristic_flags, anonset_local
		FROM tx_heuristics 
		WHERE (heuristic_flags & 8) > 0 OR (heuristic_flags & 8388608) > 0
		ORDER BY block_height DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := s.pool.Query(ctx, dataSQL, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var mixers []MixerInfo
	for rows.Next() {
		var m MixerInfo
		var anonset *int
		err := rows.Scan(&m.BlockHeight, &m.Txid, &m.HeuristicFlags, &anonset)
		if err != nil {
			return nil, 0, err
		}
		if anonset != nil {
			m.AnonsetLocal = *anonset
		}

		if (m.HeuristicFlags & 8) > 0 {
			m.MixerType = "Whirlpool"
		} else if (m.HeuristicFlags & 8388608) > 0 {
			m.MixerType = "WabiSabi"
		} else {
			m.MixerType = "CoinJoin"
		}
		mixers = append(mixers, m)
	}
	if mixers == nil {
		mixers = []MixerInfo{}
	}
	return mixers, totalCount, nil
}

// GetPool exposes the connection pool for the shadow runner and other subsystems
func (s *PostgresStore) GetPool() *pgxpool.Pool {
	return s.pool
}

type InvestigationSeed struct {
	CaseID  string
	Name    string
	Address string
	Role    string
	Label   string
}

// SaveInvestigation upserts investigation metadata for durable case storage.
func (s *PostgresStore) SaveInvestigation(ctx context.Context, caseID, name, description string, totalStolen int64) error {
	sql := `
		INSERT INTO investigations (case_id, name, description, total_stolen, status)
		VALUES ($1, $2, $3, $4, 'active')
		ON CONFLICT (case_id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			total_stolen = EXCLUDED.total_stolen,
			status = 'active',
			updated_at = NOW();
	`
	_, err := s.pool.Exec(ctx, sql, caseID, name, description, totalStolen)
	return err
}

// SaveInvestigationAddress upserts an investigation-tagged address.
func (s *PostgresStore) SaveInvestigationAddress(ctx context.Context, caseID, address, label, role, notes, taggedBy string) error {
	sql := `
		WITH target AS (
			SELECT id FROM investigations WHERE case_id = $1
		),
		updated AS (
			UPDATE investigation_addresses a
			SET
				label = $3,
				role = $4,
				notes = $5,
				tagged_by = $6,
				tagged_at = NOW()
			FROM target
			WHERE a.investigation_id = target.id
				AND a.address = $2
			RETURNING a.id
		)
		INSERT INTO investigation_addresses
			(investigation_id, address, label, role, notes, tagged_by, tagged_at)
		SELECT target.id, $2, $3, $4, $5, $6, NOW()
		FROM target
		WHERE NOT EXISTS (SELECT 1 FROM updated);
	`
	result, err := s.pool.Exec(ctx, sql, caseID, address, label, role, notes, taggedBy)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("investigation case_id not found: %s", caseID)
	}
	return nil
}

// LoadActiveInvestigationSeeds loads active tagged addresses for warm-starting
// watchlist + taint map on process boot.
func (s *PostgresStore) LoadActiveInvestigationSeeds(ctx context.Context) ([]InvestigationSeed, error) {
	sql := `
		SELECT i.case_id, i.name, a.address, a.role, COALESCE(a.label, '')
		FROM investigations i
		JOIN investigation_addresses a ON a.investigation_id = i.id
		WHERE i.status = 'active';
	`
	rows, err := s.pool.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seeds := make([]InvestigationSeed, 0)
	for rows.Next() {
		var seed InvestigationSeed
		if err := rows.Scan(&seed.CaseID, &seed.Name, &seed.Address, &seed.Role, &seed.Label); err != nil {
			return nil, err
		}
		seeds = append(seeds, seed)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return seeds, nil
}

// SaveRiskAssessment persists the risk assessment for ANY analyzed transaction.
// Unlike SaveAnalysisResult (which only stores CoinJoin-flagged txs), this
// stores a risk row for every tx processed by the pipeline, enabling
// scam investigation and entity-level risk scoring.
func (s *PostgresStore) SaveRiskAssessment(ctx context.Context, blockHeight int, txid string,
	riskScore int, riskLevel string, privacyScore int, flags uint64,
	taintLevel float64, numInputs, numOutputs int, totalValueSats int64) error {

	sql := `
		INSERT INTO risk_assessments
			(txid, block_height, risk_score, risk_level, privacy_score, heuristic_flags,
			 taint_level, num_inputs, num_outputs, total_value_sats)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (txid) DO UPDATE SET
			block_height = EXCLUDED.block_height,
			risk_score = EXCLUDED.risk_score,
			risk_level = EXCLUDED.risk_level,
			privacy_score = EXCLUDED.privacy_score,
			heuristic_flags = EXCLUDED.heuristic_flags,
			taint_level = EXCLUDED.taint_level,
			num_inputs = EXCLUDED.num_inputs,
			num_outputs = EXCLUDED.num_outputs,
			total_value_sats = EXCLUDED.total_value_sats,
			analyzed_at = NOW();
	`
	_, err := s.pool.Exec(ctx, sql, txid, blockHeight, riskScore, riskLevel,
		privacyScore, int64(flags), taintLevel, numInputs, numOutputs, totalValueSats)
	return err
}
