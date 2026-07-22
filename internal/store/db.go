package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO required
)

// DB wraps a SQLite connection and exposes jensec-specific operations.
type DB struct {
	conn *sql.DB
}

// Open opens (or creates) the jensec SQLite database.
//
// If dbPath is non-empty it is used as-is (honouring storage.db_path from the
// config file). Otherwise the default location ~/.kinga/jensec.db is used.
// The parent directory is created if it does not exist.
func Open(dbPath ...string) (*DB, error) {
	var resolvedPath string
	if len(dbPath) > 0 && dbPath[0] != "" {
		resolvedPath = dbPath[0]
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not find home directory: %w", err)
		}
		resolvedPath = filepath.Join(home, ".kinga", "jensec.db")
	}

	dir := filepath.Dir(resolvedPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("could not create config directory: %w", err)
	}

	conn, err := sql.Open("sqlite", resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %w", err)
	}

	// SQLite performs best with a single writer connection.
	conn.SetMaxOpenConns(1)

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	return db, nil
}

// Close releases the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate applies the schema and runs any pending version upgrades.
func (db *DB) migrate() error {
	// Read the current schema version (0 = fresh database).
	var current int
	db.conn.QueryRow(`
		SELECT COALESCE(MAX(version), 0)
		FROM schema_version
		WHERE EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version')
	`).Scan(&current)

	switch {
	case current == 0:
		// Fresh database — apply v2 schema and stamp version.
		if _, err := db.conn.Exec(schemaV2); err != nil {
			return fmt.Errorf("applying v2 schema: %w", err)
		}
		_, err := db.conn.Exec(`INSERT INTO schema_version (version) VALUES (?)`, currentSchemaVersion)
		return err

	case current < 2:
		// Existing v1 database — run the v1→v2 migration.
		if err := db.applyMigration(migrateV1ToV2); err != nil {
			return fmt.Errorf("migrating v1 to v2: %w", err)
		}
	}

	return nil
}

// applyMigration executes a multi-statement migration string inside a
// transaction, rolling back on any error.
func (db *DB) applyMigration(migration string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(migration); err != nil {
		return err
	}

	return tx.Commit()
}

// SaveScan persists a complete scan run and its code findings in a single
// transaction. Returns the ID assigned to the scan row.
func (db *DB) SaveScan(path, scanners string, startedAt, endedAt time.Time, findings []CodeFindingRecord) (int64, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert scan record.
	res, err := tx.Exec(
		`INSERT INTO scans (scan_path, started_at, ended_at, scanners, total) VALUES (?, ?, ?, ?, ?)`,
		path, startedAt.UTC(), endedAt.UTC(), scanners, len(findings),
	)
	if err != nil {
		return 0, fmt.Errorf("could not insert scan: %w", err)
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	// Insert each code finding.
	stmt, err := tx.Prepare(`
		INSERT INTO code_findings (scan_id, scanner, severity, rule_id, file, line, message, raw_match)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("could not prepare finding insert: %w", err)
	}
	defer stmt.Close()

	for _, f := range findings {
		if _, err := stmt.Exec(scanID, f.Scanner, f.Severity, f.RuleID, f.File, f.Line, f.Message, f.RawMatch); err != nil {
			return 0, fmt.Errorf("could not insert finding: %w", err)
		}
	}

	return scanID, tx.Commit()
}

// SaveDependencyFindings persists dependency findings for a scan.
func (db *DB) SaveDependencyFindings(scanID int64, findings []DepFindingRecord) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO dependency_findings (scan_id, scanner, severity, package, version, cve_id, ecosystem, fixed_version, description)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("could not prepare dependency finding insert: %w", err)
	}
	defer stmt.Close()

	for _, f := range findings {
		if _, err := stmt.Exec(scanID, f.Scanner, f.Severity, f.Package, f.Version, f.CVEID, f.Ecosystem, f.FixedVersion, f.Description); err != nil {
			return fmt.Errorf("could not insert dependency finding: %w", err)
		}
	}

	return tx.Commit()
}

// SaveCorrelations persists correlation records for a scan.
func (db *DB) SaveCorrelations(scanID int64, correlations []CorrelationRecord) error {
	if len(correlations) == 0 {
		return nil
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO correlations (scan_id, code_finding_id, dep_finding_id, reason, correlation_score, directional, source_finding_id, target_finding_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("could not prepare correlation insert: %w", err)
	}
	defer stmt.Close()

	for _, c := range correlations {
		directional := 0
		if c.Directional {
			directional = 1
		}
		if _, err := stmt.Exec(
			scanID,
			c.CodeFindingID,
			c.DepFindingID,
			c.Reason,
			c.CorrelationScore,
			directional,
			c.SourceFindingID,
			c.TargetFindingID,
		); err != nil {
			return fmt.Errorf("could not insert correlation: %w", err)
		}
	}

	return tx.Commit()
}

// SaveRiskScores persists file-level, package-level, and overall risk scores.
func (db *DB) SaveRiskScores(scanID int64, fileScores, pkgScores []RiskScoreRecord, overall float64) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO risk_scores (scan_id, file, package, score, contributing_finding_count)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("could not prepare risk score insert: %w", err)
	}
	defer stmt.Close()

	// Insert file-level scores.
	for _, s := range fileScores {
		if _, err := stmt.Exec(scanID, s.File, nil, s.Score, s.ContributingFindingCount); err != nil {
			return fmt.Errorf("could not insert file risk score: %w", err)
		}
	}

	// Insert package-level scores.
	for _, s := range pkgScores {
		if _, err := stmt.Exec(scanID, nil, s.Package, s.Score, s.ContributingFindingCount); err != nil {
			return fmt.Errorf("could not insert package risk score: %w", err)
		}
	}

	// Insert overall score (both file and package are null).
	if _, err := stmt.Exec(scanID, nil, nil, overall, 0); err != nil {
		return fmt.Errorf("could not insert overall risk score: %w", err)
	}

	return tx.Commit()
}

// UpdateScanRiskScore updates the overall risk_score on the scans table.
func (db *DB) UpdateScanRiskScore(scanID int64, score float64) error {
	_, err := db.conn.Exec(
		`UPDATE scans SET risk_score = ? WHERE id = ?`,
		score, scanID,
	)
	return err
}

// LatestScan returns the most recent scan record, or nil if none exist.
func (db *DB) LatestScan() (*ScanRecord, error) {
	row := db.conn.QueryRow(`
		SELECT id, scan_path, started_at, ended_at, scanners, total, risk_score
		FROM scans
		ORDER BY started_at DESC
		LIMIT 1
	`)
	return scanFromRow(row)
}

// ScanByID returns a specific scan record by ID.
func (db *DB) ScanByID(id int64) (*ScanRecord, error) {
	row := db.conn.QueryRow(`
		SELECT id, scan_path, started_at, ended_at, scanners, total, risk_score
		FROM scans WHERE id = ?
	`, id)
	return scanFromRow(row)
}

// CodeFindingsForScan returns all code findings for a given scan ID.
func (db *DB) CodeFindingsForScan(scanID int64) ([]CodeFindingRecord, error) {
	rows, err := db.conn.Query(`
		SELECT id, scan_id, scanner, severity, rule_id, file, line, message, raw_match
		FROM code_findings
		WHERE scan_id = ?
		ORDER BY severity, file, line
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []CodeFindingRecord
	for rows.Next() {
		var f CodeFindingRecord
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Scanner, &f.Severity, &f.RuleID, &f.File, &f.Line, &f.Message, &f.RawMatch); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// DepFindingsForScan returns all dependency findings for a given scan ID.
func (db *DB) DepFindingsForScan(scanID int64) ([]DepFindingRecord, error) {
	rows, err := db.conn.Query(`
		SELECT id, scan_id, scanner, severity, package, version, cve_id, ecosystem, fixed_version, description
		FROM dependency_findings
		WHERE scan_id = ?
		ORDER BY severity, package
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []DepFindingRecord
	for rows.Next() {
		var f DepFindingRecord
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Scanner, &f.Severity, &f.Package, &f.Version, &f.CVEID, &f.Ecosystem, &f.FixedVersion, &f.Description); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// RecentScans returns the n most recent scan records.
func (db *DB) RecentScans(n int) ([]ScanRecord, error) {
	rows, err := db.conn.Query(`
		SELECT id, scan_path, started_at, ended_at, scanners, total, risk_score
		FROM scans
		ORDER BY started_at DESC
		LIMIT ?
	`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanRecord
	for rows.Next() {
		var s ScanRecord
		if err := rows.Scan(&s.ID, &s.ScanPath, &s.StartedAt, &s.EndedAt, &s.Scanners, &s.Total, &s.RiskScore); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

func scanFromRow(row *sql.Row) (*ScanRecord, error) {
	var s ScanRecord
	err := row.Scan(&s.ID, &s.ScanPath, &s.StartedAt, &s.EndedAt, &s.Scanners, &s.Total, &s.RiskScore)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}
