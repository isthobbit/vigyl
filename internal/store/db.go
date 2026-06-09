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
// All DDL uses CREATE IF NOT EXISTS so it is safe to re-run against an existing DB.
func (db *DB) migrate() error {
	// Apply base DDL.
	if _, err := db.conn.Exec(schema); err != nil {
		return err
	}

	// Read the current schema version (0 if the table is empty, i.e. fresh DB).
	var current int
	db.conn.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current)

	if current == 0 {
		// Fresh database — stamp with the current version; no migrations needed.
		_, err := db.conn.Exec(`INSERT INTO schema_version (version) VALUES (?)`, currentSchemaVersion)
		return err
	}

	// Future migrations go here, e.g.:
	//   if current < 2 { applyV2(db.conn) }
	// Each step should bump schema_version to the new version number.

	return nil
}

// SaveScan persists a complete scan run and its findings in a single transaction.
// It returns the ID assigned to the scan row.
func (db *DB) SaveScan(path, scanners string, startedAt, endedAt time.Time, findings []FindingRecord) (int64, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback() // no-op if Commit succeeds

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

	// Insert each finding.
	stmt, err := tx.Prepare(`
		INSERT INTO findings (scan_id, scanner, severity, rule_id, file, line, message, raw_match)
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

// LatestScan returns the most recent scan record, or nil if none exist.
func (db *DB) LatestScan() (*ScanRecord, error) {
	row := db.conn.QueryRow(`
		SELECT id, scan_path, started_at, ended_at, scanners, total
		FROM scans
		ORDER BY started_at DESC
		LIMIT 1
	`)
	return scanFromRow(row)
}

// ScanByID returns a specific scan record by ID.
func (db *DB) ScanByID(id int64) (*ScanRecord, error) {
	row := db.conn.QueryRow(`
		SELECT id, scan_path, started_at, ended_at, scanners, total
		FROM scans WHERE id = ?
	`, id)
	return scanFromRow(row)
}

// FindingsForScan returns all findings for a given scan ID.
func (db *DB) FindingsForScan(scanID int64) ([]FindingRecord, error) {
	rows, err := db.conn.Query(`
		SELECT id, scan_id, scanner, severity, rule_id, file, line, message, raw_match
		FROM findings
		WHERE scan_id = ?
		ORDER BY severity, file, line
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []FindingRecord
	for rows.Next() {
		var f FindingRecord
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Scanner, &f.Severity, &f.RuleID, &f.File, &f.Line, &f.Message, &f.RawMatch); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// RecentScans returns the n most recent scan records.
func (db *DB) RecentScans(n int) ([]ScanRecord, error) {
	rows, err := db.conn.Query(`
		SELECT id, scan_path, started_at, ended_at, scanners, total
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
		if err := rows.Scan(&s.ID, &s.ScanPath, &s.StartedAt, &s.EndedAt, &s.Scanners, &s.Total); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

func scanFromRow(row *sql.Row) (*ScanRecord, error) {
	var s ScanRecord
	err := row.Scan(&s.ID, &s.ScanPath, &s.StartedAt, &s.EndedAt, &s.Scanners, &s.Total)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}
