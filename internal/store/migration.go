package store

// schemaV1 is the original schema applied on first open for fresh databases.
// Kept for reference — existing v1 databases are upgraded via migrateV1ToV2.
const schemaV1 = `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_path   TEXT    NOT NULL,
    started_at  DATETIME NOT NULL,
    ended_at    DATETIME NOT NULL,
    scanners    TEXT    NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner   TEXT    NOT NULL,
    severity  TEXT    NOT NULL,
    rule_id   TEXT    NOT NULL,
    file      TEXT    NOT NULL,
    line      INTEGER NOT NULL DEFAULT 0,
    message   TEXT    NOT NULL,
    raw_match TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
`

// schemaV2 is the full v2 schema applied to fresh databases.
// Existing v1 databases are upgraded via migrateV1ToV2 instead.
const schemaV2 = `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_path   TEXT     NOT NULL,
    started_at  DATETIME NOT NULL,
    ended_at    DATETIME NOT NULL,
    scanners    TEXT     NOT NULL,
    total       INTEGER  NOT NULL DEFAULT 0,
    risk_score  REAL     NOT NULL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS code_findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner   TEXT    NOT NULL,
    severity  TEXT    NOT NULL,
    rule_id   TEXT    NOT NULL,
    file      TEXT    NOT NULL,
    line      INTEGER NOT NULL DEFAULT 0,
    message   TEXT    NOT NULL,
    raw_match TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dependency_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner       TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    package       TEXT    NOT NULL,
    version       TEXT    NOT NULL,
    cve_id        TEXT    NOT NULL DEFAULT '',
    ecosystem     TEXT    NOT NULL DEFAULT '',
    fixed_version TEXT    NOT NULL DEFAULT '',
    description   TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS correlations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    code_finding_id   INTEGER REFERENCES code_findings(id) ON DELETE CASCADE,
    dep_finding_id    INTEGER REFERENCES dependency_findings(id) ON DELETE CASCADE,
    reason            TEXT    NOT NULL,
    correlation_score REAL    NOT NULL DEFAULT 0.0,
    directional       INTEGER NOT NULL DEFAULT 0,
    source_finding_id INTEGER,
    target_finding_id INTEGER
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id                    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file                       TEXT,
    package                    TEXT,
    score                      REAL    NOT NULL DEFAULT 0.0,
    contributing_finding_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_code_findings_scan_id    ON code_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_dep_findings_scan_id     ON dependency_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_correlations_scan_id     ON correlations(scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_scan_id      ON risk_scores(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_started_at         ON scans(started_at DESC);
`

const currentSchemaVersion = 2

// migrateV1ToV2 upgrades an existing v1 database to v2.
//
// SQLite does not support ALTER TABLE ... RENAME TABLE directly in all
// contexts, so we use the standard create-copy-drop-rename pattern.
// All operations run inside the caller's transaction.
const migrateV1ToV2 = `
-- 1. Add risk_score column to scans (safe to run even if it already exists
--    via the migration guard in migrate()).
ALTER TABLE scans ADD COLUMN risk_score REAL NOT NULL DEFAULT 0.0;

-- 2. Create code_findings as a copy of findings schema.
CREATE TABLE IF NOT EXISTS code_findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner   TEXT    NOT NULL,
    severity  TEXT    NOT NULL,
    rule_id   TEXT    NOT NULL,
    file      TEXT    NOT NULL,
    line      INTEGER NOT NULL DEFAULT 0,
    message   TEXT    NOT NULL,
    raw_match TEXT    NOT NULL DEFAULT ''
);

-- 3. Copy all existing findings into code_findings.
INSERT INTO code_findings (id, scan_id, scanner, severity, rule_id, file, line, message, raw_match)
SELECT id, scan_id, scanner, severity, rule_id, file, line, message, raw_match
FROM findings;

-- 4. Drop the old findings table.
DROP TABLE findings;

-- 5. Create new v2 tables.
CREATE TABLE IF NOT EXISTS dependency_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner       TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    package       TEXT    NOT NULL,
    version       TEXT    NOT NULL,
    cve_id        TEXT    NOT NULL DEFAULT '',
    ecosystem     TEXT    NOT NULL DEFAULT '',
    fixed_version TEXT    NOT NULL DEFAULT '',
    description   TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS correlations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    code_finding_id   INTEGER REFERENCES code_findings(id) ON DELETE CASCADE,
    dep_finding_id    INTEGER REFERENCES dependency_findings(id) ON DELETE CASCADE,
    reason            TEXT    NOT NULL,
    correlation_score REAL    NOT NULL DEFAULT 0.0,
    directional       INTEGER NOT NULL DEFAULT 0,
    source_finding_id INTEGER,
    target_finding_id INTEGER
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id                    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file                       TEXT,
    package                    TEXT,
    score                      REAL    NOT NULL DEFAULT 0.0,
    contributing_finding_count INTEGER NOT NULL DEFAULT 0
);

-- 6. Recreate indexes.
CREATE INDEX IF NOT EXISTS idx_code_findings_scan_id ON code_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_dep_findings_scan_id  ON dependency_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_correlations_scan_id  ON correlations(scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_scan_id   ON risk_scores(scan_id);

-- 7. Bump schema version.
UPDATE schema_version SET version = 2;
`
