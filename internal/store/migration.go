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
    description   TEXT    NOT NULL DEFAULT '',
    manifest      TEXT    NOT NULL DEFAULT ''
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

CREATE TABLE IF NOT EXISTS ignored_findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    -- fingerprint uniquely identifies a finding across scans.
    -- For code findings: scanner|rule_id|file
    -- For dep findings:  scanner|package|version|cve_id
    fingerprint       TEXT     NOT NULL UNIQUE,
    scanner           TEXT     NOT NULL,
    finding_type      TEXT     NOT NULL DEFAULT 'code',  -- 'code' | 'dep'
    reason            TEXT     NOT NULL DEFAULT 'no reason provided',
    ignored_at        DATETIME NOT NULL,
    -- original finding details for display in ignore list
    rule_id           TEXT     NOT NULL DEFAULT '',
    file              TEXT     NOT NULL DEFAULT '',
    package           TEXT     NOT NULL DEFAULT '',
    cve_id            TEXT     NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_code_findings_scan_id    ON code_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_dep_findings_scan_id     ON dependency_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_correlations_scan_id     ON correlations(scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_scan_id      ON risk_scores(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_started_at         ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ignored_fingerprint      ON ignored_findings(fingerprint);
`

const currentSchemaVersion = 4

// migrateV1ToV2 upgrades an existing v1 database to v2.
const migrateV1ToV2 = `
ALTER TABLE scans ADD COLUMN risk_score REAL NOT NULL DEFAULT 0.0;

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

INSERT INTO code_findings (id, scan_id, scanner, severity, rule_id, file, line, message, raw_match)
SELECT id, scan_id, scanner, severity, rule_id, file, line, message, raw_match
FROM findings;

DROP TABLE findings;

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

CREATE INDEX IF NOT EXISTS idx_code_findings_scan_id ON code_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_dep_findings_scan_id  ON dependency_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_correlations_scan_id  ON correlations(scan_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_scan_id   ON risk_scores(scan_id);

UPDATE schema_version SET version = 2;
`

// migrateV2ToV3 adds the ignored_findings table.
const migrateV2ToV3 = `
CREATE TABLE IF NOT EXISTS ignored_findings (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT     NOT NULL UNIQUE,
    scanner       TEXT     NOT NULL,
    finding_type  TEXT     NOT NULL DEFAULT 'code',
    reason        TEXT     NOT NULL DEFAULT 'no reason provided',
    ignored_at    DATETIME NOT NULL,
    rule_id       TEXT     NOT NULL DEFAULT '',
    file          TEXT     NOT NULL DEFAULT '',
    package       TEXT     NOT NULL DEFAULT '',
    cve_id        TEXT     NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ignored_fingerprint ON ignored_findings(fingerprint);

UPDATE schema_version SET version = 3;
`

// migrateV3ToV4 records which manifest or lockfile each dependency finding
// came from, so it can be linked to the source files that import it.
const migrateV3ToV4 = `
ALTER TABLE dependency_findings ADD COLUMN manifest TEXT NOT NULL DEFAULT '';

UPDATE schema_version SET version = 4;
`
