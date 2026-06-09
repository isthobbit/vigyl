package store

// schema is applied once on first open via a simple version check.
// We keep migrations additive so existing databases are never broken.
const schema = `
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

const currentSchemaVersion = 1
