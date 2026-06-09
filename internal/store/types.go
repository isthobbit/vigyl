package store

import "time"

// ScanRecord is one complete scan run persisted to the database.
type ScanRecord struct {
	ID        int64     `json:"id"`
	ScanPath  string    `json:"scan_path"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	// Scanners is a comma-separated list of scanners that ran: "secrets,sast"
	Scanners string `json:"scanners"`
	Total    int    `json:"total_findings"`
}

// FindingRecord is one finding from any scanner, stored flat.
type FindingRecord struct {
	ID       int64  `json:"id"`
	ScanID   int64  `json:"scan_id"`
	Scanner  string `json:"scanner"`  // "secrets" | "sast"
	Severity string `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW
	RuleID   string `json:"rule_id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
	// RawMatch holds the redacted match string (secrets) or code line (sast).
	RawMatch string `json:"raw_match"`
}
