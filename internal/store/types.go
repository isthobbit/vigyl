package store

import (
	"fmt"
	"time"
)

// ScanRecord is one complete scan run persisted to the database.
type ScanRecord struct {
	ID        int64     `json:"id"`
	ScanPath  string    `json:"scan_path"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	// Scanners is a comma-separated list of scanners that ran: "secrets,sast,trivy,osv"
	Scanners  string  `json:"scanners"`
	Total     int     `json:"total_findings"`
	RiskScore float64 `json:"risk_score"`
}

// CodeFindingRecord is one finding from a code scanner (Gitleaks or Semgrep).
type CodeFindingRecord struct {
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

// CodeFingerprint returns a stable fingerprint for a code finding.
// Deliberately excludes line number so minor refactors don't break ignores.
func CodeFingerprint(scanner, ruleID, file string) string {
	return fmt.Sprintf("%s|%s|%s", scanner, ruleID, file)
}

// DepFindingRecord is one finding from a dependency scanner (Trivy or OSV).
type DepFindingRecord struct {
	ID           int64  `json:"id"`
	ScanID       int64  `json:"scan_id"`
	Scanner      string `json:"scanner"`       // "trivy" | "osv"
	Severity     string `json:"severity"`      // CRITICAL | HIGH | MEDIUM | LOW
	Package      string `json:"package"`       // e.g. "github.com/foo/bar"
	Version      string `json:"version"`       // e.g. "1.2.3"
	CVEID        string `json:"cve_id"`        // e.g. "CVE-2024-12345" (empty if none)
	Ecosystem    string `json:"ecosystem"`     // e.g. "Go" | "npm" | "PyPI"
	FixedVersion string `json:"fixed_version"` // e.g. "1.2.4" (empty if no fix available)
	Description  string `json:"description"`
}

// DepFingerprint returns a stable fingerprint for a dependency finding.
func DepFingerprint(scanner, pkg, version, cveID string) string {
	return fmt.Sprintf("%s|%s|%s|%s", scanner, pkg, version, cveID)
}

// CorrelationRecord links two findings from different scanners.
type CorrelationRecord struct {
	ID               int64   `json:"id"`
	ScanID           int64   `json:"scan_id"`
	CodeFindingID    *int64  `json:"code_finding_id,omitempty"`
	DepFindingID     *int64  `json:"dep_finding_id,omitempty"`
	Reason           string  `json:"reason"` // e.g. "secret_in_vulnerable_file"
	CorrelationScore float64 `json:"correlation_score"`
	Directional      bool    `json:"directional"`
	SourceFindingID  *int64  `json:"source_finding_id,omitempty"` // populated when Directional=true
	TargetFindingID  *int64  `json:"target_finding_id,omitempty"` // populated when Directional=true
}

// RiskScoreRecord holds a rolled-up risk score for a scan, file, or package.
// File and Package are mutually exclusive; both nil means the overall scan score.
type RiskScoreRecord struct {
	ID                       int64   `json:"id"`
	ScanID                   int64   `json:"scan_id"`
	File                     *string `json:"file,omitempty"`
	Package                  *string `json:"package,omitempty"`
	Score                    float64 `json:"score"`
	ContributingFindingCount int     `json:"contributing_finding_count"`
}

// IgnoredFindingRecord is a finding that has been marked as ignored.
type IgnoredFindingRecord struct {
	ID          int64     `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	Scanner     string    `json:"scanner"`
	FindingType string    `json:"finding_type"` // "code" | "dep"
	Reason      string    `json:"reason"`
	IgnoredAt   time.Time `json:"ignored_at"`
	// Display fields — populated from the original finding at ignore time.
	RuleID  string `json:"rule_id"`
	File    string `json:"file"`
	Package string `json:"package"`
	CVEID   string `json:"cve_id"`
}

// RiskBand maps a numeric risk score to a named severity band.
type RiskBand string

const (
	RiskBandLow      RiskBand = "LOW"
	RiskBandMedium   RiskBand = "MEDIUM"
	RiskBandHigh     RiskBand = "HIGH"
	RiskBandCritical RiskBand = "CRITICAL"
	RiskBandSevere   RiskBand = "SEVERE"
)

// BandFromScore returns the named risk band for a given numeric score.
func BandFromScore(score float64) RiskBand {
	switch {
	case score <= 2.0:
		return RiskBandLow
	case score <= 4.0:
		return RiskBandMedium
	case score <= 6.0:
		return RiskBandHigh
	case score <= 8.0:
		return RiskBandCritical
	default:
		return RiskBandSevere
	}
}

// BandDescription returns the human-readable description for a risk band.
func BandDescription(band RiskBand) string {
	switch band {
	case RiskBandLow:
		return "No significant issues detected"
	case RiskBandMedium:
		return "Some issues worth addressing"
	case RiskBandHigh:
		return "Significant issues requiring attention"
	case RiskBandCritical:
		return "Serious issues requiring immediate action"
	case RiskBandSevere:
		return "Multiple critical issues, do not ship"
	default:
		return "Unknown"
	}
}
