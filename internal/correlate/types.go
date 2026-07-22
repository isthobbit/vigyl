package correlate

import "github.com/isthobbit/vigil/internal/store"

// Input holds all findings from a single scan, ready for correlation.
type Input struct {
	ScanID       int64
	CodeFindings []store.CodeFindingRecord
	DepFindings  []store.DepFindingRecord
}

// CorrelationRule defines a single correlation rule with its weight and type.
type CorrelationRule struct {
	Reason      string
	Weight      float64
	Directional bool
}

// DefaultRules are the seven correlation rules with their default weights.
// All weights are overridable via config.
var DefaultRules = []CorrelationRule{
	{Reason: "secret_in_vulnerable_file", Weight: 1.0, Directional: true},
	{Reason: "vuln_code_in_vulnerable_file", Weight: 0.8, Directional: true},
	{Reason: "cve_confirmed_by_multiple_scanners", Weight: 0.7, Directional: true},
	{Reason: "secret_and_vuln_in_same_file", Weight: 0.6, Directional: false},
	{Reason: "package_confirmed_by_multiple_scanners", Weight: 0.6, Directional: false},
	{Reason: "multiple_cves_in_same_package", Weight: 0.5, Directional: false},
	{Reason: "multiple_vulns_in_same_file", Weight: 0.4, Directional: false},
}

// severityRank maps severity strings to numeric ranks for scoring.
var severityRank = map[string]float64{
	"LOW":      1.0,
	"MEDIUM":   2.0,
	"HIGH":     3.0,
	"CRITICAL": 4.0,
}

// RiskBandThresholds maps score ranges to named bands.
// Scores above 8.0 are SEVERE.
var RiskBandThresholds = []struct {
	Max  float64
	Band store.RiskBand
}{
	{2.0, store.RiskBandLow},
	{4.0, store.RiskBandMedium},
	{6.0, store.RiskBandHigh},
	{8.0, store.RiskBandCritical},
	{10.0, store.RiskBandSevere},
}

// correlation is an internal representation before it is persisted.
type correlation struct {
	CodeFindingID   *int64
	DepFindingID    *int64
	Reason          string
	Score           float64
	Directional     bool
	SourceFindingID *int64
	TargetFindingID *int64
}

// fileRiskEntry accumulates risk score data for a single file.
type fileRiskEntry struct {
	File          string
	BaseScore     float64
	CompoundBonus float64
	FindingCount  int
}

// packageRiskEntry accumulates risk score data for a single package.
type packageRiskEntry struct {
	Package       string
	BaseScore     float64
	CompoundBonus float64
	FindingCount  int
}
