package correlate

import (
	"github.com/isthobbit/vigyl/internal/imports"
	"github.com/isthobbit/vigyl/internal/store"
)

// Input holds all findings from a single scan, ready for correlation.
type Input struct {
	ScanID int64
	// Root is the scanned directory. Finding paths are normalised against it
	// so the same file compares equal across scanners.
	Root string
	// Imports maps source files to the packages they import. When nil, the
	// rules that link dependencies to code are skipped.
	Imports      *imports.Index
	CodeFindings []store.CodeFindingRecord
	DepFindings  []store.DepFindingRecord
}

// CorrelationRule defines a single correlation rule with its weight and type.
type CorrelationRule struct {
	Reason      string
	Weight      float64
	Directional bool
	// Description says, in one sentence, what the rule links.
	Description string
}

// Rule reasons.
const (
	ReasonSecretInVulnerableFile    = "secret_in_vulnerable_file"
	ReasonSecretUsingVulnerableDep  = "secret_in_file_using_vulnerable_package"
	ReasonVulnCodeInVulnerableFile  = "vuln_code_in_vulnerable_file"
	ReasonCVEConfirmed              = "cve_confirmed_by_multiple_scanners"
	ReasonPackageConfirmed          = "package_confirmed_by_multiple_scanners"
	ReasonMultipleCVEsInSamePackage = "multiple_cves_in_same_package"
	ReasonMultipleVulnsInSameFile   = "multiple_vulns_in_same_file"
)

// DefaultRules are the correlation rules with their default weights. All
// weights are overridable via the correlation.weights config.
var DefaultRules = []CorrelationRule{
	{ReasonSecretInVulnerableFile, 1.0, true, "a secret sits in a file that also has a code vulnerability"},
	{ReasonSecretUsingVulnerableDep, 0.9, true, "a secret sits in a file that imports a package with a known CVE"},
	{ReasonVulnCodeInVulnerableFile, 0.8, true, "a code vulnerability sits in a file that imports a package with a known CVE"},
	{ReasonCVEConfirmed, 0.7, true, "Trivy and OSV-Scanner both report the same CVE in the same package"},
	{ReasonPackageConfirmed, 0.6, false, "Trivy and OSV-Scanner both flag the same package, under different advisory IDs"},
	{ReasonMultipleCVEsInSamePackage, 0.5, false, "a package has more than one distinct known vulnerability"},
	{ReasonMultipleVulnsInSameFile, 0.4, false, "a file has more than one code vulnerability"},
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

// BandFor returns the named band for a score.
func BandFor(score float64) store.RiskBand {
	for _, t := range RiskBandThresholds {
		if score <= t.Max {
			return t.Band
		}
	}
	return store.RiskBandSevere
}

// Result is what a correlation run produced, for display.
type Result struct {
	// Overall is the scan's risk score, 0–10.
	Overall float64
	// Risks are the scored files and packages, highest first.
	Risks []Risk
}

// Risk is one scored file or package and the reasons behind its score.
type Risk struct {
	// Kind is "file" or "package".
	Kind string `json:"kind"`
	// Name is a path relative to the scan root, or package@version.
	Name  string         `json:"name"`
	Score float64        `json:"score"`
	Band  store.RiskBand `json:"band"`
	// Why lists, in plain language, what contributed to the score.
	Why []string `json:"why"`
	// Versions lists, for a package, every vulnerable version installed.
	// It has more than one entry only in Top's grouped list.
	Versions []string `json:"versions,omitempty"`

	pkg string // package name, without the version
	// reach orders equal scores: 0 for files and imported packages, 1 when
	// imports could not be read, 2 for packages no file imports.
	reach int
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
