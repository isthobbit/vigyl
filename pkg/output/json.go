package output

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/isthobbit/vigyl/internal/correlate"
	"github.com/isthobbit/vigyl/internal/scan/deps/osv"
	"github.com/isthobbit/vigyl/internal/scan/deps/trivy"
	"github.com/isthobbit/vigyl/internal/scan/sast"
	"github.com/isthobbit/vigyl/internal/scan/secrets"
	"github.com/isthobbit/vigyl/internal/store"
)

// JSONReport is the top-level structure written when --json is passed.
type JSONReport struct {
	Meta         JSONMeta         `json:"meta"`
	Secrets      []JSONFinding    `json:"secrets"`
	SAST         []JSONFinding    `json:"sast"`
	Dependencies []JSONDepFinding `json:"dependencies"`
	Total        int              `json:"total_findings"`
	RiskScore    float64          `json:"risk_score"`
	RiskBand     string           `json:"risk_band,omitempty"`
	// TopRisks are the highest-scoring files and packages, each with the
	// reasons behind its score.
	TopRisks []correlate.Risk `json:"top_risks"`
}

// TopRiskCount is how many files and packages "top risks" lists.
const TopRiskCount = 10

type JSONMeta struct {
	ScanPath  string    `json:"scan_path"`
	Timestamp time.Time `json:"timestamp"`
	Scanners  []string  `json:"scanners"`
}

type JSONFinding struct {
	Scanner  string `json:"scanner"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
	Match    string `json:"match,omitempty"`
}

type JSONDepFinding struct {
	// Scanner is the first scanner that reported the finding; FoundBy lists
	// every scanner that did, when Trivy and OSV-Scanner agree.
	Scanner      string   `json:"scanner"`
	FoundBy      []string `json:"found_by"`
	Manifest     string   `json:"manifest,omitempty"`
	Severity     string   `json:"severity"`
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	CVEID        string   `json:"cve_id,omitempty"`
	Ecosystem    string   `json:"ecosystem,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	Description  string   `json:"description,omitempty"`
}

// WriteJSON serialises secrets, SAST, and dependency results to w as a single JSON report.
func WriteJSON(w io.Writer, scanPath string, secretsResult *secrets.Result, sastResult *sast.Result, trivyResult *trivy.Result, osvResult *osv.Result, risks *correlate.Result) error {
	report := JSONReport{
		Meta: JSONMeta{
			ScanPath:  scanPath,
			Timestamp: time.Now().UTC(),
			Scanners:  activeScanners(secretsResult, sastResult, trivyResult, osvResult),
		},
		Secrets:      secretsToJSON(secretsResult),
		SAST:         sastToJSON(sastResult),
		Dependencies: depsToJSON(trivyResult, osvResult),
	}

	report.Total = len(report.Secrets) + len(report.SAST) + len(report.Dependencies)
	report.TopRisks = []correlate.Risk{}
	if risks != nil {
		report.RiskScore = math.Round(risks.Overall*10) / 10
		report.RiskBand = string(correlate.BandFor(risks.Overall))
		report.TopRisks = topRisks(risks.Risks)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteJSONFromStore serialises stored findings to w.
func WriteJSONFromStore(w io.Writer, scan *store.ScanRecord, codeFindings []store.CodeFindingRecord, depFindings []store.DepFindingRecord) error {
	type storedReport struct {
		Meta         JSONMeta         `json:"meta"`
		CodeFindings []JSONFinding    `json:"code_findings"`
		DepFindings  []JSONDepFinding `json:"dependency_findings"`
		Total        int              `json:"total_findings"`
		RiskScore    float64          `json:"risk_score"`
		RiskBand     string           `json:"risk_band"`
	}

	jcode := make([]JSONFinding, 0, len(codeFindings))
	for _, f := range codeFindings {
		jcode = append(jcode, JSONFinding{
			Scanner:  f.Scanner,
			Severity: f.Severity,
			RuleID:   f.RuleID,
			File:     f.File,
			Line:     f.Line,
			Message:  f.Message,
			Match:    f.RawMatch,
		})
	}

	jdeps := make([]JSONDepFinding, 0, len(depFindings))
	for _, f := range depFindings {
		jdeps = append(jdeps, JSONDepFinding{
			Scanner:      f.Scanner,
			Severity:     f.Severity,
			Package:      f.Package,
			Version:      f.Version,
			CVEID:        f.CVEID,
			Ecosystem:    f.Ecosystem,
			FixedVersion: f.FixedVersion,
			Description:  f.Description,
		})
	}

	band := store.BandFromScore(scan.RiskScore)

	report := storedReport{
		Meta: JSONMeta{
			ScanPath:  scan.ScanPath,
			Timestamp: scan.StartedAt,
			Scanners:  []string{scan.Scanners},
		},
		CodeFindings: jcode,
		DepFindings:  jdeps,
		Total:        len(jcode) + len(jdeps),
		RiskScore:    scan.RiskScore,
		RiskBand:     string(band),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func secretsToJSON(r *secrets.Result) []JSONFinding {
	if r == nil {
		return []JSONFinding{}
	}
	out := make([]JSONFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, JSONFinding{
			Scanner:  "secrets",
			Severity: "HIGH",
			RuleID:   f.RuleID,
			File:     f.File,
			Line:     f.StartLine,
			Message:  f.Description,
			Match:    redactSecret(f.Match, f.Secret),
		})
	}
	return out
}

func sastToJSON(r *sast.Result) []JSONFinding {
	if r == nil {
		return []JSONFinding{}
	}
	out := make([]JSONFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, JSONFinding{
			Scanner:  "sast",
			Severity: f.Severity,
			RuleID:   f.RuleID,
			File:     f.Path,
			Line:     f.Start.Line,
			Message:  f.Message,
		})
	}
	return out
}

func depsToJSON(t *trivy.Result, o *osv.Result) []JSONDepFinding {
	out := []JSONDepFinding{}
	// index merges the same advisory for the same package version reported by
	// both scanners into one finding.
	index := map[string]int{}
	add := func(scanner, severity, pkg, version, cve, eco, fixed, desc, manifest string) {
		key := pkg + "@" + version + "|" + cve
		if i, ok := index[key]; ok && cve != "" {
			d := &out[i]
			// OSV can list one CVE under several IDs (PYSEC and GHSA).
			if !slices.Contains(d.FoundBy, scanner) {
				d.FoundBy = append(d.FoundBy, scanner)
			}
			if severityOrder(severity) > severityOrder(d.Severity) {
				d.Severity = severity
			}
			if d.FixedVersion == "" {
				d.FixedVersion = fixed
			}
			if d.Description == "" {
				d.Description = desc
			}
			return
		}
		index[key] = len(out)
		out = append(out, JSONDepFinding{
			Scanner: scanner, FoundBy: []string{scanner}, Manifest: manifest,
			Severity: severity, Package: pkg, Version: version, CVEID: cve,
			Ecosystem: eco, FixedVersion: fixed, Description: desc,
		})
	}
	if t != nil {
		for _, f := range t.Findings {
			add("trivy", f.Severity, f.Package, f.Version, f.CVEID, f.Ecosystem, f.FixedVersion, f.Description, f.Manifest)
		}
	}
	if o != nil {
		for _, f := range o.Findings {
			add("osv", f.Severity, f.Package, f.Version, f.CVEID, f.Ecosystem, f.FixedVersion, f.Description, f.Manifest)
		}
	}
	return out
}

func severityOrder(s string) int {
	return map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[strings.ToUpper(s)]
}

// topRisks returns the highest-scoring entries that have something to say.
func topRisks(all []correlate.Risk) []correlate.Risk {
	out := []correlate.Risk{}
	for _, r := range all {
		if len(out) == TopRiskCount {
			break
		}
		if r.Score > 0 {
			out = append(out, r)
		}
	}
	return out
}

func activeScanners(s *secrets.Result, a *sast.Result, t *trivy.Result, o *osv.Result) []string {
	var out []string
	if s != nil && s.GitleaksAvailable {
		out = append(out, "secrets")
	}
	if a != nil && a.SemgrepAvailable {
		out = append(out, "sast")
	}
	if t != nil && t.TrivyAvailable {
		out = append(out, "trivy")
	}
	if o != nil && o.OSVAvailable {
		out = append(out, "osv")
	}
	return out
}

// PrintStoredReport renders a stored scan report to stdout in human-readable form.
func PrintStoredReport(scan *store.ScanRecord, codeFindings []store.CodeFindingRecord, depFindings []store.DepFindingRecord, noColor bool) {
	band := store.BandFromScore(scan.RiskScore)
	bandDesc := store.BandDescription(band)

	fmt.Printf("%s\n", colorize(noColor, bold, "Scan Report"))
	fmt.Printf("   ID:        %d\n", scan.ID)
	fmt.Printf("   Path:      %s\n", scan.ScanPath)
	fmt.Printf("   Scanners:  %s\n", scan.Scanners)
	fmt.Printf("   Started:   %s\n", scan.StartedAt.Local().Format("2006-01-02 15:04:05"))
	fmt.Printf("   Duration:  %s\n", scan.EndedAt.Sub(scan.StartedAt).Round(1e6))
	fmt.Printf("   Findings:  %d\n", scan.Total)
	fmt.Printf("   Risk:      %s — %s\n\n", colorize(noColor, severityColour(string(band)), string(band)), bandDesc)

	if len(codeFindings) == 0 && len(depFindings) == 0 {
		fmt.Println(colorize(noColor, green, "  No findings recorded."))
		return
	}

	if len(codeFindings) > 0 {
		fmt.Printf("%s\n\n", colorize(noColor, bold, "Code Findings"))
		for _, f := range codeFindings {
			sevColor := severityColour(f.Severity)
			fmt.Printf("  %s  [%s]  %s\n",
				colorize(noColor, sevColor, f.Severity),
				f.Scanner,
				f.File,
			)
			fmt.Printf("       Line %d · %s\n", f.Line, f.RuleID)
			if f.Message != "" {
				fmt.Printf("       %s\n", wordWrap(f.Message, 70, "       "))
			}
			fmt.Println()
		}
	}

	if len(depFindings) > 0 {
		fmt.Printf("%s\n\n", colorize(noColor, bold, "Dependency Findings"))
		for _, f := range depFindings {
			sevColor := severityColour(f.Severity)
			fmt.Printf("  %s  [%s]  %s@%s\n",
				colorize(noColor, sevColor, f.Severity),
				f.Scanner,
				f.Package,
				f.Version,
			)
			if f.CVEID != "" {
				fmt.Printf("       %s\n", f.CVEID)
			}
			if f.FixedVersion != "" {
				fmt.Printf("       Fix available: %s\n", f.FixedVersion)
			}
			if f.Description != "" {
				fmt.Printf("       %s\n", wordWrap(f.Description, 70, "       "))
			}
			fmt.Println()
		}
	}
}
