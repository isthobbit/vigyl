package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/isthobbit/vigil/internal/scan/sast"
	"github.com/isthobbit/vigil/internal/scan/secrets"
	"github.com/isthobbit/vigil/internal/store"
)

// JSONReport is the top-level structure written when --json is passed.
type JSONReport struct {
	Meta    JSONMeta      `json:"meta"`
	Secrets []JSONFinding `json:"secrets"`
	SAST    []JSONFinding `json:"sast"`
	Total   int           `json:"total_findings"`
}

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

// WriteJSON serialises secrets and SAST results to w as a single JSON report.
func WriteJSON(w io.Writer, scanPath string, secretsResult *secrets.Result, sastResult *sast.Result) error {
	report := JSONReport{
		Meta: JSONMeta{
			ScanPath:  scanPath,
			Timestamp: time.Now().UTC(),
			Scanners:  activeScanners(secretsResult, sastResult),
		},
		Secrets: secretsToJSON(secretsResult),
		SAST:    sastToJSON(sastResult),
	}

	report.Total = len(report.Secrets) + len(report.SAST)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteJSONFromStore serialises stored findings to w.
func WriteJSONFromStore(w io.Writer, scan *store.ScanRecord, findings []store.FindingRecord) error {
	type storedReport struct {
		Meta     JSONMeta      `json:"meta"`
		Findings []JSONFinding `json:"findings"`
		Total    int           `json:"total_findings"`
	}

	jfindings := make([]JSONFinding, 0, len(findings))
	for _, f := range findings {
		jfindings = append(jfindings, JSONFinding{
			Scanner:  f.Scanner,
			Severity: f.Severity,
			RuleID:   f.RuleID,
			File:     f.File,
			Line:     f.Line,
			Message:  f.Message,
			Match:    f.RawMatch,
		})
	}

	report := storedReport{
		Meta: JSONMeta{
			ScanPath:  scan.ScanPath,
			Timestamp: scan.StartedAt,
			Scanners:  []string{scan.Scanners},
		},
		Findings: jfindings,
		Total:    len(jfindings),
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
			Severity: "HIGH", // gitleaks doesn't expose severity; secrets are always high
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

func activeScanners(s *secrets.Result, a *sast.Result) []string {
	var out []string
	if s != nil && s.GitleaksAvailable {
		out = append(out, "secrets")
	}
	if a != nil && a.SemgrepAvailable {
		out = append(out, "sast")
	}
	return out
}

// PrintStoredReport renders a stored scan report to stdout in human-readable form.
func PrintStoredReport(scan *store.ScanRecord, findings []store.FindingRecord, noColor bool) {
	fmt.Printf("%s\n", colorize(noColor, bold, "Scan Report"))
	fmt.Printf("   ID:       %d\n", scan.ID)
	fmt.Printf("   Path:     %s\n", scan.ScanPath)
	fmt.Printf("   Scanners: %s\n", scan.Scanners)
	fmt.Printf("   Started:  %s\n", scan.StartedAt.Local().Format("2006-01-02 15:04:05"))
	fmt.Printf("   Duration: %s\n", scan.EndedAt.Sub(scan.StartedAt).Round(1e6))
	fmt.Printf("   Findings: %d\n\n", scan.Total)

	if len(findings) == 0 {
		fmt.Println(colorize(noColor, green, "  No findings recorded."))
		return
	}

	for _, f := range findings {
		sevColor := severityColour(f.Severity)
		fmt.Printf("  %s  [%s]  %s\n",
			colorize(noColor, sevColor, f.Severity),
			f.Scanner,
			f.File,
		)
		fmt.Printf("       Line %d Â· %s\n", f.Line, f.RuleID)
		if f.Message != "" {
			fmt.Printf("       %s\n", wordWrap(f.Message, 70, "       "))
		}
		fmt.Println()
	}
}
