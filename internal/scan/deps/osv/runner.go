package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrOSVNotFound is returned when the osv-scanner binary is not in PATH.
var ErrOSVNotFound = errors.New("osv-scanner not found — install it: https://google.github.io/osv-scanner/installation/")

// Options controls whether osv-scanner may touch the network.
type Options struct {
	// Offline matches against local databases only and disables every
	// network feature (osv.dev API queries, dependency resolution).
	Offline bool
	// DBDir is exported as OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY when offline.
	DBDir string
}

// defaultTimeout is used when the caller passes timeout=0.
const defaultTimeout = 10 * time.Minute

// Run executes osv-scanner against the given path and returns a Result.
//
// OSV-Scanner exits 0 (no findings) or 1 (findings found or error).
// We distinguish between the two by checking whether stdout contains
// valid JSON output. Pass timeout=0 to use the built-in 10-minute default.
func Run(scanPath string, verbose bool, timeout time.Duration, excludePaths []string, opts Options) (*Result, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	// 1. Confirm osv-scanner is available.
	osvPath, err := exec.LookPath("osv-scanner")
	if err != nil {
		return &Result{ScanPath: scanPath, OSVAvailable: false}, ErrOSVNotFound
	}

	// 2. Resolve the scan path to an absolute path.
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return nil, fmt.Errorf("could not resolve scan path: %w", err)
	}

	// 3. Build the osv-scanner command.
	supported := helpFlagProbe(osvPath)
	if opts.Offline && !supported("--offline") {
		return nil, errors.New("osv-scanner offline mode needs osv-scanner v2 or newer — upgrade it: https://google.github.io/osv-scanner/installation/")
	}
	args := buildArgs(absPath, excludePaths, opts, supported)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, osvPath, args...)
	if opts.Offline && opts.DBDir != "" {
		cmd.Env = append(os.Environ(), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+opts.DBDir)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("osv-scanner timed out after %s", timeout)
		}
		// OSV-Scanner exits 1 for both findings and real errors.
		// If stdout has JSON content treat it as findings, not an error.
		if len(bytes.TrimSpace(stdout.Bytes())) == 0 {
			return nil, fmt.Errorf("osv-scanner error: %w\n%s", runErr, stderr.String())
		}
	}

	// 4. Parse JSON from stdout.
	findings, err := parseOutput(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("could not parse osv-scanner output: %w", err)
	}

	return &Result{
		Findings:     findings,
		ScanPath:     absPath,
		OSVAvailable: true,
	}, nil
}

// buildArgs assembles the osv-scanner command line.
//
//	--format json  → machine-readable output we can parse
//	--recursive    → scan subdirectories for manifest files
//	--offline      → local databases only, no network access
//
// Exclusions use --experimental-exclude with a g: (glob) prefix, which only
// newer osv-scanner releases understand; older ones scan everything.
func buildArgs(absPath string, excludePaths []string, opts Options, supported func(flag string) bool) []string {
	args := []string{
		"--format", "json",
		"--recursive",
	}
	if opts.Offline {
		args = append(args, "--offline")
	}
	if supported("--experimental-exclude") {
		for _, p := range excludePaths {
			args = append(args, "--experimental-exclude", "g:"+p)
		}
	}
	return append(args, absPath)
}

// helpFlagProbe returns a function reporting whether
// `osv-scanner scan source --help` mentions a flag. The help text is read
// once, on first use.
func helpFlagProbe(osvPath string) func(string) bool {
	var help []byte
	loaded := false
	return func(flag string) bool {
		if !loaded {
			help, _ = exec.Command(osvPath, "scan", "source", "--help").CombinedOutput() //nolint // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
			loaded = true
		}
		return bytes.Contains(help, []byte(flag))
	}
}

// BuildArgsForTest exposes buildArgs for unit testing. Do not call from
// production code.
func BuildArgsForTest(absPath string, excludePaths []string, opts Options, supported func(string) bool) []string {
	return buildArgs(absPath, excludePaths, opts, supported)
}

// parseOutput unmarshals the osv-scanner JSON report and converts it to our Finding type.
func parseOutput(data []byte) ([]Finding, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return []Finding{}, nil
	}

	var report osvReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	var findings []Finding
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				cveID := extractCVE(vuln.ID, pkg.Groups)
				fixedVersion := extractFixedVersion(vuln.Affected)
				desc := vuln.Summary
				if desc == "" {
					desc = vuln.Details
				}

				findings = append(findings, Finding{
					Package:      pkg.Package.Name,
					Version:      pkg.Package.Version,
					CVEID:        cveID,
					Severity:     normaliseSeverity(vuln.Severity),
					Ecosystem:    pkg.Package.Ecosystem,
					FixedVersion: fixedVersion,
					Description:  desc,
				})
			}
		}
	}

	return findings, nil
}

// extractCVE returns the CVE ID from the vuln ID or group aliases.
// OSV IDs look like "GHSA-xxxx" or "CVE-xxxx"; we prefer CVE IDs.
func extractCVE(id string, groups []osvGroup) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, g := range groups {
		for _, alias := range g.IDs {
			if strings.HasPrefix(alias, "CVE-") {
				return alias
			}
		}
	}
	// Fall back to the OSV ID if no CVE alias exists.
	return id
}

// extractFixedVersion returns the first fixed version found in affected ranges.
func extractFixedVersion(affected []osvAffected) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// normaliseSeverity maps OSV CVSS score strings to our severity bands.
// OSV uses CVSS v3 scores (0.0–10.0) in the severity array.
func normaliseSeverity(severities []osvSeverity) string {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			score := parseCVSSScore(s.Score)
			switch {
			case score >= 9.0:
				return "CRITICAL"
			case score >= 7.0:
				return "HIGH"
			case score >= 4.0:
				return "MEDIUM"
			default:
				return "LOW"
			}
		}
	}
	// No CVSS score available — default to MEDIUM to avoid under-reporting.
	return "MEDIUM"
}

// parseCVSSScore extracts the base score from a CVSS v3 vector string.
// OSV may return either a raw score ("7.5") or a full vector
// ("CVSS:3.1/AV:N/AC:L/..."). We handle both.
func parseCVSSScore(score string) float64 {
	// If it's a plain number, parse directly.
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil && f >= 0 && f <= 10 {
		return f
	}
	// CVSS vector strings don't embed a plain score — return 0 to trigger LOW.
	return 0
}

// ParseOutputForTest is an exported shim that exposes parseOutput for unit
// testing without requiring osv-scanner to be installed.
func ParseOutputForTest(data []byte) ([]Finding, error) {
	return parseOutput(data)
}
