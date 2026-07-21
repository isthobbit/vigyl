package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrTrivyNotFound is returned when the trivy binary is not in PATH.
var ErrTrivyNotFound = errors.New("trivy not found — install it: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")

// defaultTimeout is used when the caller passes timeout=0.
const defaultTimeout = 10 * time.Minute

// Run executes trivy against the given path and returns a Result.
//
// Trivy exits 0 (no findings) or 1 (findings found or error).
// We distinguish between the two by checking whether stdout contains
// valid JSON — a real error produces no JSON output.
// Pass timeout=0 to use the built-in 10-minute default.
func Run(scanPath string, verbose bool, timeout time.Duration, excludePaths []string) (*Result, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	// 1. Confirm trivy is available.
	trivyPath, err := exec.LookPath("trivy")
	if err != nil {
		return &Result{ScanPath: scanPath, TrivyAvailable: false}, ErrTrivyNotFound
	}

	// 2. Resolve the scan path to an absolute path.
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return nil, fmt.Errorf("could not resolve scan path: %w", err)
	}

	// 3. Build the trivy command.
	//    fs         → filesystem scan mode (dependency manifests)
	//    --format json → machine-readable output we can parse
	//    --scanners vuln → vulnerability scanning only (no secrets, no misconfig)
	//    --quiet    → suppress progress bars
	args := []string{
		"fs",
		"--format", "json",
		"--scanners", "vuln",
		"--quiet",
		absPath,
	}

	for _, p := range excludePaths {
		args = append(args, "--skip-dirs", p)
	}

	if verbose {
		args = filterOut(args, "--quiet")
		args = append(args, "--debug")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, trivyPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("trivy timed out after %s", timeout)
		}
		// Trivy exits 1 for both findings and real errors.
		// If stdout has JSON content, treat it as findings (not an error).
		if bytes.TrimSpace(stdout.Bytes()) == nil {
			return nil, fmt.Errorf("trivy error: %w\n%s", runErr, stderr.String())
		}
	}

	// 4. Parse JSON from stdout.
	findings, err := parseOutput(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("could not parse trivy output: %w", err)
	}

	return &Result{
		Findings:       findings,
		ScanPath:       absPath,
		TrivyAvailable: true,
	}, nil
}

// parseOutput unmarshals the trivy JSON report and converts it to our Finding type.
func parseOutput(data []byte) ([]Finding, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return []Finding{}, nil
	}

	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	var findings []Finding
	for _, result := range report.Results {
		ecosystem := normaliseEcosystem(result.Type)
		for _, v := range result.Vulnerabilities {
			desc := v.Description
			if desc == "" {
				desc = v.Vulnerability.Description
			}
			findings = append(findings, Finding{
				Package:      v.PkgName,
				Version:      v.InstalledVersion,
				CVEID:        v.VulnerabilityID,
				Severity:     normaliseSeverity(v.Severity),
				Ecosystem:    ecosystem,
				FixedVersion: v.FixedVersion,
				Description:  desc,
			})
		}
	}

	return findings, nil
}

// normaliseSeverity maps Trivy severity strings to our consistent uppercase form.
func normaliseSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "LOW"
	}
}

// normaliseEcosystem maps Trivy target types to a human-readable ecosystem name.
func normaliseEcosystem(t string) string {
	switch strings.ToLower(t) {
	case "gomod", "go.mod":
		return "Go"
	case "npm", "node.js":
		return "npm"
	case "pip", "pipenv", "poetry":
		return "PyPI"
	case "cargo":
		return "Rust"
	case "maven", "gradle":
		return "Java"
	case "gemspec", "bundler":
		return "Ruby"
	case "composer":
		return "PHP"
	default:
		return t
	}
}

// filterOut returns a new slice with all occurrences of remove omitted.
func filterOut(args []string, remove string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != remove {
			out = append(out, a)
		}
	}
	return out
}

// ParseOutputForTest is an exported shim that exposes parseOutput for unit
// testing without requiring trivy to be installed.
func ParseOutputForTest(data []byte) ([]Finding, error) {
	return parseOutput(data)
}
