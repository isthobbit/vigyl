package sast

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

// ErrSemgrepNotFound is returned when the semgrep binary is not in PATH.
var ErrSemgrepNotFound = errors.New("semgrep not found — install it: https://semgrep.dev/docs/getting-started")

// DefaultRuleset is the Semgrep registry ruleset used when no config is specified.
// "auto" lets Semgrep pick rules based on the detected language — good default for MVP.
const DefaultRuleset = "auto"

// defaultTimeout is used when the caller passes timeout=0 (i.e. no config file).
const defaultTimeout = 10 * time.Minute

// Run executes semgrep against the given path and returns a Result.
//
// Semgrep exits 0 (no findings), 1 (findings found), or >1 (error).
// We treat exit 1 as a normal findings result, not a Go error.
// Pass timeout=0 to use the built-in 10-minute default.
func Run(scanPath string, verbose bool, timeout time.Duration, excludePaths []string) (*Result, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	// 1. Confirm semgrep is available.
	semgrepPath, err := exec.LookPath("semgrep")
	if err != nil {
		return &Result{ScanPath: scanPath, SemgrepAvailable: false}, ErrSemgrepNotFound
	}

	// 2. Resolve to absolute path.
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return nil, fmt.Errorf("could not resolve scan path: %w", err)
	}

	// 3. Build the semgrep command.
	//    --json        → machine-readable output we can parse
	//    --config auto → auto-select rules for detected languages
	//    --quiet       → suppress progress bars (we handle output ourselves)
	//    --no-rewrite-rule-ids → keep original rule IDs intact
	args := []string{
		"--json",
		"--config", DefaultRuleset,
		"--no-rewrite-rule-ids",
		"--quiet",
		absPath,
	}

	for _, p := range excludePaths {
		args = append(args, "--exclude", p)
	}

	if verbose {
		// Replace --quiet with --verbose when the user asks for it.
		args = filterOut(args, "--quiet")
		args = append(args, "--verbose")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, semgrepPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// Exit code 1 means findings were found — that is not an error for us.
	// Exit code >1 is a real semgrep error.
	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("semgrep timed out after %s", timeout)
		}
		exitCode := cmd.ProcessState.ExitCode()
		if exitCode != 1 {
			return nil, fmt.Errorf("semgrep error (exit %d): %w\n%s", exitCode, runErr, stderr.String())
		}
	}

	// 4. Parse JSON from stdout.
	findings, err := parseOutput(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("could not parse semgrep output: %w", err)
	}

	return &Result{
		Findings:         findings,
		ScanPath:         absPath,
		SemgrepAvailable: true,
	}, nil
}

// parseOutput unmarshals the semgrep JSON report and converts it to our Finding type.
func parseOutput(data []byte) ([]Finding, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return []Finding{}, nil
	}

	var report semgrepReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	findings := make([]Finding, 0, len(report.Results))
	for _, r := range report.Results {
		findings = append(findings, Finding{
			RuleID:   r.CheckID,
			Path:     r.Path,
			Start:    r.Start,
			End:      r.End,
			Extra:    r.Extra,
			Message:  r.Extra.Message,
			Severity: normaliseSeverity(r.Extra.Severity),
			Lines:    strings.TrimSpace(r.Extra.Lines),
		})
	}

	return findings, nil
}

// normaliseSeverity maps Semgrep severity strings to a consistent uppercase form.
func normaliseSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "ERROR":
		return "CRITICAL"
	case "WARNING":
		return "HIGH"
	case "INFO":
		return "MEDIUM"
	default:
		return strings.ToUpper(s)
	}
}

// filterOut returns a new slice with all occurrences of remove omitted.
// Using a fresh slice avoids silently mutating the caller's backing array.
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
// testing without requiring semgrep to be installed. Do not call from
// production code.
func ParseOutputForTest(data []byte) ([]Finding, error) {
	return parseOutput(data)
}
