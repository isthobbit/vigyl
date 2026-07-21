package secrets

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

// ErrGitleaksNotFound is returned when the gitleaks binary is not in PATH.
var ErrGitleaksNotFound = errors.New("gitleaks not found â€” install it: https://github.com/gitleaks/gitleaks#installing")

// defaultTimeout is used when the caller passes timeout=0 (i.e. no config file).
const defaultTimeout = 10 * time.Minute

// minGitleaksVersionMajor is the minimum major version that supports --no-git.
const minGitleaksVersionMajor = 8

// supportsNoGit checks whether the installed gitleaks supports --no-git.
// Parses major version from `gitleaks version` (e.g. "v8.18.2").
// On any parse failure we assume supported to avoid blocking the scan.
func supportsNoGit(gitleaksPath string) bool {
	out, err := exec.Command(gitleaksPath, "version").Output() //nolint // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	if err != nil {
		return true
	}
	ver := strings.TrimSpace(strings.TrimPrefix(string(out), "v"))
	var major int
	fmt.Sscanf(ver, "%d", &major)
	return major >= minGitleaksVersionMajor
}

// Run executes gitleaks against the given path and returns a Result.
//
// It writes a temporary JSON report file, reads it, then cleans up.
// Gitleaks exits with code 1 when findings are present â€” that is NOT
// an error from our perspective, so we handle that case explicitly.
// Pass timeout=0 to use the built-in 10-minute default.
func Run(scanPath string, verbose bool, timeout time.Duration, excludePaths []string) (*Result, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	// 1. Confirm gitleaks is available.
	gitleaksPath, err := exec.LookPath("gitleaks")
	if err != nil {
		return &Result{ScanPath: scanPath, GitleaksAvailable: false}, ErrGitleaksNotFound
	}

	// 2. Resolve the scan path to an absolute path.
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return nil, fmt.Errorf("could not resolve scan path: %w", err)
	}

	// 3. Write the JSON report to a temp file so we can parse it.
	reportFile, err := os.CreateTemp("", "vigil-secrets-*.json")
	if err != nil {
		return nil, fmt.Errorf("could not create temp report file: %w", err)
	}
	reportPath := reportFile.Name()
	reportFile.Close()
	defer os.Remove(reportPath)

	// 4. Build the gitleaks command.
	//    --exit-code 0 â†’ we handle exit codes ourselves
	args := []string{
		"detect",
		"--source", absPath,
		"--report-format", "json",
		"--report-path", reportPath,
		"--exit-code", "0",
	}

	// write a temporary .gitleaksignore file for excluded paths
	if len(excludePaths) > 0 {
		ignoreFile, err := os.CreateTemp("", "vigil-gitleaksignore-*")
		if err == nil {
			for _, p := range excludePaths {
				fmt.Fprintln(ignoreFile, p)
			}
			ignoreFile.Close()
			defer os.Remove(ignoreFile.Name())
			args = append(args, "--gitleaks-ignore-path", ignoreFile.Name())
		}
	}

	// --no-git was introduced in gitleaks v8. Skip on older versions to avoid
	// a cryptic "unknown flag" error; the scan still works for git repos.
	if supportsNoGit(gitleaksPath) {
		args = append(args, "--no-git")
	}

	if verbose {
		args = append(args, "--verbose")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitleaksPath, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("gitleaks timed out after %s", timeout)
		}
		return nil, fmt.Errorf("gitleaks failed: %w\n%s", err, stderr.String())
	}

	// 5. Parse the JSON report.
	findings, err := parseReport(reportPath)
	if err != nil {
		return nil, fmt.Errorf("could not parse gitleaks report: %w", err)
	}

	return &Result{
		Findings:          findings,
		ScanPath:          absPath,
		GitleaksAvailable: true,
	}, nil
}

// parseReport reads and unmarshals the gitleaks JSON report file.
func parseReport(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseReportForTest(data)
}

// ParseReportForTest parses raw gitleaks JSON bytes without requiring the
// gitleaks binary. Use in unit tests only.
func ParseReportForTest(data []byte) ([]Finding, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return []Finding{}, nil
	}
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}
	return findings, nil
}
