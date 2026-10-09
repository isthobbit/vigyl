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

	"github.com/isthobbit/vigyl/internal/paths"
)

// ErrTrivyNotFound is returned when the trivy binary is not in PATH.
var ErrTrivyNotFound = errors.New("trivy not found — install it: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")

// Options controls whether trivy may touch the network.
type Options struct {
	// Offline uses the DB already in CacheDir and makes no network requests.
	Offline bool
	// CacheDir is passed to --cache-dir when set.
	CacheDir string
}

// defaultTimeout is used when the caller passes timeout=0.
const defaultTimeout = 10 * time.Minute

// Run executes trivy against the given path and returns a Result.
//
// Trivy exits 0 (no findings) or 1 (findings found or error).
// We distinguish between the two by checking whether stdout contains
// valid JSON — a real error produces no JSON output.
// Pass timeout=0 to use the built-in 10-minute default.
func Run(scanPath string, verbose bool, timeout time.Duration, excludePaths []string, opts Options) (*Result, error) {
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
	supported := func(string) bool { return false }
	if opts.Offline {
		supported = helpFlagProbe(trivyPath)
	}
	args := buildArgs(absPath, verbose, excludePaths, opts, supported)

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

	for i := range findings {
		findings[i].Manifest = paths.Rel(absPath, findings[i].Manifest)
	}

	return &Result{
		Findings:       findings,
		ScanPath:       absPath,
		TrivyAvailable: true,
	}, nil
}

// buildArgs assembles the trivy command line.
//
//	fs                → filesystem scan mode (dependency manifests)
//	--format json     → machine-readable output we can parse
//	--scanners vuln   → vulnerability scanning only (no secrets, no misconfig)
//	--quiet           → suppress progress bars
//
// Offline adds the flags that stop every network call trivy would otherwise
// make: DB and Java DB updates, dependency-identification API requests,
// version-update notices and telemetry. The last two are newer flags, so they
// are only passed when supported reports that this trivy build knows them.
func buildArgs(absPath string, verbose bool, excludePaths []string, opts Options, supported func(flag string) bool) []string {
	args := []string{
		"fs",
		"--format", "json",
		"--scanners", "vuln",
		"--quiet",
	}
	if opts.CacheDir != "" {
		args = append(args, "--cache-dir", opts.CacheDir)
	}
	if opts.Offline {
		args = append(args, "--skip-db-update", "--skip-java-db-update", "--offline-scan")
		for _, f := range []string{"--skip-version-check", "--disable-telemetry"} {
			if supported(f) {
				args = append(args, f)
			}
		}
	}
	args = append(args, absPath)

	for _, p := range excludePaths {
		args = append(args, "--skip-dirs", p)
	}

	if verbose {
		args = filterOut(args, "--quiet")
		args = append(args, "--debug")
	}
	return args
}

// helpFlagProbe returns a function reporting whether `trivy fs --help`
// mentions a flag. The help text is read once, on first use.
func helpFlagProbe(trivyPath string) func(string) bool {
	var help []byte
	loaded := false
	return func(flag string) bool {
		if !loaded {
			help, _ = exec.Command(trivyPath, "fs", "--help").CombinedOutput() //nolint // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
			loaded = true
		}
		return bytes.Contains(help, []byte(flag))
	}
}

// BuildArgsForTest exposes buildArgs for unit testing. Do not call from
// production code.
func BuildArgsForTest(absPath string, verbose bool, excludePaths []string, opts Options, supported func(string) bool) []string {
	return buildArgs(absPath, verbose, excludePaths, opts, supported)
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
				Manifest:     result.Target,
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
