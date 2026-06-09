package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/isthobbit/kinga/internal/config"
	"github.com/isthobbit/kinga/internal/installer"
	"github.com/isthobbit/kinga/internal/scan/sast"
	"github.com/isthobbit/kinga/internal/scan/secrets"
	"github.com/isthobbit/kinga/internal/store"
	"github.com/isthobbit/kinga/pkg/output"
	"github.com/spf13/cobra"
)

var (
	scanOutput string
	failOn     string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scans on your codebase",
}

var scanAllCmd = &cobra.Command{
	Use:   "all [path]",
	Short: "Run all scans (SAST + secrets)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScanAll,
}

var scanSASTCmd = &cobra.Command{
	Use:   "sast [path]",
	Short: "Run SAST scan (powered by Semgrep)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScanSAST,
}

var scanSecretsCmd = &cobra.Command{
	Use:   "secrets [path]",
	Short: "Run secrets detection (powered by Gitleaks)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScanSecrets,
}

func init() {
	scanCmd.AddCommand(scanAllCmd, scanSASTCmd, scanSecretsCmd)
	rootCmd.AddCommand(scanCmd)

	for _, cmd := range []*cobra.Command{scanAllCmd, scanSASTCmd, scanSecretsCmd} {
		cmd.Flags().StringVarP(&scanOutput, "output", "o", "", "write JSON results to file")
		cmd.Flags().StringVar(&failOn, "fail-on", "", "exit 1 at this severity or above (critical|high|medium|low|none)")
	}
}

func resolvePath(args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	return os.Getwd()
}

// ── Scan commands ─────────────────────────────────────────────────────────────

func runScanAll(cmd *cobra.Command, args []string) error {
	path, err := resolvePath(args)
	if err != nil {
		return err
	}

	// Ensure both tools are present, prompting to install any that are missing.
	// If the user declines or install fails we skip that scanner but continue.
	gitleaksOK, semgrepOK := installer.EnsureAll(noColor)

	cfg := loadConfig()
	threshold := resolveFailOn(cfg)
	startedAt := time.Now()

	if !jsonOut {
		scanners := activeScanners(gitleaksOK, semgrepOK)
		output.PrintScanHeader(path, scanners, noColor)
	}

	var secretsResult *secrets.Result
	if gitleaksOK {
		secretsResult, err = secrets.Run(path, verbose, cfg.Scan.Timeout, cfg.Scan.ExcludePaths)
		if err != nil {
			printScannerError("secrets", err)
		} else if !jsonOut {
			output.PrintSecretsResult(secretsResult, noColor)
		}
	}

	var sastResult *sast.Result
	if semgrepOK {
		sastResult, err = sast.Run(path, verbose, cfg.Scan.Timeout, cfg.Scan.ExcludePaths)
		if err != nil {
			printScannerError("sast", err)
		} else if !jsonOut {
			output.PrintSASTResult(sastResult, noColor)
		}
	}

	elapsed := time.Since(startedAt)

	if !jsonOut {
		sc, ac := countResults(secretsResult, sastResult)
		output.PrintScanSummary(sc, ac, elapsed, noColor)
	}

	persistScan(path, "secrets,sast", startedAt, time.Now(), secretsResult, sastResult)

	if jsonOut || scanOutput != "" {
		writeJSONOutput(path, secretsResult, sastResult)
	}

	if shouldFail(threshold, secretsResult, sastResult) {
		os.Exit(1)
	}
	return nil
}

func runScanSAST(cmd *cobra.Command, args []string) error {
	path, err := resolvePath(args)
	if err != nil {
		return err
	}

	// Prompt to install semgrep if missing.
	if !installer.IsInstalled(installer.Semgrep) {
		ok, _ := installer.Prompt(installer.Semgrep, noColor)
		if !ok {
			fmt.Fprintln(os.Stderr, "semgrep is required for SAST scanning. Exiting.")
			os.Exit(2)
		}
	}

	cfg := loadConfig()
	threshold := resolveFailOn(cfg)
	startedAt := time.Now()

	if !jsonOut {
		output.PrintScanHeader(path, []string{"sast"}, noColor)
	}

	result, err := sast.Run(path, verbose, cfg.Scan.Timeout, cfg.Scan.ExcludePaths)
	if err != nil {
		printScannerError("sast", err)
		os.Exit(2)
	}

	if !jsonOut {
		output.PrintSASTResult(result, noColor)
		output.PrintScanSummary(0, len(result.Findings), time.Since(startedAt), noColor)
	}

	persistScan(path, "sast", startedAt, time.Now(), nil, result)

	if jsonOut || scanOutput != "" {
		writeJSONOutput(path, nil, result)
	}

	if config.MeetsSeverityThreshold(highestSeverity(nil, result), threshold) {
		os.Exit(1)
	}
	return nil
}

func runScanSecrets(cmd *cobra.Command, args []string) error {
	path, err := resolvePath(args)
	if err != nil {
		return err
	}

	// Prompt to install gitleaks if missing.
	if !installer.IsInstalled(installer.Gitleaks) {
		ok, _ := installer.Prompt(installer.Gitleaks, noColor)
		if !ok {
			fmt.Fprintln(os.Stderr, "gitleaks is required for secrets scanning. Exiting.")
			os.Exit(2)
		}
	}

	cfg := loadConfig()
	threshold := resolveFailOn(cfg)
	startedAt := time.Now()

	if !jsonOut {
		output.PrintScanHeader(path, []string{"secrets"}, noColor)
	}

	result, err := secrets.Run(path, verbose, cfg.Scan.Timeout, cfg.Scan.ExcludePaths)
	if err != nil {
		printScannerError("secrets", err)
		os.Exit(2)
	}

	if !jsonOut {
		output.PrintSecretsResult(result, noColor)
		output.PrintScanSummary(len(result.Findings), 0, time.Since(startedAt), noColor)
	}

	persistScan(path, "secrets", startedAt, time.Now(), result, nil)

	if jsonOut || scanOutput != "" {
		writeJSONOutput(path, result, nil)
	}

	if config.MeetsSeverityThreshold(highestSeverity(result, nil), threshold) {
		os.Exit(1)
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func loadConfig() *config.Config {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		d := config.Defaults()
		return &d
	}
	return cfg
}

func resolveFailOn(cfg *config.Config) string {
	if failOn != "" {
		return strings.ToLower(failOn)
	}
	return strings.ToLower(cfg.Scan.FailOn)
}

// shouldFail returns true when the highest severity found meets or exceeds threshold.
func shouldFail(threshold string, s *secrets.Result, a *sast.Result) bool {
	if threshold == "none" {
		return false
	}
	return config.MeetsSeverityThreshold(highestSeverity(s, a), threshold)
}

// highestSeverity returns the most severe finding level across both result sets.
// Secrets findings have no per-finding severity; all detected secrets are treated
// as HIGH (a leaked credential is always significant). This means --fail-on critical
// will NOT trigger on secrets findings — use --fail-on high or lower for that.
func highestSeverity(s *secrets.Result, a *sast.Result) string {
	best := ""
	if s != nil && len(s.Findings) > 0 {
		if config.SeverityOrder["high"] > config.SeverityOrder[best] {
			best = "high"
		}
	}
	if a != nil {
		for _, f := range a.Findings {
			sev := strings.ToLower(f.Severity)
			if config.SeverityOrder[sev] > config.SeverityOrder[best] {
				best = sev
			}
		}
	}
	if best == "" {
		return "low"
	}
	return best
}

func countResults(s *secrets.Result, a *sast.Result) (int, int) {
	sc, ac := 0, 0
	if s != nil {
		sc = len(s.Findings)
	}
	if a != nil {
		ac = len(a.Findings)
	}
	return sc, ac
}

// activeScanners returns the list of scanner names that will actually run,
// used to populate the scan header when some tools are unavailable.
func activeScanners(gitleaksOK, semgrepOK bool) []string {
	var s []string
	if gitleaksOK {
		s = append(s, "secrets")
	}
	if semgrepOK {
		s = append(s, "sast")
	}
	if len(s) == 0 {
		return []string{"none"}
	}
	return s
}

func printScannerError(scanner string, err error) {
	var notFound interface{ Error() string }
	if errors.As(err, &notFound) && strings.Contains(err.Error(), "not found") {
		fmt.Fprintf(os.Stderr, "WARNING: %s scanner not installed: %v\n", scanner, err)
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: %s scan error: %v\n", scanner, err)
	}
}

func persistScan(path, scanners string, startedAt, endedAt time.Time, s *secrets.Result, a *sast.Result) {
	cfg := loadConfig()
	db, err := store.Open(cfg.Storage.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Could not open scan history: %v\n", err)
		return
	}
	defer db.Close()

	findings := buildFindingRecords(s, a)
	scanID, err := db.SaveScan(path, scanners, startedAt, endedAt, findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Could not save scan: %v\n", err)
		return
	}
	if verbose {
		fmt.Printf("  Scan saved (ID: %d)\n", scanID)
	}
}

func buildFindingRecords(s *secrets.Result, a *sast.Result) []store.FindingRecord {
	var records []store.FindingRecord
	if s != nil {
		for _, f := range s.Findings {
			records = append(records, store.FindingRecord{
				Scanner: "secrets",
				// Gitleaks does not emit per-finding severity; we treat all
				// detected secrets as HIGH — a leaked credential is always
				// significant regardless of entropy. Future versions may
				// introduce per-rule overrides via a custom gitleaks config.
				Severity: "HIGH",
				RuleID:   f.RuleID,
				File:     f.File,
				Line:     f.StartLine,
				Message:  f.Description,
				RawMatch: redactForStore(f.Match, f.Secret),
			})
		}
	}
	if a != nil {
		for _, f := range a.Findings {
			records = append(records, store.FindingRecord{
				Scanner:  "sast",
				Severity: f.Severity,
				RuleID:   f.RuleID,
				File:     f.Path,
				Line:     f.Start.Line,
				Message:  f.Message,
				RawMatch: f.Lines,
			})
		}
	}
	return records
}

func redactForStore(match, secret string) string {
	if secret == "" || match == "" {
		return match
	}
	n := len(secret)
	if n > 12 {
		n = 12
	}
	return strings.ReplaceAll(match, secret, strings.Repeat("*", n))
}

func writeJSONOutput(path string, s *secrets.Result, a *sast.Result) {
	if scanOutput != "" {
		f, err := os.Create(scanOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Could not create output file: %v\n", err)
			return
		}
		defer f.Close()
		output.WriteJSON(f, path, s, a)
		return
	}
	output.WriteJSON(os.Stdout, path, s, a)
}
