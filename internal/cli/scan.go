package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/isthobbit/vigil/internal/config"
	"github.com/isthobbit/vigil/internal/correlate"
	"github.com/isthobbit/vigil/internal/installer"
	"github.com/isthobbit/vigil/internal/recommend"
	"github.com/isthobbit/vigil/internal/scan/deps/osv"
	"github.com/isthobbit/vigil/internal/scan/deps/trivy"
	"github.com/isthobbit/vigil/internal/scan/sast"
	"github.com/isthobbit/vigil/internal/scan/secrets"
	"github.com/isthobbit/vigil/internal/store"
	"github.com/isthobbit/vigil/internal/trends"
	"github.com/isthobbit/vigil/pkg/output"
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
	Short: "Run all scans (secrets + SAST + dependencies)",
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

var scanDepsCmd = &cobra.Command{
	Use:   "deps [path]",
	Short: "Run dependency vulnerability scan (powered by Trivy + OSV)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScanDeps,
}

func init() {
	scanCmd.AddCommand(scanAllCmd, scanSASTCmd, scanSecretsCmd, scanDepsCmd)
	rootCmd.AddCommand(scanCmd)

	for _, cmd := range []*cobra.Command{scanAllCmd, scanSASTCmd, scanSecretsCmd, scanDepsCmd} {
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

	gitleaksOK, semgrepOK, trivyOK, osvOK := installer.EnsureAll(noColor)

	cfg := loadConfig()
	threshold := resolveFailOn(cfg)
	startedAt := time.Now()

	if !jsonOut {
		scanners := activeScanners(gitleaksOK, semgrepOK, trivyOK, osvOK)
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

	var trivyResult *trivy.Result
	if trivyOK {
		trivyResult, err = trivy.Run(path, verbose, cfg.Scan.Timeout, cfg.Scan.ExcludePaths)
		if err != nil {
			printScannerError("trivy", err)
		}
	}

	var osvResult *osv.Result
	if osvOK {
		osvResult, err = osv.Run(path, verbose, cfg.Scan.Timeout, cfg.Scan.ExcludePaths)
		if err != nil {
			printScannerError("osv", err)
		}
	}

	elapsed := time.Since(startedAt)

	if !jsonOut {
		sc, ac := countResults(secretsResult, sastResult)
		output.PrintScanSummary(sc, ac, elapsed, noColor)
	}

	persistScan(path, "secrets,sast,trivy,osv", startedAt, time.Now(), secretsResult, sastResult, trivyResult, osvResult)

	if jsonOut || scanOutput != "" {
		writeJSONOutput(path, secretsResult, sastResult, trivyResult, osvResult)
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

	persistScan(path, "sast", startedAt, time.Now(), nil, result, nil, nil)

	if jsonOut || scanOutput != "" {
		writeJSONOutput(path, nil, result, nil, nil)
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

	persistScan(path, "secrets", startedAt, time.Now(), result, nil, nil, nil)

	if jsonOut || scanOutput != "" {
		writeJSONOutput(path, result, nil, nil, nil)
	}

	if config.MeetsSeverityThreshold(highestSeverity(result, nil), threshold) {
		os.Exit(1)
	}
	return nil
}

func runScanDeps(cmd *cobra.Command, args []string) error {
	path, err := resolvePath(args)
	if err != nil {
		return err
	}

	trivyOK := installer.IsInstalled(installer.Trivy)
	osvOK := installer.IsInstalled(installer.OSVScanner)

	if !trivyOK {
		ok, _ := installer.Prompt(installer.Trivy, noColor)
		trivyOK = ok
	}
	if !osvOK {
		ok, _ := installer.Prompt(installer.OSVScanner, noColor)
		osvOK = ok
	}

	if !trivyOK && !osvOK {
		fmt.Fprintln(os.Stderr, "At least one of trivy or osv-scanner is required. Exiting.")
		os.Exit(2)
	}

	cfg := loadConfig()
	startedAt := time.Now()

	if !jsonOut {
		output.PrintScanHeader(path, []string{"trivy", "osv"}, noColor)
	}

	var trivyResult *trivy.Result
	if trivyOK {
		trivyResult, err = trivy.Run(path, verbose, cfg.Scan.Timeout, cfg.Scan.ExcludePaths)
		if err != nil {
			printScannerError("trivy", err)
		}
	}

	var osvResult *osv.Result
	if osvOK {
		osvResult, err = osv.Run(path, verbose, cfg.Scan.Timeout, cfg.Scan.ExcludePaths)
		if err != nil {
			printScannerError("osv", err)
		}
	}

	elapsed := time.Since(startedAt)
	_ = elapsed

	persistScan(path, "trivy,osv", startedAt, time.Now(), nil, nil, trivyResult, osvResult)

	if jsonOut || scanOutput != "" {
		writeJSONOutput(path, nil, nil, trivyResult, osvResult)
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

func shouldFail(threshold string, s *secrets.Result, a *sast.Result) bool {
	if threshold == "none" {
		return false
	}
	return config.MeetsSeverityThreshold(highestSeverity(s, a), threshold)
}

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

func activeScanners(gitleaksOK, semgrepOK, trivyOK, osvOK bool) []string {
	var s []string
	if gitleaksOK {
		s = append(s, "secrets")
	}
	if semgrepOK {
		s = append(s, "sast")
	}
	if trivyOK {
		s = append(s, "trivy")
	}
	if osvOK {
		s = append(s, "osv")
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

func persistScan(path, scanners string, startedAt, endedAt time.Time, s *secrets.Result, a *sast.Result, t *trivy.Result, o *osv.Result) {
	cfg := loadConfig()
	db, err := store.Open(cfg.Storage.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Could not open scan history: %v\n", err)
		return
	}
	defer db.Close()

	codeFindings := buildCodeFindingRecords(s, a)
	scanID, err := db.SaveScan(path, scanners, startedAt, endedAt, codeFindings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Could not save scan: %v\n", err)
		return
	}

	depFindings := buildDepFindingRecords(t, o)
	if len(depFindings) > 0 {
		if err := db.SaveDependencyFindings(scanID, depFindings); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Could not save dependency findings: %v\n", err)
		}
	}

	// Run the correlation engine.
	engine := correlate.New(db, nil)
	codeRecs, _ := db.CodeFindingsForScan(scanID)
	depRecs, _ := db.DepFindingsForScan(scanID)
	if err := engine.Run(correlate.Input{
		ScanID:       scanID,
		CodeFindings: codeRecs,
		DepFindings:  depRecs,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Correlation engine error: %v\n", err)
	}

	// Generate and display recommendations.
	correlationRecs, _ := db.CorrelationsForScan(scanID)
	recs := recommend.Generate(correlationRecs, codeRecs, depRecs)
	if !jsonOut && len(recs) > 0 {
		output.PrintRecommendations(recs, noColor)
	}

	// Run trend analysis.
	trendCfg := trends.DefaultConfig()
	if report, err := trends.Analyse(db, scanID, path, trendCfg); err == nil && !jsonOut {
		trends.Print(report, noColor)
	}

	if verbose {
		fmt.Printf("  Scan saved (ID: %d)\n", scanID)
	}
}

func buildCodeFindingRecords(s *secrets.Result, a *sast.Result) []store.CodeFindingRecord {
	var records []store.CodeFindingRecord
	if s != nil {
		for _, f := range s.Findings {
			records = append(records, store.CodeFindingRecord{
				Scanner:  "secrets",
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
			records = append(records, store.CodeFindingRecord{
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

func buildDepFindingRecords(t *trivy.Result, o *osv.Result) []store.DepFindingRecord {
	var records []store.DepFindingRecord
	if t != nil {
		for _, f := range t.Findings {
			records = append(records, store.DepFindingRecord{
				Scanner:      "trivy",
				Severity:     f.Severity,
				Package:      f.Package,
				Version:      f.Version,
				CVEID:        f.CVEID,
				Ecosystem:    f.Ecosystem,
				FixedVersion: f.FixedVersion,
				Description:  f.Description,
			})
		}
	}
	if o != nil {
		for _, f := range o.Findings {
			records = append(records, store.DepFindingRecord{
				Scanner:      "osv",
				Severity:     f.Severity,
				Package:      f.Package,
				Version:      f.Version,
				CVEID:        f.CVEID,
				Ecosystem:    f.Ecosystem,
				FixedVersion: f.FixedVersion,
				Description:  f.Description,
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

func writeJSONOutput(path string, s *secrets.Result, a *sast.Result, t *trivy.Result, o *osv.Result) {
	if scanOutput != "" {
		f, err := os.Create(scanOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Could not create output file: %v\n", err)
			return
		}
		defer f.Close()
		output.WriteJSON(f, path, s, a, t, o)
		return
	}
	output.WriteJSON(os.Stdout, path, s, a, t, o)
}
