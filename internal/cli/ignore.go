package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/isthobbit/vigyl/internal/store"
	"github.com/spf13/cobra"
)

var ignoreReason string

var ignoreCmd = &cobra.Command{
	Use:   "ignore <finding-id>",
	Short: "Suppress a finding from future scan output",
	Long: `Mark a finding as ignored so it no longer appears in scan output or recommendations.

The finding is identified by its ID from the most recent scan. Run 'jensec report'
to see finding IDs.

Examples:
  jensec ignore 42
  jensec ignore 42 --reason "test data, not a real credential"
  jensec ignore list
  jensec ignore remove 3`,
	Args: cobra.MaximumNArgs(1),
	RunE: runIgnore,
}

var ignoreListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all ignored findings",
	RunE:  runIgnoreList,
}

var ignoreRemoveCmd = &cobra.Command{
	Use:   "remove <ignore-id>",
	Short: "Remove an ignore rule and reinstate the finding",
	Args:  cobra.ExactArgs(1),
	RunE:  runIgnoreRemove,
}

func init() {
	ignoreCmd.AddCommand(ignoreListCmd, ignoreRemoveCmd)
	ignoreCmd.Flags().StringVar(&ignoreReason, "reason", "", "why this finding is being ignored")
	rootCmd.AddCommand(ignoreCmd)
}

func runIgnore(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	findingID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid finding ID %q — must be a number", args[0])
	}

	cfg := loadConfig()
	db, err := store.Open(cfg.Storage.DBPath)
	if err != nil {
		return fmt.Errorf("could not open scan history: %w", err)
	}
	defer db.Close()

	// Try to find the finding in code_findings first, then dep_findings.
	record, err := buildIgnoreFromCodeFinding(db, findingID)
	if err != nil {
		return err
	}
	if record == nil {
		record, err = buildIgnoreFromDepFinding(db, findingID)
		if err != nil {
			return err
		}
	}
	if record == nil {
		return fmt.Errorf("finding ID %d not found — run 'jensec report' to see finding IDs", findingID)
	}

	if ignoreReason != "" {
		record.Reason = ignoreReason
	}

	if err := db.SaveIgnore(*record); err != nil {
		return fmt.Errorf("could not save ignore rule: %w", err)
	}

	fmt.Printf("Finding %d ignored", findingID)
	if record.Reason != "no reason provided" {
		fmt.Printf(" — %s", record.Reason)
	}
	fmt.Println()

	if record.FindingType == "code" {
		fmt.Printf("  [%s] %s in %s\n", record.Scanner, record.RuleID, record.File)
	} else {
		fmt.Printf("  [%s] %s in %s\n", record.Scanner, record.CVEID, record.Package)
	}

	fmt.Println("\nThis finding will be suppressed in future scans.")
	fmt.Println("Run 'jensec ignore list' to see all ignored findings.")
	return nil
}

func runIgnoreList(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	db, err := store.Open(cfg.Storage.DBPath)
	if err != nil {
		return fmt.Errorf("could not open scan history: %w", err)
	}
	defer db.Close()

	records, err := db.AllIgnored()
	if err != nil {
		return fmt.Errorf("could not retrieve ignored findings: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("No ignored findings. Use 'jensec ignore <finding-id>' to suppress a finding.")
		return nil
	}

	fmt.Printf("%-6s  %-8s  %-10s  %-30s  %s\n", "ID", "SCANNER", "TYPE", "FINDING", "REASON")
	fmt.Println(strings.Repeat("─", 80))

	for _, r := range records {
		finding := r.File
		if r.FindingType == "dep" {
			finding = r.Package
		}
		if len(finding) > 30 {
			finding = "..." + finding[len(finding)-27:]
		}
		reason := r.Reason
		if len(reason) > 30 {
			reason = reason[:27] + "..."
		}
		fmt.Printf("%-6d  %-8s  %-10s  %-30s  %s\n",
			r.ID, r.Scanner, r.FindingType, finding, reason,
		)
	}

	fmt.Printf("\n%d ignored finding(s). Use 'jensec ignore remove <id>' to reinstate.\n", len(records))
	return nil
}

func runIgnoreRemove(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid ID %q — must be a number", args[0])
	}

	cfg := loadConfig()
	db, err := store.Open(cfg.Storage.DBPath)
	if err != nil {
		return fmt.Errorf("could not open scan history: %w", err)
	}
	defer db.Close()

	if err := db.RemoveIgnore(id); err != nil {
		return fmt.Errorf("could not remove ignore rule: %w", err)
	}

	fmt.Printf("Ignore rule %d removed — finding will appear in future scans.\n", id)
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// buildIgnoreFromCodeFinding looks up a code finding by ID and builds an
// IgnoredFindingRecord from it. Returns nil if not found.
func buildIgnoreFromCodeFinding(db *store.DB, id int64) (*store.IgnoredFindingRecord, error) {
	findings, err := db.CodeFindingByID(id)
	if err != nil {
		return nil, err
	}
	if findings == nil {
		return nil, nil
	}

	return &store.IgnoredFindingRecord{
		Fingerprint: store.CodeFingerprint(findings.Scanner, findings.RuleID, findings.File),
		Scanner:     findings.Scanner,
		FindingType: "code",
		Reason:      "no reason provided",
		IgnoredAt:   time.Now(),
		RuleID:      findings.RuleID,
		File:        findings.File,
	}, nil
}

// buildIgnoreFromDepFinding looks up a dependency finding by ID and builds an
// IgnoredFindingRecord from it. Returns nil if not found.
func buildIgnoreFromDepFinding(db *store.DB, id int64) (*store.IgnoredFindingRecord, error) {
	finding, err := db.DepFindingByID(id)
	if err != nil {
		return nil, err
	}
	if finding == nil {
		return nil, nil
	}

	return &store.IgnoredFindingRecord{
		Fingerprint: store.DepFingerprint(finding.Scanner, finding.Package, finding.Version, finding.CVEID),
		Scanner:     finding.Scanner,
		FindingType: "dep",
		Reason:      "no reason provided",
		IgnoredAt:   time.Now(),
		Package:     finding.Package,
		CVEID:       finding.CVEID,
	}, nil
}

// isIgnoredCodeFinding checks if a code finding's fingerprint is in the ignore list.
func isIgnoredCodeFinding(ignored map[string]bool, f store.CodeFindingRecord) bool {
	return ignored[store.CodeFingerprint(f.Scanner, f.RuleID, f.File)]
}

// isIgnoredDepFinding checks if a dep finding's fingerprint is in the ignore list.
func isIgnoredDepFinding(ignored map[string]bool, f store.DepFindingRecord) bool {
	return ignored[store.DepFingerprint(f.Scanner, f.Package, f.Version, f.CVEID)]
}

// filterIgnoredCode returns code findings with ignored ones removed,
// and a separate slice of the ignored ones for dimmed display.
func filterIgnoredCode(findings []store.CodeFindingRecord, ignored map[string]bool) (active, suppressed []store.CodeFindingRecord) {
	for _, f := range findings {
		if isIgnoredCodeFinding(ignored, f) {
			suppressed = append(suppressed, f)
		} else {
			active = append(active, f)
		}
	}
	return
}

// filterIgnoredDep returns dep findings with ignored ones removed.
func filterIgnoredDep(findings []store.DepFindingRecord, ignored map[string]bool) (active, suppressed []store.DepFindingRecord) {
	for _, f := range findings {
		if isIgnoredDepFinding(ignored, f) {
			suppressed = append(suppressed, f)
		} else {
			active = append(active, f)
		}
	}
	return
}

// ignoredSummaryLine returns a one-line summary of suppressed findings.
func ignoredSummaryLine(codeCount, depCount int) string {
	total := codeCount + depCount
	if total == 0 {
		return ""
	}
	parts := []string{}
	if codeCount > 0 {
		parts = append(parts, fmt.Sprintf("%d code", codeCount))
	}
	if depCount > 0 {
		parts = append(parts, fmt.Sprintf("%d dependency", depCount))
	}
	return fmt.Sprintf("  [IGNORED] %s finding(s) suppressed. Run 'jensec ignore list' to review.\n",
		strings.Join(parts, ", "))
}

// suppress unused import warning
var _ = os.Stderr
