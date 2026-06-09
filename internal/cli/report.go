package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/isthobbit/kinga/internal/store"
	"github.com/isthobbit/kinga/pkg/output"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report [scan-id]",
	Short: "Display findings from a past scan",
	Long: `Display findings from scan history.

With no arguments, shows the most recent scan.
Pass a scan ID to show a specific scan: jensec report 3`,
	Args: cobra.MaximumNArgs(1),
	RunE: runReport,
}

var listScans bool

func init() {
	reportCmd.Flags().BoolVarP(&listScans, "list", "l", false, "list recent scans instead of showing findings")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	db, err := store.Open()
	if err != nil {
		return fmt.Errorf("could not open scan history: %w", err)
	}
	defer db.Close()

	// --list → print a summary table of recent scans and exit.
	if listScans {
		return printScanList(db)
	}

	// Resolve which scan to show.
	var scan *store.ScanRecord
	if len(args) == 1 {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid scan ID %q — must be a number", args[0])
		}
		scan, err = db.ScanByID(id)
		if err != nil {
			return fmt.Errorf("could not retrieve scan: %w", err)
		}
		if scan == nil {
			return fmt.Errorf("scan ID %d not found", id)
		}
	} else {
		scan, err = db.LatestScan()
		if err != nil {
			return fmt.Errorf("could not retrieve latest scan: %w", err)
		}
		if scan == nil {
			fmt.Println("No scan history found. Run `jensec scan all` first.")
			return nil
		}
	}

	findings, err := db.FindingsForScan(scan.ID)
	if err != nil {
		return fmt.Errorf("could not retrieve findings: %w", err)
	}

	if jsonOut {
		return output.WriteJSONFromStore(os.Stdout, scan, findings)
	}

	output.PrintStoredReport(scan, findings, noColor)
	return nil
}

func printScanList(db *store.DB) error {
	scans, err := db.RecentScans(20)
	if err != nil {
		return fmt.Errorf("could not retrieve scans: %w", err)
	}

	if len(scans) == 0 {
		fmt.Println("No scan history found. Run `jensec scan all` first.")
		return nil
	}

	fmt.Printf("%-6s  %-19s  %-10s  %-8s  %s\n", "ID", "DATE", "SCANNERS", "FINDINGS", "PATH")
	fmt.Println("──────  ───────────────────  ──────────  ────────  ────────────────────────────")

	for _, s := range scans {
		fmt.Printf("%-6d  %-19s  %-10s  %-8d  %s\n",
			s.ID,
			s.StartedAt.Local().Format("2006-01-02 15:04:05"),
			s.Scanners,
			s.Total,
			s.ScanPath,
		)
	}
	return nil
}
