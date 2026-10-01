package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/isthobbit/vigyl/internal/offline"
	"github.com/spf13/cobra"
)

var (
	offlineDir          string
	offlineSources      []string
	offlineEcosystems   []string
	offlineSemgrepPacks []string
	offlineJavaDB       bool
	offlineNoVerify     bool
)

var offlineCmd = &cobra.Command{
	Use:   "offline",
	Short: "Prepare and manage data for offline scanning",
	Long: `Manage the local data that 'jensec scan --offline' uses: the Trivy
vulnerability DB, OSV ecosystem databases and Semgrep rule packs.

On a connected machine:
  jensec offline sync
  jensec offline export jensec-offline.tar.gz

Copy jensec-offline.tar.gz and jensec-offline.tar.gz.sha256 to the
air-gapped machine, then:
  jensec offline import jensec-offline.tar.gz
  jensec scan all . --offline`,
}

var offlineSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Download vulnerability databases and rule packs for offline use",
	Long: `Download everything offline scans need into the offline directory
(default ~/.vigyl/offline).

Semgrep rule packs are fetched from the Semgrep registry onto this machine;
jensec does not ship them.

Examples:
  jensec offline sync
  jensec offline sync --only osv --ecosystems npm,PyPI
  jensec offline sync --semgrep-packs default,secrets,golang
  jensec offline sync --java-db`,
	Args: cobra.NoArgs,
	RunE: runOfflineSync,
}

var offlineStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show what offline data is present and how old it is",
	Args:  cobra.NoArgs,
	RunE:  runOfflineStatus,
}

var offlineExportCmd = &cobra.Command{
	Use:   "export <file.tar.gz>",
	Short: "Pack offline data into one archive for an air-gapped machine",
	Args:  cobra.ExactArgs(1),
	RunE:  runOfflineExport,
}

var offlineImportCmd = &cobra.Command{
	Use:   "import <file.tar.gz>",
	Short: "Unpack an archive made by 'jensec offline export'",
	Long: `Unpack an archive made by 'jensec offline export' into the offline
directory. The archive is checked against <file>.sha256 first.`,
	Args: cobra.ExactArgs(1),
	RunE: runOfflineImport,
}

func init() {
	offlineCmd.AddCommand(offlineSyncCmd, offlineStatusCmd, offlineExportCmd, offlineImportCmd)
	offlineCmd.PersistentFlags().StringVar(&offlineDir, "dir", "", "offline data directory (default: storage.offline_dir or ~/.vigyl/offline)")

	offlineSyncCmd.Flags().StringSliceVar(&offlineSources, "only", nil, "sync only these sources (trivy,osv,semgrep)")
	offlineSyncCmd.Flags().StringSliceVar(&offlineEcosystems, "ecosystems", nil, "OSV ecosystems to download (default: "+strings.Join(offline.DefaultEcosystems, ",")+")")
	offlineSyncCmd.Flags().StringSliceVar(&offlineSemgrepPacks, "semgrep-packs", nil, "Semgrep registry packs to download (default: "+strings.Join(offline.DefaultSemgrepPacks, ",")+")")
	offlineSyncCmd.Flags().BoolVar(&offlineJavaDB, "java-db", false, "also download Trivy's Java DB (large; needed to scan .jar files)")

	offlineImportCmd.Flags().BoolVar(&offlineNoVerify, "no-verify", false, "skip the .sha256 checksum check")

	rootCmd.AddCommand(offlineCmd)
}

func offlinePaths() (offline.Paths, error) {
	dir := offlineDir
	if dir == "" {
		dir = loadConfig().Storage.OfflineDir
	}
	return offline.Resolve(dir)
}

func runOfflineSync(cmd *cobra.Command, args []string) error {
	for _, s := range offlineSources {
		switch s {
		case offline.SourceTrivy, offline.SourceOSV, offline.SourceSemgrep:
		default:
			return fmt.Errorf("unknown source %q — must be one of: trivy, osv, semgrep", s)
		}
	}
	p, err := offlinePaths()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(os.Stderr, "Syncing offline data into %s\n", p.Root)
	syncErr := offline.Sync(ctx, p, offline.SyncOptions{
		Sources:      offlineSources,
		Ecosystems:   offlineEcosystems,
		SemgrepPacks: offlineSemgrepPacks,
		JavaDB:       offlineJavaDB,
	}, os.Stderr)

	fmt.Fprintln(os.Stderr)
	if err := printOfflineStatus(p); err != nil {
		return err
	}
	if syncErr != nil {
		return fmt.Errorf("sync finished with errors:\n%w", syncErr)
	}
	return nil
}

func runOfflineStatus(cmd *cobra.Command, args []string) error {
	p, err := offlinePaths()
	if err != nil {
		return err
	}
	return printOfflineStatus(p)
}

func printOfflineStatus(p offline.Paths) error {
	rows, err := p.Status(time.Now())
	if err != nil {
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"dir": p.Root, "sources": rows})
	}

	fmt.Printf("Offline data: %s\n\n", p.Root)
	for _, r := range rows {
		state := "ready"
		switch {
		case !r.Ready:
			state = "missing"
		case r.Stale:
			state = "STALE"
		}
		synced := "never"
		if !r.SyncedAt.IsZero() {
			synced = fmt.Sprintf("%s (%s ago)", r.SyncedAt.Local().Format("2006-01-02 15:04"), humanAge(time.Since(r.SyncedAt)))
		}
		fmt.Printf("  %-8s %-8s synced %s\n", r.Source, state, synced)
		if len(r.Items) > 0 {
			fmt.Printf("           %s\n", strings.Join(r.Items, ", "))
		}
	}
	for _, r := range rows {
		if r.Stale {
			fmt.Printf("\nWARNING: some offline data is over %d days old and will miss recently published vulnerabilities. Run 'jensec offline sync'.\n", int(offline.StaleAfter.Hours()/24))
			break
		}
	}
	return nil
}

func runOfflineExport(cmd *cobra.Command, args []string) error {
	p, err := offlinePaths()
	if err != nil {
		return err
	}
	sum, err := offline.Export(p, args[0])
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}
	info, _ := os.Stat(args[0])
	size := int64(0)
	if info != nil {
		size = info.Size()
	}
	fmt.Printf("Wrote %s (%.1f MB)\n", args[0], float64(size)/(1<<20))
	fmt.Printf("Wrote %s.sha256 (sha256 %s)\n", args[0], sum)
	fmt.Println("Copy both files to the offline machine and run 'jensec offline import'.")
	return nil
}

func runOfflineImport(cmd *cobra.Command, args []string) error {
	p, err := offlinePaths()
	if err != nil {
		return err
	}
	if err := offline.Import(p, args[0], offlineNoVerify); err != nil {
		return fmt.Errorf("import failed: %w", err)
	}
	fmt.Printf("Imported %s\n\n", args[0])
	return printOfflineStatus(p)
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
