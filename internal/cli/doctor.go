package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/isthobbit/vigyl/internal/doctor"
	"github.com/isthobbit/vigyl/pkg/version"
	"github.com/spf13/cobra"
)

var doctorOffline bool

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check that jensec and its scanners are set up correctly",
	Long: `Check everything jensec needs to scan: the four scanners (installed, on
PATH, and a supported version), offline data, the config file and the scan
history database. Each problem comes with the fix.

doctor only inspects; it installs, downloads and changes nothing. It exits 1
when any check fails, so it can gate a CI job:

  jensec doctor
  jensec doctor --offline     # also require offline data to be synced
  jensec doctor --json`,
	Args: cobra.NoArgs,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorOffline, "offline", false, "treat missing offline data as a failure")
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, args []string) error {
	checks := doctor.Run(doctor.Options{
		Env:        doctor.SystemEnv(),
		ConfigFile: cfgFile,
		Offline:    doctorOffline,
		Now:        time.Now(),
	})
	fails, warns := doctor.Summary(checks)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"version":  version.Version,
			"ok":       fails == 0,
			"failures": fails,
			"warnings": warns,
			"checks":   checks,
		}); err != nil {
			return err
		}
	} else {
		printDoctor(checks, fails, warns)
	}

	if fails > 0 {
		os.Exit(1)
	}
	return nil
}

func printDoctor(checks []doctor.Check, fails, warns int) {
	fmt.Printf("jensec %s\n", version.Version)
	group := ""
	for _, c := range checks {
		if c.Group != group {
			group = c.Group
			fmt.Printf("\n%s\n", group)
		}
		fmt.Printf("  %s %-12s", doctorBadge(c.Status), c.Name)
		if c.Version != "" {
			fmt.Printf(" %-9s", c.Version)
		}
		switch {
		case c.Detail != "":
			fmt.Printf(" %s", c.Detail)
		case c.Path != "":
			fmt.Printf(" %s", c.Path)
		}
		fmt.Println()
		if c.Detail != "" && c.Path != "" && (c.Status == doctor.Warn || c.Status == doctor.Fail) {
			fmt.Printf("                 at:  %s\n", c.Path)
		}
		if c.Fix != "" {
			fmt.Printf("                 fix: %s\n", c.Fix)
		}
	}

	fmt.Println()
	switch {
	case fails == 0 && warns == 0:
		fmt.Println(doctorColor("\033[32m", "All checks passed."))
	case fails == 0:
		fmt.Println(doctorColor("\033[33m", fmt.Sprintf("%d warning%s; jensec can scan.", warns, plural(warns))))
	default:
		fmt.Println(doctorColor("\033[31m", fmt.Sprintf("%d problem%s, %d warning%s. Fix the problems above for complete results.", fails, plural(fails), warns, plural(warns))))
	}
}

func doctorBadge(s doctor.Status) string {
	switch s {
	case doctor.OK:
		return doctorColor("\033[32m", "[ ok ]")
	case doctor.Warn:
		return doctorColor("\033[33m", "[warn]")
	case doctor.Fail:
		return doctorColor("\033[31m", "[FAIL]")
	default:
		return doctorColor("\033[90m", "[ -- ]")
	}
}

func doctorColor(code, text string) string {
	if noColor {
		return text
	}
	return code + text + "\033[0m"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
