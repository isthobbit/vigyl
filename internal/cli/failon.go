package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/isthobbit/vigyl/internal/config"
	"github.com/isthobbit/vigyl/internal/recommend"
	"github.com/isthobbit/vigyl/internal/scan/deps/osv"
	"github.com/isthobbit/vigyl/internal/scan/deps/trivy"
	"github.com/isthobbit/vigyl/internal/scan/sast"
	"github.com/isthobbit/vigyl/internal/scan/secrets"
	"github.com/isthobbit/vigyl/internal/store"
	"github.com/isthobbit/vigyl/pkg/output"
	"github.com/spf13/cobra"
)

// depsGate is when dependency vulnerabilities fail a scan.
type depsGate struct {
	threshold   string // critical | high | medium | low | none
	fixableOnly bool
}

// resolveFailOn returns the --fail-on threshold, from the flag or the config.
func resolveFailOn(cfg *config.Config) (string, error) {
	t := strings.ToLower(cfg.Scan.FailOn)
	if failOn != "" {
		t = strings.ToLower(failOn)
	}
	return t, checkThreshold("--fail-on", t)
}

// resolveDepsGate returns the --fail-on-deps settings, from the flags or the
// config.
func resolveDepsGate(cmd *cobra.Command, cfg *config.Config) (depsGate, error) {
	g := depsGate{threshold: strings.ToLower(cfg.Scan.FailOnDeps), fixableOnly: cfg.Scan.FailOnDepsFixable}
	if failOnDeps != "" {
		g.threshold = strings.ToLower(failOnDeps)
	}
	if cmd.Flags().Changed("fail-on-deps-fixable") {
		g.fixableOnly = failOnDepsFixable
	}
	return g, checkThreshold("--fail-on-deps", g.threshold)
}

// checkThreshold rejects an unknown severity, which would otherwise match
// every finding and fail every scan.
func checkThreshold(flag, value string) error {
	if !config.ValidFailOnValues[value] {
		return fmt.Errorf("invalid %s value %q — must be one of: critical, high, medium, low, none", flag, value)
	}
	return nil
}

// loadIgnored returns the fingerprints of findings hidden with
// `jensec ignore`. Without scan history nothing is ignored.
func loadIgnored(cfg *config.Config) map[string]bool {
	db, err := store.Open(cfg.Storage.DBPath)
	if err != nil {
		return map[string]bool{}
	}
	defer db.Close()
	ignored, err := db.IgnoredFingerprints()
	if err != nil || ignored == nil {
		return map[string]bool{}
	}
	return ignored
}

// codeFails reports whether a secret or code finding that is not ignored is
// at or above threshold.
func codeFails(threshold string, s *secrets.Result, a *sast.Result, ignored map[string]bool) bool {
	return config.MeetsSeverityThreshold(highestSeverity(s, a, ignored), threshold)
}

// highestSeverity is the highest severity among findings that are not
// ignored, or "" when there are none. Secrets have no severity of their own
// and count as high.
func highestSeverity(s *secrets.Result, a *sast.Result, ignored map[string]bool) string {
	best := ""
	raise := func(sev string) {
		if config.SeverityOrder[sev] > config.SeverityOrder[best] {
			best = sev
		}
	}
	if s != nil {
		for _, f := range s.Findings {
			if !ignored[store.CodeFingerprint("secrets", f.RuleID, f.File)] {
				raise("high")
			}
		}
	}
	if a != nil {
		for _, f := range a.Findings {
			if !ignored[store.CodeFingerprint("sast", f.RuleID, f.Path)] {
				raise(strings.ToLower(f.Severity))
			}
		}
	}
	return best
}

// depFailures returns the dependency vulnerabilities that fail the scan,
// most severe first. Each vulnerability counts once even when both scanners
// report it, and it is skipped if either scanner's report of it is ignored.
func depFailures(g depsGate, t *trivy.Result, o *osv.Result, ignored map[string]bool) []output.JSONDepFinding {
	if g.threshold == "none" {
		return nil
	}
	var out []output.JSONDepFinding
	for _, d := range output.MergeDeps(t, o) {
		if !config.MeetsSeverityThreshold(strings.ToLower(d.Severity), g.threshold) {
			continue
		}
		if g.fixableOnly && d.FixedVersion == "" {
			continue
		}
		skip := false
		for _, scanner := range d.FoundBy {
			if ignored[store.DepFingerprint(scanner, d.Package, d.Version, d.CVEID)] {
				skip = true
			}
		}
		if !skip {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return config.SeverityOrder[strings.ToLower(out[i].Severity)] > config.SeverityOrder[strings.ToLower(out[j].Severity)]
	})
	return out
}

// depsUnchecked reports why --fail-on-deps could not be checked: a
// dependency scanner that should have run failed, or none ran at all. A
// security gate must not pass when it has not looked, so the scan then
// exits 2 instead of 0. It returns "" when the gate is off or both scanners
// that ran succeeded.
func depsUnchecked(g depsGate, trivyRan, osvRan bool, trivyErr, osvErr error) string {
	if g.threshold == "none" {
		return ""
	}
	var problems []string
	if trivyRan && trivyErr != nil {
		problems = append(problems, "trivy failed")
	}
	if osvRan && osvErr != nil {
		problems = append(problems, "osv-scanner failed")
	}
	if !trivyRan && !osvRan {
		problems = append(problems, "neither trivy nor osv-scanner is available")
	}
	if len(problems) == 0 {
		return ""
	}
	return fmt.Sprintf("Cannot check --fail-on-deps: %s, so dependency vulnerabilities may be missed.", strings.Join(problems, " and "))
}

// printDepFailures explains why dependency vulnerabilities failed the scan.
func printDepFailures(w io.Writer, g depsGate, failures []output.JSONDepFinding) {
	fixable := 0
	for _, d := range failures {
		if d.FixedVersion != "" {
			fixable++
		}
	}
	noun := "vulnerabilities"
	if len(failures) == 1 {
		noun = "vulnerability"
	}
	detail := fmt.Sprintf(" (%d %s a fix)", fixable, map[bool]string{true: "has", false: "have"}[fixable == 1])
	if g.fixableOnly {
		detail = " with a fix available"
	}
	fmt.Fprintf(w, "Failing: %d dependency %s at or above %s%s.\n",
		len(failures), noun, strings.ToUpper(g.threshold), detail)

	const shown = 10
	for i, d := range failures {
		if i == shown {
			fmt.Fprintf(w, "  +%d more\n", len(failures)-shown)
			break
		}
		id := d.CVEID
		if id == "" {
			id = "(no advisory ID)"
		}
		fix := "no fix yet"
		if d.FixedVersion != "" {
			fix = "fix: " + recommend.NearestFix(d.Version, d.FixedVersion)
		}
		fmt.Fprintf(w, "  %-9s %s@%s  %s  %s\n", d.Severity, d.Package, d.Version, id, fix)
	}
}
