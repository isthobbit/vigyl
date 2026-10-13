package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/config"
	"github.com/isthobbit/vigyl/internal/scan/deps/osv"
	"github.com/isthobbit/vigyl/internal/scan/deps/trivy"
	"github.com/isthobbit/vigyl/internal/scan/sast"
	"github.com/isthobbit/vigyl/internal/scan/secrets"
	"github.com/isthobbit/vigyl/internal/store"
	"github.com/spf13/cobra"
)

func TestCodeFails(t *testing.T) {
	s := &secrets.Result{Findings: []secrets.Finding{{RuleID: "github-pat", File: "/repo/.env"}}}
	a := &sast.Result{Findings: []sast.Finding{{RuleID: "eval-detected", Path: "/repo/app.py", Severity: "CRITICAL"}}}
	none := map[string]bool{}

	if !codeFails("critical", s, a, none) {
		t.Error("a CRITICAL code finding should fail --fail-on critical")
	}
	if codeFails("critical", s, nil, none) {
		t.Error("secrets count as HIGH, so they should not fail --fail-on critical")
	}
	if codeFails("low", nil, &sast.Result{}, none) {
		t.Error("a scan with no findings must not fail, even at --fail-on low")
	}

	ignored := map[string]bool{
		store.CodeFingerprint("sast", "eval-detected", "/repo/app.py"): true,
		store.CodeFingerprint("secrets", "github-pat", "/repo/.env"):   true,
	}
	if codeFails("low", s, a, ignored) {
		t.Error("ignored findings must not fail the scan")
	}
}

func TestDepFailures(t *testing.T) {
	tr := &trivy.Result{Findings: []trivy.Finding{
		{Package: "minimist", Version: "1.2.0", CVEID: "CVE-2021-44906", Severity: "CRITICAL", FixedVersion: "1.2.6"},
		{Package: "lodash", Version: "4.17.15", CVEID: "CVE-2020-8203", Severity: "HIGH", FixedVersion: "4.17.19"},
		{Package: "swig", Version: "1.4.2", CVEID: "CVE-2023-25345", Severity: "HIGH"},
		{Package: "ms", Version: "2.0.0", CVEID: "CVE-2017-20162", Severity: "MEDIUM", FixedVersion: "2.0.1"},
	}}
	ov := &osv.Result{Findings: []osv.Finding{
		// The same minimist CVE again: must count once.
		{Package: "minimist", Version: "1.2.0", CVEID: "CVE-2021-44906", Severity: "CRITICAL"},
	}}
	none := map[string]bool{}

	if got := depFailures(depsGate{threshold: "none"}, tr, ov, none); len(got) != 0 {
		t.Errorf("threshold none must never fail, got %d", len(got))
	}

	got := depFailures(depsGate{threshold: "high"}, tr, ov, none)
	if len(got) != 3 {
		t.Fatalf("expected minimist, lodash and swig at or above HIGH, got %+v", got)
	}
	if got[0].Package != "minimist" || len(got[0].FoundBy) != 2 {
		t.Errorf("most severe first, merged across scanners: %+v", got[0])
	}

	if got := depFailures(depsGate{threshold: "high", fixableOnly: true}, tr, ov, none); len(got) != 2 {
		t.Errorf("fixable only should drop swig, got %+v", got)
	}

	// Ignoring OSV's copy of the minimist CVE ignores the vulnerability.
	ignored := map[string]bool{store.DepFingerprint("osv", "minimist", "1.2.0", "CVE-2021-44906"): true}
	for _, d := range depFailures(depsGate{threshold: "high"}, tr, ov, ignored) {
		if d.Package == "minimist" {
			t.Error("a vulnerability ignored for one scanner must not fail the scan")
		}
	}
}

func TestPrintDepFailures(t *testing.T) {
	tr := &trivy.Result{}
	for i := 0; i < 12; i++ {
		tr.Findings = append(tr.Findings, trivy.Finding{Package: "pkg", Version: string(rune('a' + i)), CVEID: "CVE-1", Severity: "HIGH", FixedVersion: "9"})
	}
	g := depsGate{threshold: "high", fixableOnly: true}
	var buf bytes.Buffer
	printDepFailures(&buf, g, depFailures(g, tr, nil, map[string]bool{}))
	out := buf.String()
	for _, want := range []string{"Failing: 12 dependency vulnerabilities at or above HIGH with a fix available.", "pkg@a  CVE-1  fix: 9", "+2 more"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestResolveThresholds(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scan.FailOnDeps = "critical"
	cfg.Scan.FailOnDepsFixable = true

	newCmd := func() *cobra.Command {
		c := &cobra.Command{}
		c.Flags().StringVar(&failOnDeps, "fail-on-deps", "", "")
		c.Flags().BoolVar(&failOnDepsFixable, "fail-on-deps-fixable", false, "")
		return c
	}

	c := newCmd()
	g, err := resolveDepsGate(c, &cfg)
	if err != nil || g.threshold != "critical" || !g.fixableOnly {
		t.Errorf("config values should apply without flags: %+v, %v", g, err)
	}

	c = newCmd()
	if err := c.ParseFlags([]string{"--fail-on-deps", "HIGH", "--fail-on-deps-fixable=false"}); err != nil {
		t.Fatal(err)
	}
	g, err = resolveDepsGate(c, &cfg)
	if err != nil || g.threshold != "high" || g.fixableOnly {
		t.Errorf("flags should override the config: %+v, %v", g, err)
	}

	c = newCmd()
	if err := c.ParseFlags([]string{"--fail-on-deps", "hgh"}); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDepsGate(c, &cfg); err == nil {
		t.Error("a misspelt --fail-on-deps must be rejected, not fail every scan")
	}
	failOnDeps, failOnDepsFixable = "", false

	failOn = "hgih"
	if _, err := resolveFailOn(&cfg); err == nil {
		t.Error("a misspelt --fail-on must be rejected")
	}
	failOn = ""
}

func TestDepsUnchecked(t *testing.T) {
	on, off := depsGate{threshold: "critical"}, depsGate{threshold: "none"}
	boom := errors.New("db download failed")
	for _, c := range []struct {
		name             string
		g                depsGate
		trivyRan, osvRan bool
		trivyErr, osvErr error
		want             string
	}{
		{"gate off ignores failures", off, true, true, boom, boom, ""},
		{"both succeed", on, true, true, nil, nil, ""},
		{"one scanner not installed is fine", on, false, true, nil, nil, ""},
		{"trivy failed", on, true, true, boom, nil, "trivy failed"},
		{"both failed", on, true, true, boom, boom, "trivy failed and osv-scanner failed"},
		{"none available", on, false, false, nil, nil, "neither trivy nor osv-scanner is available"},
	} {
		got := depsUnchecked(c.g, c.trivyRan, c.osvRan, c.trivyErr, c.osvErr)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want it to mention %q", c.name, got, c.want)
		}
	}
}
