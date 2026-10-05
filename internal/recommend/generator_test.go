package recommend

import (
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/store"
)

func ptr(id int64) *int64 { return &id }

func depRec(id int64, scanner, severity, pkg, version, cve, fixed string) store.DepFindingRecord {
	return store.DepFindingRecord{ID: id, Scanner: scanner, Severity: severity, Package: pkg, Version: version, CVEID: cve, FixedVersion: fixed}
}

// Every package rule, on every version of a package, becomes one
// recommendation for that package.
func TestGenerate_OneRecommendationPerPackage(t *testing.T) {
	deps := []store.DepFindingRecord{
		depRec(1, "trivy", "CRITICAL", "minimist", "0.0.8", "CVE-2021-44906", "1.2.6"),
		depRec(2, "osv", "CRITICAL", "minimist", "0.0.8", "CVE-2021-44906", "1.2.6"),
		depRec(3, "trivy", "MEDIUM", "minimist", "0.0.8", "CVE-2020-7598", "0.2.1"),
		depRec(4, "trivy", "CRITICAL", "minimist", "1.2.0", "CVE-2021-44906", "1.2.6"),
		depRec(5, "osv", "HIGH", "lodash", "4.17.15", "CVE-2021-23337", "4.17.21"),
	}
	corr := []store.CorrelationRecord{
		{Reason: "cve_confirmed_by_multiple_scanners", DepFindingID: ptr(1), TargetFindingID: ptr(2)},
		{Reason: "multiple_cves_in_same_package", DepFindingID: ptr(1), TargetFindingID: ptr(3)},
		{Reason: "multiple_cves_in_same_package", DepFindingID: ptr(4)},
		{Reason: "multiple_cves_in_same_package", DepFindingID: ptr(5)},
	}

	recs := Generate(corr, nil, deps)
	if len(recs) != 2 {
		t.Fatalf("expected one recommendation each for minimist and lodash, got %d: %+v", len(recs), recs)
	}

	m := recs[0]
	if m.Title != "Upgrade minimist (2 vulnerable versions installed)" || m.Priority != "CRITICAL" {
		t.Errorf("minimist recommendation wrong: %+v", m)
	}
	for _, want := range []string{"versions 0.0.8, 1.2.0", "2 known vulnerabilities", "CVE-2021-44906 (CRITICAL)", "Both Trivy and OSV-Scanner"} {
		if !strings.Contains(m.Context, want) {
			t.Errorf("context missing %q: %s", want, m.Context)
		}
	}
	if !strings.Contains(m.Action, "0.0.8 to 1.2.6; 1.2.0 to 1.2.6") {
		t.Errorf("action should give each version's fix: %s", m.Action)
	}
	if len(m.FindingRefs) != 4 {
		t.Errorf("expected all four minimist findings referenced, got %v", m.FindingRefs)
	}

	l := recs[1]
	if l.Title != "Upgrade lodash 4.17.15" || l.Action != "Upgrade lodash from 4.17.15 to 4.17.21." || strings.Contains(l.Context, "Both") {
		t.Errorf("lodash recommendation wrong: %+v", l)
	}
}

func TestShortPath(t *testing.T) {
	for in, want := range map[string]string{
		"app/db.py":            "app/db.py",
		"artifacts/cert/a.key": "artifacts/cert/a.key",
		"a/b/c/d/e.go":         ".../d/e.go",
		`C:\Users\x\repo\a.go`: ".../repo/a.go",
	} {
		if got := shortPath(in); got != want {
			t.Errorf("shortPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNearestFix(t *testing.T) {
	for _, c := range []struct{ installed, fixed, want string }{
		{"0.0.10", "1.2.6, 0.2.4", "0.2.4"}, // the fix on its own release line
		{"1.2.0", "1.2.6, 0.2.4", "1.2.6"},
		{"2.0.0", "2.0.1, 3.0.1", "2.0.1"},
		{"4.16.4", "4.19.2, 5.0.0-beta.3", "4.19.2"},
		{"1.0.0", "", ""},
	} {
		if got := nearestFix(c.installed, c.fixed); got != c.want {
			t.Errorf("nearestFix(%q, %q) = %q, want %q", c.installed, c.fixed, got, c.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.0.10", "0.0.8", 1},
		{"1.2", "1.2.0", 0},
		{"5.0.0-beta.3", "5.0.0", -1},
		{"v1.10.0", "1.9.9", 1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
