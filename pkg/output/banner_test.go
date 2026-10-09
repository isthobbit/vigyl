package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/deps/osv"
	"github.com/isthobbit/vigyl/internal/scan/deps/trivy"
)

func TestBanner_PlainTextIsAlignedAndUncoloured(t *testing.T) {
	plain := Banner(true)
	if strings.Contains(plain, "\033[") {
		t.Fatal("noColor banner contains ANSI escape codes")
	}
	lines := strings.Split(strings.TrimRight(plain, "\n"), "\n")
	if len(lines) != len(meerkat) {
		t.Fatalf("expected %d lines, got %d", len(meerkat), len(lines))
	}
	// Every caption starts in the same column, right of the meerkat.
	col := -1
	for i, line := range lines {
		if strings.HasSuffix(line, " ") {
			t.Errorf("line %d has trailing whitespace: %q", i, line)
		}
		caption, ok := bannerText[i]
		if !ok {
			continue
		}
		at := strings.Index(line, caption.text)
		if col == -1 {
			col = at
		} else if at != col {
			t.Errorf("line %d caption starts at column %d, want %d", i, at, col)
		}
	}
	for _, want := range []string{"jensec · by vigyl", "local-first DevSecOps scanner"} {
		if !strings.Contains(plain, want) {
			t.Errorf("banner missing %q", want)
		}
	}
}

func TestBanner_ColouredMatchesPlainText(t *testing.T) {
	coloured := Banner(false)
	if !strings.Contains(coloured, "\033[") {
		t.Fatal("coloured banner has no ANSI codes")
	}
	stripped := coloured
	for _, code := range []string{yellow, bold, dim, reset} {
		stripped = strings.ReplaceAll(stripped, code, "")
	}
	if stripped != Banner(true) {
		t.Error("coloured banner differs from plain banner beyond colour codes")
	}
}

func TestPrintBanner_SkipsNonTerminals(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	PrintBanner(f, false)
	f.Close()
	data, _ := os.ReadFile(f.Name())
	if len(data) != 0 {
		t.Errorf("banner written to a file: %q", data)
	}
}

func TestDepsToJSON_MergesAcrossScanners(t *testing.T) {
	tr := &trivy.Result{Findings: []trivy.Finding{
		{Package: "requests", Version: "2.19.0", CVEID: "CVE-2018-18074", Severity: "MEDIUM", Manifest: "requirements.txt"},
		{Package: "requests", Version: "2.19.0", CVEID: "CVE-2023-32681", Severity: "MEDIUM"},
	}}
	ov := &osv.Result{Findings: []osv.Finding{
		// The same CVE twice (OSV lists it under PYSEC and GHSA IDs), rated higher.
		{Package: "requests", Version: "2.19.0", CVEID: "CVE-2018-18074", Severity: "HIGH", FixedVersion: "2.20.0"},
		{Package: "requests", Version: "2.19.0", CVEID: "CVE-2018-18074", Severity: "HIGH"},
		{Package: "requests", Version: "2.19.0", CVEID: "GHSA-only-0000", Severity: "LOW"},
	}}
	got := depsToJSON(tr, ov)
	if len(got) != 3 {
		t.Fatalf("expected 3 distinct findings, got %d: %+v", len(got), got)
	}
	m := got[0]
	if m.CVEID != "CVE-2018-18074" || len(m.FoundBy) != 2 || m.Severity != "HIGH" || m.FixedVersion != "2.20.0" || m.Manifest != "requirements.txt" {
		t.Errorf("merged finding wrong: %+v", m)
	}
	if got[1].FoundBy[0] != "trivy" || got[2].FoundBy[0] != "osv" || len(got[2].FoundBy) != 1 {
		t.Errorf("unmerged findings should keep their own scanner: %+v / %+v", got[1], got[2])
	}
}

func TestScanProgress(t *testing.T) {
	for _, c := range []struct {
		scanners []string
		parallel bool
		want     string
	}{
		{[]string{"secrets", "sast", "trivy", "osv"}, true, "   Running secrets, sast, trivy and osv at the same time…"},
		{[]string{"trivy", "osv"}, false, "   Running trivy and osv one after another…"},
		{[]string{"osv"}, true, "   Running osv…"},
	} {
		if got := scanProgress(c.scanners, c.parallel); got != c.want {
			t.Errorf("scanProgress(%v, %v) = %q, want %q", c.scanners, c.parallel, got, c.want)
		}
	}
}
