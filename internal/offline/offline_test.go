package offline_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/offline"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReady_EmptyDirReportsEachScanner(t *testing.T) {
	p := offline.Paths{Root: t.TempDir()}
	checks := map[string]error{
		"trivy":       p.TrivyReady(),
		"osv-scanner": p.OSVReady(),
		"semgrep":     p.SemgrepReady(),
	}
	for scanner, err := range checks {
		var missing *offline.MissingError
		if !errors.As(err, &missing) {
			t.Fatalf("%s: expected *MissingError, got %v", scanner, err)
		}
		if missing.Scanner != scanner {
			t.Errorf("expected scanner %q, got %q", scanner, missing.Scanner)
		}
		if !strings.Contains(err.Error(), "jensec offline sync") {
			t.Errorf("%s: error should tell the user how to fix it: %v", scanner, err)
		}
	}
}

func TestReady_PopulatedDir(t *testing.T) {
	p := offline.Paths{Root: t.TempDir()}
	touch(t, filepath.Join(p.TrivyCache(), "db", "trivy.db"))
	touch(t, p.OSVEcosystemZip("npm"))
	touch(t, p.OSVEcosystemZip("PyPI"))
	touch(t, filepath.Join(p.SemgrepRules(), "default.yml"))

	if err := p.TrivyReady(); err != nil {
		t.Errorf("trivy: %v", err)
	}
	if err := p.OSVReady(); err != nil {
		t.Errorf("osv: %v", err)
	}
	if err := p.SemgrepReady(); err != nil {
		t.Errorf("semgrep: %v", err)
	}
	if got := p.OSVEcosystems(); len(got) != 2 {
		t.Errorf("expected 2 ecosystems, got %v", got)
	}
	if got := p.SemgrepPacks(); len(got) != 1 || got[0] != "default" {
		t.Errorf("expected [default], got %v", got)
	}
}

func TestResolve_DefaultsUnderHome(t *testing.T) {
	p, err := offline.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(p.Root), ".vigyl/offline") {
		t.Errorf("unexpected default dir %q", p.Root)
	}
}
