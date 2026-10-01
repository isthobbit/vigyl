package offline

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRegistry serves OSV zips under /osv and Semgrep packs under /semgrep.
func fakeRegistry(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/osv/npm/all.zip", r.URL.Path == "/osv/PyPI/all.zip":
			w.Write([]byte("PK fake zip"))
		case r.URL.Path == "/semgrep/default":
			w.Write([]byte("rules:\n- id: x\n"))
		case r.URL.Path == "/semgrep/html-page":
			w.Write([]byte("<html>Not a rule pack</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	oldOSV, oldSemgrep := osvBaseURL, semgrepBaseURL
	osvBaseURL, semgrepBaseURL = srv.URL+"/osv", srv.URL+"/semgrep"
	t.Cleanup(func() { osvBaseURL, semgrepBaseURL = oldOSV, oldSemgrep })
}

func TestSync_DownloadsAndRecordsManifest(t *testing.T) {
	fakeRegistry(t)
	p := Paths{Root: t.TempDir()}

	err := Sync(context.Background(), p, SyncOptions{
		Sources:      []string{SourceOSV, SourceSemgrep},
		Ecosystems:   []string{"npm", "PyPI"},
		SemgrepPacks: []string{"p/default"},
	}, io.Discard)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := p.OSVReady(); err != nil {
		t.Error(err)
	}
	if got := p.SemgrepPacks(); len(got) != 1 || got[0] != "default" {
		t.Errorf("semgrep packs: %v", got)
	}

	m, err := p.ReadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.OSV == nil || len(m.OSV.Items) != 2 || m.Semgrep == nil {
		t.Fatalf("manifest not recorded: %+v", m)
	}
	if m.Trivy != nil {
		t.Errorf("trivy was not requested but appears in manifest")
	}

	rows, _ := p.Status(time.Now())
	for _, r := range rows {
		if r.Source != SourceTrivy && (!r.Ready || r.Stale) {
			t.Errorf("%s should be ready and fresh: %+v", r.Source, r)
		}
	}
	rows, _ = p.Status(time.Now().Add(StaleAfter + time.Hour))
	for _, r := range rows {
		if r.Ready && !r.Stale {
			t.Errorf("%s should be stale after %s", r.Source, StaleAfter)
		}
	}
}

func TestSync_PartialFailureKeepsGoodData(t *testing.T) {
	fakeRegistry(t)
	p := Paths{Root: t.TempDir()}

	err := Sync(context.Background(), p, SyncOptions{
		Sources:      []string{SourceOSV, SourceSemgrep},
		Ecosystems:   []string{"npm", "NoSuchEcosystem"},
		SemgrepPacks: []string{"default", "html-page"},
	}, io.Discard)
	if err == nil {
		t.Fatal("expected errors for the missing ecosystem and the HTML response")
	}
	for _, want := range []string{"NoSuchEcosystem", "not a Semgrep rules file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
	if _, statErr := os.Stat(filepath.Join(p.SemgrepRules(), "html-page.yml")); statErr == nil {
		t.Error("an HTML error page was saved as a rule pack")
	}
	if got := p.OSVEcosystems(); len(got) != 1 || got[0] != "npm" {
		t.Errorf("good ecosystem should still be saved: %v", got)
	}
}

func TestSync_RejectsUnsafeNames(t *testing.T) {
	fakeRegistry(t)
	p := Paths{Root: t.TempDir()}
	err := Sync(context.Background(), p, SyncOptions{
		Sources:    []string{SourceOSV},
		Ecosystems: []string{"../../etc"},
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "invalid ecosystem name") {
		t.Fatalf("expected invalid name error, got %v", err)
	}
}
