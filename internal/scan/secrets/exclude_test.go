package secrets_test

import (
	"crypto/rand"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/secrets"
)

// fakeToken returns a random string in GitHub PAT format. It is generated at
// run time so this file never contains anything that looks like a secret.
func fakeToken(t *testing.T) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 36)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return "ghp_" + string(b)
}

func writeSecret(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN="+fakeToken(t)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRun_ExcludePaths runs the real gitleaks binary to check that excluded
// paths are skipped and everything else is still scanned.
func TestRun_ExcludePaths(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}
	dir := t.TempDir()
	writeSecret(t, filepath.Join(dir, "app", "settings.env"))
	writeSecret(t, filepath.Join(dir, "fixtures", "sample.env"))
	writeSecret(t, filepath.Join(dir, "pkg", "token_test.go"))

	all, err := secrets.Run(dir, false, 0, nil)
	if err != nil {
		t.Fatalf("scan without exclusions: %v", err)
	}
	if len(all.Findings) != 3 {
		t.Fatalf("expected 3 findings without exclusions, got %d", len(all.Findings))
	}

	got, err := secrets.Run(dir, false, 0, []string{"fixtures/**", "**/*_test.go"})
	if err != nil {
		t.Fatalf("scan with exclusions: %v", err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("expected 1 finding with exclusions, got %d: %+v", len(got.Findings), got.Findings)
	}
	if filepath.Base(got.Findings[0].File) != "settings.env" {
		t.Errorf("wrong file left after exclusions: %s", got.Findings[0].File)
	}
}

// TestRun_ExcludePathsKeepsRepoConfig checks that a repo's own .gitleaks.toml
// still applies when jensec adds its exclusion config.
func TestRun_ExcludePathsKeepsRepoConfig(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}
	dir := t.TempDir()
	writeSecret(t, filepath.Join(dir, "app", "settings.env"))
	writeSecret(t, filepath.Join(dir, "docs", "example.env"))
	writeSecret(t, filepath.Join(dir, "fixtures", "sample.env"))
	repoCfg := "[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['''(^|[/\\\\])docs([/\\\\].*)?$''']\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitleaks.toml"), []byte(repoCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := secrets.Run(dir, false, 0, []string{"fixtures"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got.Findings) != 1 || filepath.Base(got.Findings[0].File) != "settings.env" {
		t.Fatalf("expected only app/settings.env (docs excluded by repo config, fixtures by jensec), got %+v", got.Findings)
	}
}
