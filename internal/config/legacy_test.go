package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/isthobbit/vigyl/internal/config"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMigrateLegacyDir_MovesFilesAndRemovesEmptyDir(t *testing.T) {
	home := isolateHome(t)
	writeFile(t, filepath.Join(home, ".kinga", "jensec.db"), "history")
	writeFile(t, filepath.Join(home, ".kinga", "config.yaml"), "scan:\n  fail_on: low\n")

	m, err := config.MigrateLegacyDir()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Moved) != 2 || !m.MovedConfig || len(m.Conflicts) != 0 {
		t.Fatalf("unexpected result: %+v", m)
	}
	if got := readFile(t, filepath.Join(home, ".vigyl", "jensec.db")); got != "history" {
		t.Errorf("database content changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".kinga")); !os.IsNotExist(err) {
		t.Error("empty ~/.kinga should be removed")
	}

	// The moved config is now the one Load reads.
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.FailOn != "low" {
		t.Errorf("moved config not applied: fail_on=%q", cfg.Scan.FailOn)
	}
}

func TestMigrateLegacyDir_NeverOverwrites(t *testing.T) {
	home := isolateHome(t)
	writeFile(t, filepath.Join(home, ".kinga", "jensec.db"), "old")
	writeFile(t, filepath.Join(home, ".kinga", "notes.txt"), "user file")
	writeFile(t, filepath.Join(home, ".vigyl", "jensec.db"), "new")

	m, err := config.MigrateLegacyDir()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Moved) != 0 || len(m.Conflicts) != 1 {
		t.Fatalf("expected one conflict and no moves: %+v", m)
	}
	if got := readFile(t, filepath.Join(home, ".vigyl", "jensec.db")); got != "new" {
		t.Errorf("~/.vigyl database was overwritten: %q", got)
	}
	if got := readFile(t, filepath.Join(home, ".kinga", "jensec.db")); got != "old" {
		t.Errorf("~/.kinga database was changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".kinga", "notes.txt")); err != nil {
		t.Error("unrelated files in ~/.kinga must be left alone")
	}
}

func TestMigrateLegacyDir_NoLegacyDir(t *testing.T) {
	isolateHome(t)
	m, err := config.MigrateLegacyDir()
	if err != nil || len(m.Moved)+len(m.Conflicts) != 0 {
		t.Fatalf("expected no-op, got %+v, %v", m, err)
	}
}

func TestLoad_StorageDBPathFromEnv(t *testing.T) {
	isolateHome(t)
	t.Setenv("VIGYL_STORAGE_DB_PATH", "/tmp/custom.db")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.DBPath != "/tmp/custom.db" {
		t.Errorf("VIGYL_STORAGE_DB_PATH ignored: got %q", cfg.Storage.DBPath)
	}
}
