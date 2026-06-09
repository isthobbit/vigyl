package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/isthobbit/kinga/internal/config"
)

// ── Defaults ──────────────────────────────────────────────────────────────────

func TestDefaults_FailOnIsHigh(t *testing.T) {
	d := config.Defaults()
	if d.Scan.FailOn != "high" {
		t.Errorf("expected default fail_on=high, got %q", d.Scan.FailOn)
	}
}

func TestDefaults_MaxHistoryPositive(t *testing.T) {
	d := config.Defaults()
	if d.Storage.MaxHistory <= 0 {
		t.Errorf("expected positive max_history, got %d", d.Storage.MaxHistory)
	}
}

func TestDefaults_SemgrepRulesIsAuto(t *testing.T) {
	d := config.Defaults()
	if d.Scan.SemgrepRules != "auto" {
		t.Errorf("expected semgrep_rules=auto, got %q", d.Scan.SemgrepRules)
	}
}

// ── Load ─────────────────────────────────────────────────────────────────────

func TestLoad_NoConfigFile_ReturnsDefaults(t *testing.T) {
	// Point at a directory with no config file — should succeed with defaults.
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load() with no config file returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	d := config.Defaults()
	if cfg.Scan.FailOn != d.Scan.FailOn {
		t.Errorf("expected fail_on=%q, got %q", d.Scan.FailOn, cfg.Scan.FailOn)
	}
}

func TestLoad_ExplicitConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := "scan:\n  fail_on: medium\n  semgrep_rules: p/owasp-top-ten\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Scan.FailOn != "medium" {
		t.Errorf("expected fail_on=medium, got %q", cfg.Scan.FailOn)
	}
	if cfg.Scan.SemgrepRules != "p/owasp-top-ten" {
		t.Errorf("expected semgrep_rules=p/owasp-top-ten, got %q", cfg.Scan.SemgrepRules)
	}
}

func TestLoad_InvalidFailOn_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("scan:\n  fail_on: banana\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid fail_on value, got nil")
	}
}

func TestLoad_EnvVarOverridesFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("scan:\n  fail_on: high\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KINGA_SCAN_FAIL_ON", "critical")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Scan.FailOn != "critical" {
		t.Errorf("expected env var to override config file: got %q", cfg.Scan.FailOn)
	}
}

// ── Severity threshold ────────────────────────────────────────────────────────

func TestMeetsSeverityThreshold(t *testing.T) {
	tests := []struct {
		found     string
		threshold string
		want      bool
	}{
		{"critical", "high", true},
		{"high", "high", true},
		{"medium", "high", false},
		{"low", "high", false},
		{"critical", "none", false},
		{"high", "none", false},
		{"medium", "medium", true},
		{"low", "critical", false},
	}

	for _, tc := range tests {
		got := config.MeetsSeverityThreshold(tc.found, tc.threshold)
		if got != tc.want {
			t.Errorf("MeetsSeverityThreshold(%q, %q) = %v, want %v",
				tc.found, tc.threshold, got, tc.want)
		}
	}
}

// ── Write ─────────────────────────────────────────────────────────────────────

func TestWrite_CreatesFileAndSetsKey(t *testing.T) {
	// Override home so Write() doesn't touch the real ~/.kinga directory.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := config.Write("scan.fail_on", "low"); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	cfgPath := filepath.Join(dir, ".kinga", "config.yaml")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if string(data) == "" {
		t.Error("config file is empty after Write()")
	}
}
