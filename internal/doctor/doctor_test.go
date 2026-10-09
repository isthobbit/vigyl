package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeEnv simulates a machine: installed maps tool name to its --version
// output; offPath maps tool name to a path found outside PATH.
func fakeEnv(goos string, installed, offPath map[string]string) Env {
	return Env{
		GOOS: goos,
		LookPath: func(name string) (string, error) {
			if _, ok := installed[name]; ok {
				return "/bin/" + name, nil
			}
			return "", errors.New("not found")
		},
		Output: func(path string, args ...string) ([]byte, error) {
			return []byte(installed[filepath.Base(path)]), nil
		},
		Getenv: func(key string) string {
			if key == "LOCALAPPDATA" {
				return `C:\Users\me\AppData\Local`
			}
			return ""
		},
		Glob: func(pattern string) ([]string, error) {
			for name, p := range offPath {
				if strings.HasSuffix(pattern, name+".exe") && strings.Contains(pattern, "WinGet") {
					return []string{p}, nil
				}
			}
			return nil, nil
		},
	}
}

// Real version output captured from each scanner.
var current = map[string]string{
	"gitleaks":    "8.30.1\n",
	"semgrep":     "1.165.0\n",
	"trivy":       "Version: 0.72.0\nVulnerability DB:\n  Version: 2\n",
	"osv-scanner": "osv-scanner version: 2.4.0\nosv-scalibr version: 0.4.5\ncommit: b56b519\n",
}

func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	// Settings from the caller's environment would point at real data.
	for _, key := range []string{"VIGYL_STORAGE_DB_PATH", "VIGYL_STORAGE_OFFLINE_DIR", "VIGYL_SCAN_OFFLINE"} {
		t.Setenv(key, "")
	}
	// Keep the working directory free of a stray config.yaml.
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(wd) })
}

func find(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q", name)
	return Check{}
}

func TestRun_HealthyMachine(t *testing.T) {
	isolate(t)
	checks := Run(Options{Env: fakeEnv("linux", current, nil), Now: time.Now()})
	if fails, warns := Summary(checks); fails != 0 || warns != 0 {
		t.Fatalf("expected a clean report, got %d fails, %d warns: %+v", fails, warns, checks)
	}
	if v := find(t, checks, "osv-scanner").Version; v != "2.4.0" {
		t.Errorf("osv-scanner version parsed as %q", v)
	}
	if c := find(t, checks, "history"); c.Status != Info {
		t.Errorf("history with no database should be info, got %v: %s", c.Status, c.Detail)
	}
}

func TestRun_MissingToolGetsInstallFix(t *testing.T) {
	isolate(t)
	installed := map[string]string{"gitleaks": "8.30.1", "semgrep": "1.165.0", "osv-scanner": "osv-scanner version: 2.4.0"}
	c := find(t, Run(Options{Env: fakeEnv("windows", installed, nil), Now: time.Now()}), "trivy")
	if c.Status != Fail || !strings.Contains(c.Fix, "winget install AquaSecurity.Trivy") {
		t.Errorf("expected fail with winget fix, got %+v", c)
	}
}

func TestRun_WindowsToolOffPath(t *testing.T) {
	isolate(t)
	installed := map[string]string{"gitleaks": "8.30.1", "semgrep": "1.165.0", "osv-scanner": "osv-scanner version: 2.4.0"}
	found := `C:\Users\me\AppData\Local\Microsoft\WinGet\Packages\AquaSecurity.Trivy_x\trivy.exe`
	c := find(t, Run(Options{Env: fakeEnv("windows", installed, map[string]string{"trivy": found}), Now: time.Now()}), "trivy")
	if c.Status != Fail || !strings.Contains(c.Detail, "not on PATH") || !strings.Contains(c.Fix, filepath.Dir(found)) {
		t.Errorf("expected PATH fix pointing at the install dir, got %+v", c)
	}
}

func TestRun_OffPathLookupIsWindowsOnly(t *testing.T) {
	isolate(t)
	installed := map[string]string{"gitleaks": "8.30.1", "semgrep": "1.165.0", "osv-scanner": "osv-scanner version: 2.4.0"}
	c := find(t, Run(Options{Env: fakeEnv("linux", installed, map[string]string{"trivy": "/x/trivy.exe"}), Now: time.Now()}), "trivy")
	if c.Detail != "not installed" {
		t.Errorf("non-Windows should report not installed, got %+v", c)
	}
}

func TestRun_VersionThresholds(t *testing.T) {
	isolate(t)
	cases := []struct {
		name      string
		tool      string
		version   string
		offline   bool
		want      Status
		wantInMsg string
	}{
		{"older than tested", "trivy", "Version: 0.60.0", false, Warn, "tested version 0.72.0"},
		{"below hard minimum", "gitleaks", "7.6.1", false, Fail, "needs 8.0.0"},
		{"osv v1 online is only a warning", "osv-scanner", "osv-scanner version: 1.9.2", false, Warn, "offline mode needs 2.0.0"},
		{"osv v1 offline fails", "osv-scanner", "osv-scanner version: 1.9.2", true, Fail, "offline mode needs 2.0.0"},
		{"newer than tested", "semgrep", "1.200.0", false, OK, ""},
		{"unreadable version", "semgrep", "", false, Warn, "could not read its version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installed := map[string]string{}
			for k, v := range current {
				installed[k] = v
			}
			installed[tc.tool] = tc.version
			c := find(t, Run(Options{Env: fakeEnv("linux", installed, nil), Offline: tc.offline, Now: time.Now()}), tc.tool)
			if c.Status != tc.want || !strings.Contains(c.Detail, tc.wantInMsg) {
				t.Errorf("got %v %q, want %v containing %q", c.Status, c.Detail, tc.want, tc.wantInMsg)
			}
		})
	}
}

func TestRun_OfflineData(t *testing.T) {
	isolate(t)
	env := fakeEnv("linux", current, nil)

	// Offline rows share names with scanners, so select them by group.
	var offlineRows []Check
	for _, ch := range Run(Options{Env: env, Now: time.Now()}) {
		if ch.Group == GroupOffline {
			offlineRows = append(offlineRows, ch)
		}
	}
	for _, r := range offlineRows {
		if r.Status != Info {
			t.Errorf("unsynced data without --offline should be info, got %+v", r)
		}
	}

	for _, ch := range Run(Options{Env: env, Offline: true, Now: time.Now()}) {
		if ch.Group == GroupOffline && ch.Status != Fail {
			t.Errorf("unsynced data with --offline should fail, got %+v", ch)
		}
	}
}

func TestRun_BrokenConfig(t *testing.T) {
	isolate(t)
	bad := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(bad, []byte("scan:\n  fail_on: sometimes\n"), 0o644)

	c := find(t, Run(Options{Env: fakeEnv("linux", current, nil), ConfigFile: bad, Now: time.Now()}), "config")
	if c.Status != Fail || !strings.Contains(c.Detail, "sometimes") || c.Path != bad {
		t.Errorf("expected config failure naming the bad value and file, got %+v", c)
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.2.3", "1.2.4", true},
		{"1.10.0", "1.9.0", false},
		{"2.0.0", "2.0.0", false},
		{"0.9.9", "1.0.0", true},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
