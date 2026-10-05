// Package doctor checks whether jensec can scan on this machine: scanner
// installs and versions, offline data, config and scan history. It only
// inspects; it never installs, downloads or writes anything.
package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/isthobbit/vigyl/internal/config"
	"github.com/isthobbit/vigyl/internal/installer"
	"github.com/isthobbit/vigyl/internal/offline"
	"github.com/isthobbit/vigyl/internal/store"
)

// Status is the outcome of one check.
type Status int

const (
	OK Status = iota
	Info
	Warn
	Fail
)

func (s Status) String() string {
	return [...]string{"ok", "info", "warn", "fail"}[s]
}

// MarshalJSON writes the status as its name.
func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Check is one line of the doctor report.
type Check struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// Groups, in report order.
const (
	GroupScanners = "Scanners"
	GroupOffline  = "Offline data"
	GroupSetup    = "Config & storage"
)

// Env is the machine doctor inspects. Tests replace it with a fake.
type Env struct {
	GOOS     string
	LookPath func(name string) (string, error)
	// Output runs a command and returns its stdout.
	Output func(name string, args ...string) ([]byte, error)
	Getenv func(key string) string
	Glob   func(pattern string) ([]string, error)
}

// SystemEnv inspects the real machine.
func SystemEnv() Env {
	return Env{
		GOOS:     runtime.GOOS,
		LookPath: exec.LookPath,
		Output: func(name string, args ...string) ([]byte, error) {
			cmd := exec.Command(name, args...) //nolint // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
			// Stop semgrep checking for updates over the network, and let
			// it read UTF-8 on Windows.
			cmd.Env = append(os.Environ(), "SEMGREP_ENABLE_VERSION_CHECK=0", "PYTHONUTF8=1")
			return cmd.Output()
		},
		Getenv: os.Getenv,
		Glob:   filepath.Glob,
	}
}

// Options configures a doctor run.
type Options struct {
	Env Env
	// ConfigFile is the --config flag value, if any.
	ConfigFile string
	// Offline makes missing offline data a failure rather than information.
	Offline bool
	// Now is used for data-age checks.
	Now time.Time
}

// tool describes a scanner and the versions jensec relies on.
type tool struct {
	t           installer.Tool
	versionArgs []string
	// min is the oldest version jensec works with at all ("" = no floor).
	min string
	// minOffline is the oldest version that supports offline mode.
	minOffline string
	// tested is the version pinned in CI; older ones are untested.
	tested string
}

var tools = []tool{
	{t: installer.Gitleaks, versionArgs: []string{"version"}, min: "8.0.0", tested: "8.30.1"},
	{t: installer.Semgrep, versionArgs: []string{"--version"}, tested: "1.165.0"},
	{t: installer.Trivy, versionArgs: []string{"--version"}, tested: "0.72.0"},
	{t: installer.OSVScanner, versionArgs: []string{"--version"}, minOffline: "2.0.0", tested: "2.4.0"},
}

// Run performs every check and returns them in report order. A config that
// fails to load is reported and defaults are used for the remaining checks.
func Run(opts Options) []Check {
	cfg, cfgCheck := checkConfig(opts.ConfigFile)
	offlineMode := opts.Offline || cfg.Scan.Offline

	var checks []Check
	for _, tl := range tools {
		checks = append(checks, checkTool(opts.Env, tl, offlineMode))
	}
	checks = append(checks, checkOffline(cfg, offlineMode, opts.Now)...)
	checks = append(checks, cfgCheck)
	checks = append(checks, checkHistory(cfg))
	checks = append(checks, checkLegacyDir()...)
	return checks
}

// Summary counts failures and warnings.
func Summary(checks []Check) (fails, warns int) {
	for _, c := range checks {
		switch c.Status {
		case Fail:
			fails++
		case Warn:
			warns++
		}
	}
	return fails, warns
}

// ── Scanners ─────────────────────────────────────────────────────────────────

func checkTool(env Env, tl tool, offlineMode bool) Check {
	name := string(tl.t)
	c := Check{Group: GroupScanners, Name: name}

	path, err := env.LookPath(name)
	if err != nil {
		c.Status = Fail
		if found := findOffPath(env, name); found != "" {
			c.Detail = "installed but not on PATH: " + found
			c.Fix = "add " + filepath.Dir(found) + " to your user PATH, then open a new terminal"
			return c
		}
		c.Detail = "not installed"
		c.Fix = installFix(tl.t, env.GOOS)
		return c
	}
	c.Path = path

	out, err := env.Output(path, tl.versionArgs...)
	c.Version = parseVersion(string(out))
	if err != nil || c.Version == "" {
		c.Status = Warn
		c.Detail = "could not read its version; it may be broken"
		c.Fix = "run '" + name + " " + strings.Join(tl.versionArgs, " ") + "' to see the error, or reinstall: " + installFix(tl.t, env.GOOS)
		return c
	}

	switch {
	case tl.min != "" && versionLess(c.Version, tl.min):
		c.Status = Fail
		c.Detail = "jensec needs " + tl.min + " or newer"
		c.Fix = "upgrade: " + installFix(tl.t, env.GOOS)
	case offlineMode && tl.minOffline != "" && versionLess(c.Version, tl.minOffline):
		c.Status = Fail
		c.Detail = "offline mode needs " + tl.minOffline + " or newer"
		c.Fix = "upgrade: " + installFix(tl.t, env.GOOS)
	case versionLess(c.Version, tl.tested):
		c.Status = Warn
		c.Detail = "older than the tested version " + tl.tested
		if tl.minOffline != "" && versionLess(c.Version, tl.minOffline) {
			c.Detail += "; offline mode needs " + tl.minOffline + " or newer"
		}
		c.Fix = "upgrade if you see problems: " + installFix(tl.t, env.GOOS)
	default:
		c.Status = OK
	}
	return c
}

func installFix(t installer.Tool, goos string) string {
	if hint := installer.InstallHint(t, goos); hint != "" {
		return hint + " (or see " + installer.ManualURL(t) + ")"
	}
	return "see " + installer.ManualURL(t)
}

// findOffPath looks where Windows package managers put tools that are often
// missing from PATH (see the README's winget note). It returns "" when the
// tool is not found there either.
func findOffPath(env Env, name string) string {
	if env.GOOS != "windows" {
		return ""
	}
	exe := name + ".exe"
	local, roaming := env.Getenv("LOCALAPPDATA"), env.Getenv("APPDATA")
	var patterns []string
	if local != "" {
		patterns = append(patterns,
			filepath.Join(local, "Microsoft", "WinGet", "Links", exe),
			filepath.Join(local, "Microsoft", "WinGet", "Packages", "*", exe),
			filepath.Join(local, "Microsoft", "WinGet", "Packages", "*", "*", exe),
			// pip installs from the Microsoft Store Python
			filepath.Join(local, "Packages", "PythonSoftwareFoundation.Python.*", "LocalCache", "local-packages", "Python*", "Scripts", exe),
			filepath.Join(local, "Programs", "Python", "Python*", "Scripts", exe),
		)
	}
	if roaming != "" {
		patterns = append(patterns, filepath.Join(roaming, "Python", "Python*", "Scripts", exe))
	}
	for _, p := range patterns {
		if matches, _ := env.Glob(p); len(matches) > 0 {
			return matches[0]
		}
	}
	return ""
}

var semverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// parseVersion returns the first x.y.z in a tool's version output. Each
// scanner prints its own version first ("8.30.1", "Version: 0.72.0",
// "osv-scanner version: 2.4.0"), ahead of any library versions.
func parseVersion(out string) string {
	return semverRe.FindString(out)
}

// versionLess reports whether a < b for x.y.z strings.
func versionLess(a, b string) bool {
	pa, pb := splitVersion(a), splitVersion(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func splitVersion(v string) [3]int {
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(part)
	}
	return out
}

// ── Offline data ─────────────────────────────────────────────────────────────

func checkOffline(cfg *config.Config, offlineMode bool, now time.Time) []Check {
	paths, err := offline.Resolve(cfg.Storage.OfflineDir)
	if err != nil {
		return []Check{{Group: GroupOffline, Name: "offline dir", Status: Warn, Detail: err.Error()}}
	}
	rows, err := paths.Status(now)
	if err != nil {
		return []Check{{Group: GroupOffline, Name: "manifest", Status: Warn, Path: paths.Manifest(), Detail: err.Error(),
			Fix: "run 'jensec offline sync' to rewrite it"}}
	}

	var checks []Check
	for _, r := range rows {
		c := Check{Group: GroupOffline, Name: r.Source, Path: paths.Root}
		switch {
		case !r.Ready && offlineMode:
			c.Status = Fail
			c.Detail = "not synced, and offline mode is on"
			c.Fix = "run 'jensec offline sync' (or 'jensec offline import' on an air-gapped machine)"
		case !r.Ready:
			c.Status = Info
			c.Detail = "not synced (only needed for --offline)"
		case r.Stale:
			c.Status = Warn
			c.Detail = "synced " + age(now, r.SyncedAt) + "; may miss recent vulnerabilities"
			c.Fix = "run 'jensec offline sync'"
		default:
			c.Status = OK
			c.Detail = "synced " + age(now, r.SyncedAt)
		}
		checks = append(checks, c)
	}
	return checks
}

func age(now, t time.Time) string {
	if t.IsZero() {
		return "at an unknown time"
	}
	d := now.Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// ── Config & storage ─────────────────────────────────────────────────────────

func checkConfig(cfgFile string) (*config.Config, Check) {
	c := Check{Group: GroupSetup, Name: "config", Path: config.Locate(cfgFile)}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		d := config.Defaults()
		c.Status = Fail
		c.Detail = err.Error() + " (scans fall back to built-in defaults)"
		c.Fix = "correct the value above in the config file, then run 'jensec doctor' again"
		return &d, c
	}
	c.Status = OK
	if c.Path == "" {
		c.Detail = "no config file; using defaults"
	}
	return cfg, c
}

func checkHistory(cfg *config.Config) Check {
	c := Check{Group: GroupSetup, Name: "history"}
	path := cfg.Storage.DBPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			c.Status = Fail
			c.Detail = err.Error()
			return c
		}
		path = p
	}
	c.Path = path

	if _, err := os.Stat(path); err == nil {
		n, err := store.CountScans(path)
		if err != nil {
			c.Status = Fail
			c.Detail = "cannot read scan history: " + err.Error()
			c.Fix = "check the file is a jensec database and not in use; move it aside to start fresh"
			return c
		}
		c.Status = OK
		c.Detail = fmt.Sprintf("%d scans recorded", n)
		return c
	}

	if err := writableDir(filepath.Dir(path)); err != nil {
		c.Status = Fail
		c.Detail = "cannot create scan history: " + err.Error()
		c.Fix = "make the directory writable or set storage.db_path"
		return c
	}
	c.Status = Info
	c.Detail = "no scans yet; created on first scan"
	return c
}

// writableDir checks that dir (or, if it does not exist yet, its nearest
// existing parent) accepts new files. The probe file is removed at once.
func writableDir(dir string) error {
	for {
		if info, err := os.Stat(dir); err == nil {
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", dir)
			}
			f, err := os.CreateTemp(dir, ".jensec-doctor-*")
			if err != nil {
				return err
			}
			name := f.Name()
			f.Close()
			return os.Remove(name)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("no existing parent directory for %s", dir)
		}
		dir = parent
	}
}

func checkLegacyDir() []Check {
	leftovers, err := config.LegacyLeftovers()
	if err != nil || len(leftovers) == 0 {
		return nil
	}
	return []Check{{
		Group:  GroupSetup,
		Name:   "~/.kinga",
		Status: Warn,
		Detail: "old files not moved because ~/.vigyl already has them: " + strings.Join(leftovers, ", "),
		Fix:    "compare them with ~/.vigyl, keep the one you want there, then delete ~/.kinga",
	}}
}
