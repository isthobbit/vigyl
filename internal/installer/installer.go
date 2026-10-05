// Package installer handles detection and guided installation of the external
// tools that jensec depends on: gitleaks, semgrep, trivy, and osv-scanner.
//
// When a tool is missing, the caller can invoke Prompt to ask the user
// interactively whether they want jensec to install it. If the user agrees,
// Install runs the appropriate package-manager command for the current OS.
//
// Supported install paths:
//   - macOS:         Homebrew (brew install)
//   - Linux (apt):   apt-get  (gitleaks via GitHub release, semgrep via pip)
//   - Linux (dnf):   dnf install
//   - Linux (pacman):pacman -S
//   - Windows:       winget install
//   - fallback:      prints the manual install URL and exits gracefully
package installer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Tool identifies a dependency that jensec can install.
type Tool string

const (
	Gitleaks   Tool = "gitleaks"
	Semgrep    Tool = "semgrep"
	Trivy      Tool = "trivy"
	OSVScanner Tool = "osv-scanner"
)

// meta holds display name, install instructions per platform, and a fallback URL.
type meta struct {
	DisplayName string
	ManualURL   string
	// installFn is called when the user agrees to install.
	// It should print what it's doing and return any error.
	installFn func() error
}

// toolMeta returns the install metadata for a given tool.
func toolMeta(t Tool) meta {
	switch t {
	case Gitleaks:
		return meta{
			DisplayName: "Gitleaks (secrets scanner)",
			ManualURL:   "https://github.com/gitleaks/gitleaks#installing",
			installFn:   installGitleaks,
		}
	case Semgrep:
		return meta{
			DisplayName: "Semgrep (SAST scanner)",
			ManualURL:   "https://semgrep.dev/docs/getting-started",
			installFn:   installSemgrep,
		}
	case Trivy:
		return meta{
			DisplayName: "Trivy (dependency vulnerability scanner)",
			ManualURL:   "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
			installFn:   installTrivy,
		}
	case OSVScanner:
		return meta{
			DisplayName: "OSV-Scanner (dependency vulnerability scanner)",
			ManualURL:   "https://google.github.io/osv-scanner/installation/",
			installFn:   installOSVScanner,
		}
	default:
		return meta{DisplayName: string(t)}
	}
}

// IsInstalled reports whether the tool binary is available in PATH.
func IsInstalled(t Tool) bool {
	_, err := exec.LookPath(string(t))
	return err == nil
}

// Prompt asks the user interactively whether to install the given tool.
// It returns true if the user confirmed and the install succeeded.
// It returns false (without error) if the user declined.
// It returns an error if the install was attempted but failed.
//
// noColor disables ANSI codes in the prompt output.
func Prompt(t Tool, noColor bool) (installed bool, err error) {
	m := toolMeta(t)

	warn := color(noColor, "\033[33m", "WARNING: "+m.DisplayName+" is not installed.")
	fmt.Fprintln(os.Stderr, warn)
	fmt.Fprintf(os.Stderr, "   jensec can install it for you now.\n\n")
	fmt.Fprintf(os.Stderr, "   Install %s? [Y/n]: ", m.DisplayName)

	if !readYes() {
		fmt.Fprintln(os.Stderr, "   Skipping. You can install it manually:")
		fmt.Fprintf(os.Stderr, "   %s\n\n", m.ManualURL)
		return false, nil
	}

	fmt.Fprintln(os.Stderr)
	if err := m.installFn(); err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR: Install failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "   Install manually: %s\n\n", m.ManualURL)
		return false, err
	}

	// Verify the binary is now on PATH.
	if !IsInstalled(t) {
		fmt.Fprintf(os.Stderr, "\nWARNING: Install appeared to succeed but %q is still not in PATH.\n", string(t))
		fmt.Fprintf(os.Stderr, "   You may need to open a new terminal, then run jensec again.\n\n")
		return false, fmt.Errorf("%s installed but not found in PATH", string(t))
	}

	fmt.Fprintf(os.Stderr, "\n%s installed successfully.\n\n", m.DisplayName)
	return true, nil
}

// Detect reports which of the four scanners are on PATH without prompting or
// installing anything. Offline scans use it so jensec never reaches for the
// network to fetch a missing tool.
func Detect() (gitleaksOK, semgrepOK, trivyOK, osvOK bool) {
	return IsInstalled(Gitleaks), IsInstalled(Semgrep), IsInstalled(Trivy), IsInstalled(OSVScanner)
}

// EnsureAll checks all four scanners. For each missing tool it calls Prompt.
// It returns four booleans: whether gitleaks, semgrep, trivy, and osv-scanner
// are available after the prompts (either pre-existing or freshly installed).
func EnsureAll(noColor bool) (gitleaksOK, semgrepOK, trivyOK, osvOK bool) {
	gitleaksOK = IsInstalled(Gitleaks)
	semgrepOK = IsInstalled(Semgrep)
	trivyOK = IsInstalled(Trivy)
	osvOK = IsInstalled(OSVScanner)

	if !gitleaksOK {
		ok, _ := Prompt(Gitleaks, noColor)
		gitleaksOK = ok
	}
	if !semgrepOK {
		ok, _ := Prompt(Semgrep, noColor)
		semgrepOK = ok
	}
	if !trivyOK {
		ok, _ := Prompt(Trivy, noColor)
		trivyOK = ok
	}
	if !osvOK {
		ok, _ := Prompt(OSVScanner, noColor)
		osvOK = ok
	}
	return
}

// ── Install functions ─────────────────────────────────────────────────────────

func installGitleaks() error {
	switch runtime.GOOS {
	case "darwin":
		return brew("gitleaks")
	case "linux":
		return installGitleaksLinux()
	case "windows":
		return winget("Gitleaks.Gitleaks")
	default:
		return unsupported("gitleaks", "https://github.com/gitleaks/gitleaks#installing")
	}
}

func installSemgrep() error {
	switch runtime.GOOS {
	case "darwin":
		return pip("semgrep")
	case "linux":
		return pip("semgrep")
	case "windows":
		return pip("semgrep")
	default:
		return unsupported("semgrep", "https://semgrep.dev/docs/getting-started")
	}
}

func installTrivy() error {
	switch runtime.GOOS {
	case "darwin":
		return brew("trivy")
	case "linux":
		return installTrivyLinux()
	case "windows":
		return winget("AquaSecurity.Trivy")
	default:
		return unsupported("trivy", "https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
	}
}

func installOSVScanner() error {
	switch runtime.GOOS {
	case "darwin":
		return brew("osv-scanner")
	case "linux":
		return installOSVScannerLinux()
	case "windows":
		return installOSVScannerWindows()
	default:
		return unsupported("osv-scanner", "https://google.github.io/osv-scanner/installation/")
	}
}

// installGitleaksLinux tries, in order: brew (if present), apt, dnf, pacman,
// then falls back to the GitHub release download.
func installGitleaksLinux() error {
	if hasBin("brew") {
		return brew("gitleaks")
	}
	if hasBin("apt-get") {
		return installGitleaksViaGitHub()
	}
	if hasBin("dnf") {
		return run("sudo", "dnf", "install", "-y", "gitleaks")
	}
	if hasBin("pacman") {
		return run("sudo", "pacman", "-S", "--noconfirm", "gitleaks")
	}
	return installGitleaksViaGitHub()
}

// installGitleaksViaGitHub downloads and installs the latest gitleaks binary
// from GitHub Releases using the official install script.
func installGitleaksViaGitHub() error {
	fmt.Fprintln(os.Stderr, "   → Downloading gitleaks from GitHub Releases...")
	script := `curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b /usr/local/bin`
	return run("sh", "-c", script)
}

// installTrivyLinux installs Trivy on Linux using the official install script.
func installTrivyLinux() error {
	if hasBin("brew") {
		return brew("trivy")
	}
	if hasBin("apt-get") {
		return installTrivyViaScript()
	}
	if hasBin("dnf") {
		return installTrivyViaScript()
	}
	return installTrivyViaScript()
}

// installTrivyViaScript downloads and installs Trivy using the official script.
func installTrivyViaScript() error {
	fmt.Fprintln(os.Stderr, "   → Downloading Trivy from GitHub Releases...")
	script := `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`
	return run("sh", "-c", script)
}

// installOSVScannerLinux installs OSV-Scanner on Linux.
func installOSVScannerLinux() error {
	if hasBin("brew") {
		return brew("osv-scanner")
	}
	fmt.Fprintln(os.Stderr, "   → Downloading osv-scanner from GitHub Releases...")
	script := `curl -sSfL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner`
	return run("sh", "-c", script)
}

// installOSVScannerWindows installs OSV-Scanner on Windows via winget or direct download.
func installOSVScannerWindows() error {
	if hasBin("winget") {
		return winget("Google.OSVScanner")
	}
	return unsupported("osv-scanner", "https://google.github.io/osv-scanner/installation/")
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

func brew(pkg string) error {
	fmt.Fprintf(os.Stderr, "   → Running: brew install %s\n", pkg)
	return run("brew", "install", pkg)
}

func pip(pkg string) error {
	pipBin := "pip3"
	if !hasBin("pip3") {
		pipBin = "pip"
	}
	fmt.Fprintf(os.Stderr, "   → Running: %s install %s\n", pipBin, pkg)
	return run(pipBin, "install", pkg)
}

func winget(id string) error {
	fmt.Fprintf(os.Stderr, "   → Running: winget install %s\n", id)
	return run("winget", "install", id, "--accept-source-agreements", "--accept-package-agreements")
}

func unsupported(tool, url string) error {
	return fmt.Errorf(
		"automatic install of %s is not supported on %s — install manually: %s",
		tool, runtime.GOOS, url,
	)
}

// run executes a command with its output wired to the terminal so the user
// can see progress (package managers print their own status lines).
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...) //nolint // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Stdout = os.Stderr             // installer output goes to stderr, not stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func hasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// readYes reads a line from stdin and returns true for "y", "Y", or an empty
// line (i.e. the user just pressed Enter, accepting the default of Yes).
func readYes() bool {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false
	}
	input := strings.TrimSpace(scanner.Text())
	return input == "" || strings.EqualFold(input, "y") || strings.EqualFold(input, "yes")
}

func color(noColor bool, code, text string) string {
	if noColor {
		return text
	}
	return code + text + "\033[0m"
}

// ManualURL returns the install documentation link for a tool.
func ManualURL(t Tool) string {
	return toolMeta(t).ManualURL
}

// InstallHint returns the one-line command that installs a tool on goos, the
// same one jensec's install prompt would run, or "" when the install is
// distro-specific and only the manual URL applies.
func InstallHint(t Tool, goos string) string {
	if t == Semgrep {
		return "pip install semgrep"
	}
	switch goos {
	case "darwin":
		return "brew install " + string(t)
	case "windows":
		ids := map[Tool]string{
			Gitleaks:   "Gitleaks.Gitleaks",
			Trivy:      "AquaSecurity.Trivy",
			OSVScanner: "Google.OSVScanner",
		}
		return "winget install " + ids[t]
	}
	return ""
}
