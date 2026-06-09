// Package installer handles detection and guided installation of the external
// tools that jensec depends on: gitleaks and semgrep.
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
	Gitleaks Tool = "gitleaks"
	Semgrep  Tool = "semgrep"
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

// EnsureAll checks both gitleaks and semgrep. For each missing tool it calls
// Prompt. It returns two booleans: whether gitleaks and semgrep are available
// after the prompts (either pre-existing or freshly installed).
func EnsureAll(noColor bool) (gitleaksOK, semgrepOK bool) {
	gitleaksOK = IsInstalled(Gitleaks)
	semgrepOK = IsInstalled(Semgrep)

	if !gitleaksOK {
		ok, _ := Prompt(Gitleaks, noColor)
		gitleaksOK = ok
	}
	if !semgrepOK {
		ok, _ := Prompt(Semgrep, noColor)
		semgrepOK = ok
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
		// Prefer pip so the version matches the macOS brew formula;
		// both work but pip is the canonical install path per semgrep docs.
		return pip("semgrep")
	case "linux":
		return pip("semgrep")
	case "windows":
		return pip("semgrep")
	default:
		return unsupported("semgrep", "https://semgrep.dev/docs/getting-started")
	}
}

// installGitleaksLinux tries, in order: brew (if present), apt, dnf, pacman,
// then falls back to the GitHub release download.
func installGitleaksLinux() error {
	if hasBin("brew") {
		return brew("gitleaks")
	}
	if hasBin("apt-get") {
		// gitleaks is not in the default apt repos; use the GitHub release.
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
	// Official one-liner from the gitleaks README.
	script := `curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b /usr/local/bin`
	return run("sh", "-c", script)
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

func brew(pkg string) error {
	fmt.Fprintf(os.Stderr, "   → Running: brew install %s\n", pkg)
	return run("brew", "install", pkg)
}

func pip(pkg string) error {
	// Prefer pip3, fall back to pip.
	pipBin := "pip3"
	if !hasBin("pip3") {
		pipBin = "pip"
	}
	fmt.Fprintf(os.Stderr, "   → Running: %s install %s\n", pipBin, pkg)
	return run(pipBin, "install", pkg)
}

func winget(id string) error {
	fmt.Fprintf(os.Stderr, "   → Running: winget install %s\n", id)
	// --accept-source-agreements and --accept-package-agreements suppress the
	// interactive Microsoft Store prompts that winget emits when called from
	// inside another process — without them the install fails with 0x8a150042.
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
		return false // EOF / no TTY → treat as "no"
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
