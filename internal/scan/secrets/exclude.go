package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/isthobbit/vigyl/internal/globs"
)

// excludeConfig builds a gitleaks config that keeps the rules gitleaks would
// otherwise use and adds an allowlist for the excluded paths.
//
// Passing --config stops gitleaks from picking up GITLEAKS_CONFIG,
// GITLEAKS_CONFIG_TOML or <source>/.gitleaks.toml by itself, so whichever of
// those applies (in gitleaks' own order) is extended rather than replaced.
// The returned cleanup removes any temp files.
func excludeConfig(sourcePath string, excludePaths []string) (configPath string, cleanup func(), err error) {
	var temps []string
	cleanup = func() {
		for _, t := range temps {
			os.Remove(t)
		}
	}
	writeTemp := func(pattern, content string) (string, error) {
		f, err := os.CreateTemp("", pattern)
		if err != nil {
			return "", err
		}
		temps = append(temps, f.Name())
		if _, err := f.WriteString(content); err != nil {
			f.Close()
			return "", err
		}
		return f.Name(), f.Close()
	}

	base := ""
	switch {
	case os.Getenv("GITLEAKS_CONFIG") != "":
		base = os.Getenv("GITLEAKS_CONFIG")
	case os.Getenv("GITLEAKS_CONFIG_TOML") != "":
		if base, err = writeTemp("vigyl-gitleaks-base-*.toml", os.Getenv("GITLEAKS_CONFIG_TOML")); err != nil {
			cleanup()
			return "", nil, err
		}
	default:
		if repoCfg := filepath.Join(sourcePath, ".gitleaks.toml"); fileExists(repoCfg) {
			base = repoCfg
		}
	}

	var b strings.Builder
	b.WriteString("title = \"jensec scan.exclude_paths\"\n\n[extend]\n")
	if base != "" {
		fmt.Fprintf(&b, "path = '''%s'''\n", base)
	} else {
		b.WriteString("useDefault = true\n")
	}
	b.WriteString("\n[allowlist]\ndescription = \"jensec scan.exclude_paths\"\npaths = [\n")
	for _, p := range excludePaths {
		fmt.Fprintf(&b, "  '''%s''',\n", globs.ToRegex(p))
	}
	b.WriteString("]\n")

	configPath, err = writeTemp("vigyl-gitleaks-*.toml", b.String())
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return configPath, cleanup, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
