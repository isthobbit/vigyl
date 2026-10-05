// Package offline manages the local data jensec needs to scan with zero
// network access: the Trivy vulnerability DB, OSV ecosystem databases and
// Semgrep rule packs.
//
// Layout under the offline directory (default ~/.vigyl/offline):
//
//	trivy/                         Trivy --cache-dir (db/trivy.db, java-db/)
//	osv/osv-scanner/<eco>/all.zip  OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY
//	semgrep-rules/<pack>.yml       Semgrep rule packs
//	manifest.json                  what was synced and when
package offline

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// StaleAfter is the age at which offline data is reported as stale.
// Old vulnerability data silently misses new CVEs, so we warn early.
const StaleAfter = 7 * 24 * time.Hour

const (
	trivyDir     = "trivy"
	osvDir       = "osv"
	semgrepDir   = "semgrep-rules"
	manifestName = "manifest.json"
)

// Paths resolves file locations inside an offline directory.
type Paths struct {
	Root string
}

// DefaultDir returns ~/.vigyl/offline.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not find home directory: %w", err)
	}
	return filepath.Join(home, ".vigyl", "offline"), nil
}

// Resolve returns Paths for dir, falling back to DefaultDir when dir is empty.
func Resolve(dir string) (Paths, error) {
	if dir == "" {
		d, err := DefaultDir()
		if err != nil {
			return Paths{}, err
		}
		dir = d
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Paths{}, fmt.Errorf("could not resolve offline dir: %w", err)
	}
	return Paths{Root: abs}, nil
}

// TrivyCache is the directory passed to trivy --cache-dir.
func (p Paths) TrivyCache() string { return filepath.Join(p.Root, trivyDir) }

// OSVCache is the value for OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY.
// osv-scanner appends osv-scanner/<ecosystem>/all.zip to it.
func (p Paths) OSVCache() string { return filepath.Join(p.Root, osvDir) }

// OSVEcosystemZip is where osv-scanner looks for an ecosystem's database.
func (p Paths) OSVEcosystemZip(ecosystem string) string {
	return filepath.Join(p.OSVCache(), "osv-scanner", ecosystem, "all.zip")
}

// SemgrepRules is the directory passed to semgrep --config.
func (p Paths) SemgrepRules() string { return filepath.Join(p.Root, semgrepDir) }

// Manifest is the path of manifest.json.
func (p Paths) Manifest() string { return filepath.Join(p.Root, manifestName) }

// MissingError reports that a scanner has no offline data to work with.
type MissingError struct {
	Scanner string
	Path    string
}

func (e *MissingError) Error() string {
	return fmt.Sprintf("%s: no offline data at %s — run 'jensec offline sync' on a connected machine (or 'jensec offline import')", e.Scanner, e.Path)
}

// TrivyReady returns a *MissingError when the Trivy DB has not been synced.
func (p Paths) TrivyReady() error {
	db := filepath.Join(p.TrivyCache(), "db", "trivy.db")
	if !fileExists(db) {
		return &MissingError{Scanner: "trivy", Path: db}
	}
	return nil
}

// OSVReady returns a *MissingError when no OSV ecosystem database exists.
func (p Paths) OSVReady() error {
	if len(p.OSVEcosystems()) == 0 {
		return &MissingError{Scanner: "osv-scanner", Path: filepath.Join(p.OSVCache(), "osv-scanner")}
	}
	return nil
}

// OSVEcosystems lists the ecosystems that have a downloaded database.
func (p Paths) OSVEcosystems() []string {
	matches, _ := filepath.Glob(filepath.Join(p.OSVCache(), "osv-scanner", "*", "all.zip"))
	var ecos []string
	for _, m := range matches {
		ecos = append(ecos, filepath.Base(filepath.Dir(m)))
	}
	return ecos
}

// SemgrepReady returns a *MissingError when no rule pack has been synced.
func (p Paths) SemgrepReady() error {
	if len(p.SemgrepPacks()) == 0 {
		return &MissingError{Scanner: "semgrep", Path: p.SemgrepRules()}
	}
	return nil
}

// SemgrepPacks lists the synced rule pack files (without extension).
func (p Paths) SemgrepPacks() []string {
	matches, _ := filepath.Glob(filepath.Join(p.SemgrepRules(), "*.yml"))
	var packs []string
	for _, m := range matches {
		name := filepath.Base(m)
		packs = append(packs, name[:len(name)-len(".yml")])
	}
	return packs
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
