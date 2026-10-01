package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// legacyDirName is where builds before the ~/.vigyl move kept their files.
const legacyDirName = ".kinga"

// legacyFiles are moved from ~/.kinga to ~/.vigyl. SQLite side files are
// included so a database left mid-transaction moves intact.
var legacyFiles = []string{"jensec.db", "jensec.db-wal", "jensec.db-shm", "config.yaml"}

// LegacyMigration reports what MigrateLegacyDir did.
type LegacyMigration struct {
	// Moved lists files moved into ~/.vigyl, as "old -> new".
	Moved []string
	// Conflicts lists files present in both directories; the ~/.vigyl copy
	// is used and the ~/.kinga one is left alone.
	Conflicts []string
	// MovedConfig is true when config.yaml was moved, so its settings now
	// apply where previously they were ignored.
	MovedConfig bool
}

// MigrateLegacyDir moves jensec's history database and config from ~/.kinga
// to ~/.vigyl. A file is only moved when ~/.vigyl does not already have one,
// so nothing is ever overwritten. The legacy directory is removed if it ends
// up empty.
func MigrateLegacyDir() (*LegacyMigration, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not find home directory: %w", err)
	}
	oldDir := filepath.Join(home, legacyDirName)
	newDir := filepath.Join(home, ".vigyl")

	if info, err := os.Stat(oldDir); err != nil || !info.IsDir() {
		return &LegacyMigration{}, nil
	}

	m := &LegacyMigration{}
	for _, name := range legacyFiles {
		src := filepath.Join(oldDir, name)
		dst := filepath.Join(newDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if _, err := os.Stat(dst); err == nil {
			m.Conflicts = append(m.Conflicts, src)
			continue
		}
		if err := os.MkdirAll(newDir, 0o755); err != nil {
			return m, err
		}
		if err := os.Rename(src, dst); err != nil {
			return m, fmt.Errorf("could not move %s to %s: %w", src, dst, err)
		}
		m.Moved = append(m.Moved, src+" -> "+dst)
		if name == "config.yaml" {
			m.MovedConfig = true
		}
	}

	// os.Remove fails on a non-empty directory, so any other files the user
	// keeps there stay put.
	_ = os.Remove(oldDir)
	return m, nil
}
