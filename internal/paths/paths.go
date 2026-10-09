// Package paths normalises the file paths scanners report.
//
// Each scanner reports paths its own way: gitleaks and OSV-Scanner give
// absolute paths with forward slashes, semgrep gives native ones (backslashes
// on Windows) and Trivy gives paths relative to the scan root. Findings about
// the same file must compare equal, so everything is converted to one form:
// slash-separated and relative to the scan root.
package paths

import (
	"path/filepath"
	"strings"
)

// Rel converts p to a slash-separated path relative to root. Relative paths
// are taken to be relative to root already. A path outside root is returned
// absolute, in slash form.
func Rel(root, p string) string {
	if p == "" {
		return ""
	}
	native := filepath.FromSlash(p)
	if !filepath.IsAbs(native) {
		return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(native)), "./")
	}
	rel, err := filepath.Rel(root, native)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(filepath.Clean(native))
	}
	return filepath.ToSlash(rel)
}
