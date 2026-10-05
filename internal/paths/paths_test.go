package paths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestRel(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	slashRoot := filepath.ToSlash(root)

	cases := map[string]string{
		"":                                  "",
		"app/db.py":                         "app/db.py",
		"./app/db.py":                       "app/db.py",
		filepath.Join(root, "app", "db.py"): "app/db.py",
		slashRoot + "/app/db.py":            "app/db.py",
		slashRoot + "/requirements.txt":     "requirements.txt",
	}
	if runtime.GOOS == "windows" {
		// semgrep reports backslashes, gitleaks forward slashes: same file.
		cases[root+`\app\db.py`] = "app/db.py"
	}
	for in, want := range cases {
		if got := Rel(root, in); got != want {
			t.Errorf("Rel(%q) = %q, want %q", in, got, want)
		}
	}

	outside := filepath.Join(filepath.Dir(root), "other", "x.py")
	if got := Rel(root, outside); got != filepath.ToSlash(outside) {
		t.Errorf("path outside root should stay absolute, got %q", got)
	}
}
