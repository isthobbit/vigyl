package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBanner_PlainTextIsAlignedAndUncoloured(t *testing.T) {
	plain := Banner(true)
	if strings.Contains(plain, "\033[") {
		t.Fatal("noColor banner contains ANSI escape codes")
	}
	lines := strings.Split(strings.TrimRight(plain, "\n"), "\n")
	if len(lines) != len(meerkat) {
		t.Fatalf("expected %d lines, got %d", len(meerkat), len(lines))
	}
	// Every caption starts in the same column, right of the meerkat.
	col := -1
	for i, line := range lines {
		if strings.HasSuffix(line, " ") {
			t.Errorf("line %d has trailing whitespace: %q", i, line)
		}
		caption, ok := bannerText[i]
		if !ok {
			continue
		}
		at := strings.Index(line, caption.text)
		if col == -1 {
			col = at
		} else if at != col {
			t.Errorf("line %d caption starts at column %d, want %d", i, at, col)
		}
	}
	for _, want := range []string{"jensec · by vigyl", "local-first DevSecOps scanner"} {
		if !strings.Contains(plain, want) {
			t.Errorf("banner missing %q", want)
		}
	}
}

func TestBanner_ColouredMatchesPlainText(t *testing.T) {
	coloured := Banner(false)
	if !strings.Contains(coloured, "\033[") {
		t.Fatal("coloured banner has no ANSI codes")
	}
	stripped := coloured
	for _, code := range []string{yellow, bold, dim, reset} {
		stripped = strings.ReplaceAll(stripped, code, "")
	}
	if stripped != Banner(true) {
		t.Error("coloured banner differs from plain banner beyond colour codes")
	}
}

func TestPrintBanner_SkipsNonTerminals(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	PrintBanner(f, false)
	f.Close()
	data, _ := os.ReadFile(f.Name())
	if len(data) != 0 {
		t.Errorf("banner written to a file: %q", data)
	}
}
