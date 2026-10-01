package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
)

// meerkat is jensec's mascot: a meerkat standing sentry, keeping watch for
// the group — the vigil in "vigyl". Each line is padded to the same width so
// the text column lines up.
var meerkat = []string{
	`  .-"""-.  `,
	` /  o o  \ `,
	` \   v   / `,
	`  '.___.'  `,
	`  /     \  `,
	` /|     |\ `,
	`(_|     |_)`,
	`  |  |  |  `,
	` _|  |  |_ `,
	`(___/ \___)`,
}

// bannerText sits to the right of the meerkat, keyed by line index.
var bannerText = map[int]struct{ code, text string }{
	1: {bold, "jensec · by vigyl"},
	2: {"", "local-first DevSecOps scanner"},
	4: {"", "secrets · SAST · dependencies"},
	5: {"", "→ one prioritised risk score"},
	7: {dim, "your code never leaves your machine"},
}

const dim = "\033[2m"

// Banner returns the meerkat banner. With noColor it is plain text, which is
// also what `jensec --help` embeds.
func Banner(noColor bool) string {
	var b strings.Builder
	for i, line := range meerkat {
		t, hasText := bannerText[i]
		if !hasText {
			line = strings.TrimRight(line, " ")
		}
		b.WriteString("    ")
		b.WriteString(colorize(noColor, yellow, line))
		if hasText {
			b.WriteString("    ")
			if t.code == "" {
				b.WriteString(t.text)
			} else {
				b.WriteString(colorize(noColor, t.code, t.text))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// IsTerminal reports whether f is an interactive terminal, including the
// Cygwin/MSYS ptys used by Git Bash on Windows.
func IsTerminal(f *os.File) bool {
	fd := f.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// PrintBanner writes the banner to w only when w is an interactive terminal,
// so piped output, CI logs and redirected files stay free of it.
func PrintBanner(w *os.File, noColor bool) {
	if IsTerminal(w) {
		fmt.Fprintln(w)
		io.WriteString(w, Banner(noColor))
		fmt.Fprintln(w)
	}
}
