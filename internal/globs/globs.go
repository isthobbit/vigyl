// Package globs converts scan.exclude_paths patterns into regular
// expressions, so every part of jensec interprets them the same way.
package globs

import (
	"path/filepath"
	"regexp"
	"strings"
)

// sep matches a path separator in either form, because scanners report
// native paths and Windows uses backslashes.
const sep = `[/\\]`

// ToRegex converts an exclude glob into a regex. The match may start at any
// directory boundary, and a pattern that names a directory also matches
// everything inside it:
//
//	fixtures/**     → anything under any fixtures/ directory
//	**/*_test.go    → any file ending in _test.go
//	vendor          → a file or directory named vendor, and its contents
func ToRegex(glob string) string {
	g := strings.Trim(filepath.ToSlash(glob), "/")
	var b strings.Builder
	b.WriteString(`(^|` + sep + `)`)
	for i := 0; i < len(g); i++ {
		switch c := g[i]; {
		case strings.HasPrefix(g[i:], "**/"):
			b.WriteString(`(.*` + sep + `)?`)
			i += 2
		case strings.HasPrefix(g[i:], "**"):
			b.WriteString(`.*`)
			i++
		case c == '*':
			b.WriteString(`[^/\\]*`)
		case c == '?':
			b.WriteString(`[^/\\]`)
		case c == '/':
			b.WriteString(sep)
		default:
			b.WriteString(quoteByte(c))
		}
	}
	b.WriteString(`(` + sep + `.*)?$`)
	return b.String()
}

func quoteByte(c byte) string {
	if strings.ContainsRune(`\.+()|[]{}^$`, rune(c)) {
		return `\` + string(c)
	}
	return string(c)
}

// Matcher reports whether a path matches any of a set of globs.
type Matcher []*regexp.Regexp

// Compile builds a Matcher; invalid patterns cannot occur because ToRegex
// quotes every literal character.
func Compile(patterns []string) Matcher {
	m := make(Matcher, 0, len(patterns))
	for _, p := range patterns {
		m = append(m, regexp.MustCompile(ToRegex(p)))
	}
	return m
}

// Match reports whether path matches any pattern.
func (m Matcher) Match(path string) bool {
	for _, re := range m {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
