// Package imports records which packages each source file imports, so a
// vulnerable dependency can be linked to the files that actually use it.
//
// It understands Go, JavaScript/TypeScript and Python. For other ecosystems
// it reports that it cannot tell, never that a package is unused.
package imports

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/isthobbit/vigyl/internal/globs"
)

// Lang is a source language the index understands.
type Lang string

const (
	Go     Lang = "go"
	JS     Lang = "js"
	Python Lang = "python"
)

// maxFileSize skips generated or minified files that are too large to be
// hand-written source.
const maxFileSize = 1 << 20

// skipDirs are never source the user wrote.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
	"venv": true, "__pycache__": true, ".tox": true, "site-packages": true,
}

// Index maps each source file (slash-separated, relative to Root) to the
// module specifiers it imports.
type Index struct {
	Root  string
	files map[string]fileImports
}

type fileImports struct {
	lang    Lang
	modules []string
}

// Build walks root once and parses imports from every supported source
// file, skipping dependency directories and paths matching exclude.
func Build(root string, exclude globs.Matcher) (*Index, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	ix := &Index{Root: abs, files: map[string]fileImports{}}

	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		rel, _ := filepath.Rel(abs, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (skipDirs[d.Name()] || exclude.Match(rel)) {
				return filepath.SkipDir
			}
			return nil
		}
		lang := langOf(d.Name())
		if lang == "" || exclude.Match(rel) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if mods := parse(lang, src); len(mods) > 0 {
			ix.files[rel] = fileImports{lang: lang, modules: mods}
		}
		return nil
	})
	return ix, err
}

func langOf(name string) Lang {
	switch strings.ToLower(path.Ext(name)) {
	case ".go":
		return Go
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return JS
	case ".py":
		return Python
	}
	return ""
}

func parse(lang Lang, src []byte) []string {
	switch lang {
	case Go:
		return parseGo(src)
	case JS:
		return parseJS(string(src))
	case Python:
		return parsePython(string(src))
	}
	return nil
}

// Usage is the answer to "which files import this package?".
type Usage struct {
	// Known is false when the ecosystem is not supported, so nothing can be
	// said about whether the package is used.
	Known bool
	// Files are the importing files, slash-separated and relative to Root.
	Files []string
}

// Importers returns the files that import pkg. manifest is the dependency's
// manifest or lockfile path relative to Root (e.g. "services/api/go.mod");
// only files in that manifest's directory tree are considered, so in a
// monorepo a CVE in one service is not linked to another service's files.
func (ix *Index) Importers(ecosystem, pkg, manifest string) Usage {
	lang, match := matcherFor(ecosystem, pkg)
	if lang == "" {
		return Usage{}
	}
	scope := path.Dir(filepath.ToSlash(manifest))
	if manifest == "" || scope == "." {
		scope = ""
	}

	u := Usage{Known: true}
	for file, fi := range ix.files {
		if fi.lang != lang {
			continue
		}
		if scope != "" && !strings.HasPrefix(file, scope+"/") {
			continue
		}
		for _, m := range fi.modules {
			if match(m) {
				u.Files = append(u.Files, file)
				break
			}
		}
	}
	sort.Strings(u.Files)
	return u
}

// matcherFor returns the language whose imports can reference pkg and a
// function reporting whether an import specifier refers to it.
func matcherFor(ecosystem, pkg string) (Lang, func(string) bool) {
	switch strings.ToLower(ecosystem) {
	case "go", "gomod":
		if pkg == "stdlib" || pkg == "" {
			return "", nil // toolchain CVEs are not a single import
		}
		return Go, func(m string) bool { return m == pkg || strings.HasPrefix(m, pkg+"/") }
	case "npm", "yarn", "pnpm", "node-pkg":
		return JS, func(m string) bool { return jsPackage(m) == pkg }
	case "pypi", "pip", "pipenv", "poetry", "uv":
		want := pythonModules(pkg)
		return Python, func(m string) bool {
			for _, w := range want {
				if m == w || strings.HasPrefix(m, w+".") {
					return true
				}
			}
			return false
		}
	}
	return "", nil
}

// ── Go ───────────────────────────────────────────────────────────────────────

func parseGo(src []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), "", src, parser.ImportsOnly)
	if err != nil {
		return nil
	}
	var mods []string
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil {
			mods = append(mods, p)
		}
	}
	return mods
}

// ── JavaScript / TypeScript ──────────────────────────────────────────────────

// parseJS returns module specifiers from import/export-from statements,
// require() and dynamic import(). It walks the source as tokens, so a module
// name inside an ordinary string or a comment does not count.
func parseJS(src string) []string {
	var mods []string
	var prev []string // the last few significant tokens
	push := func(t string) {
		prev = append(prev, t)
		if len(prev) > 3 {
			prev = prev[1:]
		}
	}
	last := func(n int) string {
		if len(prev) < n {
			return ""
		}
		return prev[len(prev)-n]
	}

	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return mods
			}
			i += end + 4
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			lit := ""
			if j <= len(src) && j > i+1 {
				lit = src[i+1 : min(j, len(src))]
			}
			// A string is a module specifier only directly after `from`,
			// after `import` (side-effect import), or as the first
			// argument of require( / import(.
			if c != '`' && (last(1) == "from" || last(1) == "import" ||
				(last(1) == "(" && (last(2) == "require" || last(2) == "import"))) {
				mods = append(mods, lit)
			}
			push("<str>")
			i = j + 1
		case isIdentStart(c):
			j := i
			for j < len(src) && isIdentPart(src[j]) {
				j++
			}
			// A property access such as obj.require( is not a call to require.
			if i > 0 && src[i-1] == '.' {
				push("<prop>")
			} else {
				push(src[i:j])
			}
			i = j
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		default:
			push(string(c))
			i++
		}
	}
	return mods
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// jsPackage maps a module specifier to its npm package name, or "" for
// relative paths and Node built-ins:
//
//	lodash/merge     → lodash
//	@scope/pkg/sub   → @scope/pkg
func jsPackage(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

// ── Python ───────────────────────────────────────────────────────────────────

// parsePython returns absolute module paths from `import a, b.c` and
// `from a.b import c`, ignoring comments, relative imports and lines inside
// triple-quoted strings.
func parsePython(src string) []string {
	var mods []string
	inString := ""
	for _, raw := range strings.Split(src, "\n") {
		line := raw
		if inString != "" {
			if strings.Count(line, inString)%2 == 1 {
				inString = ""
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		for _, q := range []string{`"""`, `'''`} {
			if strings.Count(trimmed, q)%2 == 1 {
				inString = q
			}
		}
		if inString != "" {
			continue
		}
		if i := strings.Index(trimmed, "#"); i >= 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		switch {
		case strings.HasPrefix(trimmed, "import "):
			for _, part := range strings.Split(strings.TrimPrefix(trimmed, "import "), ",") {
				name := strings.Fields(part)
				if len(name) > 0 {
					mods = append(mods, name[0])
				}
			}
		case strings.HasPrefix(trimmed, "from "):
			fields := strings.Fields(trimmed)
			if len(fields) >= 3 && fields[2] == "import" && !strings.HasPrefix(fields[1], ".") {
				mods = append(mods, fields[1])
			}
		}
	}
	return mods
}

// pythonAliases covers common PyPI distributions whose import name differs
// from the distribution name. Anything else falls back to the normalised name.
var pythonAliases = map[string][]string{
	"pyyaml":              {"yaml"},
	"beautifulsoup4":      {"bs4"},
	"pillow":              {"PIL"},
	"scikit-learn":        {"sklearn"},
	"opencv-python":       {"cv2"},
	"python-dateutil":     {"dateutil"},
	"pyjwt":               {"jwt"},
	"python-dotenv":       {"dotenv"},
	"pycryptodome":        {"Crypto"},
	"pycryptodomex":       {"Cryptodome"},
	"psycopg2-binary":     {"psycopg2"},
	"protobuf":            {"google.protobuf"},
	"attrs":               {"attr", "attrs"},
	"pymongo":             {"pymongo", "bson", "gridfs"},
	"setuptools":          {"setuptools", "pkg_resources"},
	"python-jose":         {"jose"},
	"pyopenssl":           {"OpenSSL"},
	"msgpack-python":      {"msgpack"},
	"djangorestframework": {"rest_framework"},
}

// pythonModules returns the import names a PyPI distribution provides.
func pythonModules(dist string) []string {
	key := strings.ToLower(dist)
	if a, ok := pythonAliases[key]; ok {
		return a
	}
	return []string{strings.NewReplacer("-", "_", ".", "_").Replace(key)}
}
