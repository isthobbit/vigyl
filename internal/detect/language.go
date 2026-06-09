package detect

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// skipDirs are directories we never descend into — they contain
// dependencies or generated code, not the project's own source.
var skipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	".svn":         true,
	"dist":         true,
	"build":        true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"env":          true,
	"target":       true, // Rust/Java
	"bin":          true,
	"obj":          true, // C#
	".idea":        true,
	".vscode":      true,
}

// Analyse walks scanPath and returns a Stack describing the project.
func Analyse(scanPath string) (*Stack, error) {
	// 1. Build extension → language map for O(1) lookups.
	extToLang := make(map[string]string)
	for _, def := range knownLanguages {
		for _, ext := range def.Extensions {
			extToLang[ext] = def.Name
		}
	}

	// 2. Walk the tree, counting source files per language.
	langCounts := make(map[string]int)
	totalFiles := 0

	err := filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if lang, ok := extToLang[ext]; ok {
			langCounts[lang]++
			totalFiles++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// 3. Convert counts to Language structs, sorted by file count desc.
	var languages []Language
	for name, count := range langCounts {
		confidence := 0.0
		if totalFiles > 0 {
			confidence = float64(count) / float64(totalFiles)
		}
		languages = append(languages, Language{
			Name:       name,
			FileCount:  count,
			Confidence: round2(confidence),
		})
	}
	sort.Slice(languages, func(i, j int) bool {
		return languages[i].FileCount > languages[j].FileCount
	})

	// 4. Detect frameworks by reading manifest files.
	frameworks := detectFrameworks(scanPath)

	// 5. Determine primary language.
	var primary Language
	if len(languages) > 0 {
		primary = languages[0]
	}

	return &Stack{
		Languages:  languages,
		Frameworks: frameworks,
		Primary:    primary,
	}, nil
}

// detectFrameworks reads known manifest files from the project root
// and checks for framework-specific strings inside them.
func detectFrameworks(root string) []Framework {
	// Cache manifest file contents so we don't re-read the same file
	// for every framework that references it (e.g. package.json).
	cache := make(map[string]string)

	readFile := func(rel string) string {
		if content, ok := cache[rel]; ok {
			return content
		}
		full := filepath.Join(root, rel)
		data, err := os.ReadFile(full)
		if err != nil {
			cache[rel] = ""
			return ""
		}
		content := strings.ToLower(string(data))
		cache[rel] = content
		return content
	}

	seen := make(map[string]bool) // prevent duplicate framework entries
	var frameworks []Framework

	for _, def := range knownFrameworks {
		content := readFile(def.File)
		if content == "" {
			continue // manifest not present
		}

		key := def.Name + "/" + def.Language
		if seen[key] {
			continue
		}

		if def.KeyInFile == "" {
			// File presence alone is enough.
			seen[key] = true
			frameworks = append(frameworks, Framework{
				Name:     def.Name,
				Language: def.Language,
				Evidence: def.File,
			})
		} else if strings.Contains(content, strings.ToLower(def.KeyInFile)) {
			seen[key] = true
			frameworks = append(frameworks, Framework{
				Name:     def.Name,
				Language: def.Language,
				Evidence: def.File + " (contains \"" + def.KeyInFile + "\")",
			})
		}
	}

	return frameworks
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
