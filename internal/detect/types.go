package detect

// Stack holds everything detected about a project's technology choices.
type Stack struct {
	Languages  []Language
	Frameworks []Framework
	// Primary is the single most prominent language (highest file count).
	Primary Language
}

// Language represents a detected programming language.
type Language struct {
	Name      string `json:"name"`
	FileCount int    `json:"file_count"`
	// Confidence is 0.0–1.0 based on file count vs total files.
	Confidence float64 `json:"confidence"`
}

// Framework represents a detected framework or major library.
type Framework struct {
	Name     string `json:"name"`
	Language string `json:"language"`
	// Evidence is the file or pattern that confirmed this framework.
	Evidence string `json:"evidence"`
}

// languageDef maps file extensions to language names.
type languageDef struct {
	Name       string
	Extensions []string
}

// frameworkDef maps a manifest filename or pattern to a framework.
type frameworkDef struct {
	Name     string
	Language string
	// File is the manifest or config file that signals this framework.
	File string
	// KeyInFile is an optional string that must appear inside File.
	// Empty means the file's existence alone is enough.
	KeyInFile string
}

// knownLanguages is the list of languages jensec can detect.
// Ordered roughly by global prevalence so the "first match wins" tie-break
// in extension collisions (e.g. .js vs .ts) favours the right language.
var knownLanguages = []languageDef{
	{Name: "Go", Extensions: []string{".go"}},
	{Name: "TypeScript", Extensions: []string{".ts", ".tsx"}},
	{Name: "JavaScript", Extensions: []string{".js", ".jsx", ".mjs", ".cjs"}},
	{Name: "Python", Extensions: []string{".py", ".pyw"}},
	{Name: "Rust", Extensions: []string{".rs"}},
	{Name: "Java", Extensions: []string{".java"}},
	{Name: "Kotlin", Extensions: []string{".kt", ".kts"}},
	{Name: "C#", Extensions: []string{".cs"}},
	{Name: "C/C++", Extensions: []string{".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}},
	{Name: "Ruby", Extensions: []string{".rb"}},
	{Name: "PHP", Extensions: []string{".php"}},
	{Name: "Swift", Extensions: []string{".swift"}},
	{Name: "Dart", Extensions: []string{".dart"}},
	{Name: "Scala", Extensions: []string{".scala"}},
	{Name: "Elixir", Extensions: []string{".ex", ".exs"}},
	{Name: "Shell", Extensions: []string{".sh", ".bash", ".zsh"}},
}

// knownFrameworks is the list of frameworks jensec can detect.
var knownFrameworks = []frameworkDef{
	// Go
	{Name: "Gin", Language: "Go", File: "go.mod", KeyInFile: "github.com/gin-gonic/gin"},
	{Name: "Echo", Language: "Go", File: "go.mod", KeyInFile: "github.com/labstack/echo"},
	{Name: "Fiber", Language: "Go", File: "go.mod", KeyInFile: "github.com/gofiber/fiber"},
	{Name: "Chi", Language: "Go", File: "go.mod", KeyInFile: "github.com/go-chi/chi"},

	// Node / JS / TS
	{Name: "Next.js", Language: "TypeScript", File: "next.config.js"},
	{Name: "Next.js", Language: "TypeScript", File: "next.config.ts"},
	{Name: "NestJS", Language: "TypeScript", File: "package.json", KeyInFile: "@nestjs/core"},
	{Name: "Express", Language: "JavaScript", File: "package.json", KeyInFile: "\"express\""},
	{Name: "Fastify", Language: "JavaScript", File: "package.json", KeyInFile: "\"fastify\""},
	{Name: "React", Language: "TypeScript", File: "package.json", KeyInFile: "\"react\""},
	{Name: "Vue", Language: "JavaScript", File: "package.json", KeyInFile: "\"vue\""},
	{Name: "Svelte", Language: "JavaScript", File: "package.json", KeyInFile: "\"svelte\""},

	// Python
	{Name: "Django", Language: "Python", File: "requirements.txt", KeyInFile: "django"},
	{Name: "Django", Language: "Python", File: "pyproject.toml", KeyInFile: "django"},
	{Name: "FastAPI", Language: "Python", File: "requirements.txt", KeyInFile: "fastapi"},
	{Name: "FastAPI", Language: "Python", File: "pyproject.toml", KeyInFile: "fastapi"},
	{Name: "Flask", Language: "Python", File: "requirements.txt", KeyInFile: "flask"},

	// Rust
	{Name: "Actix", Language: "Rust", File: "Cargo.toml", KeyInFile: "actix-web"},
	{Name: "Axum", Language: "Rust", File: "Cargo.toml", KeyInFile: "axum"},

	// Java / Kotlin
	{Name: "Spring Boot", Language: "Java", File: "pom.xml", KeyInFile: "spring-boot"},
	{Name: "Spring Boot", Language: "Kotlin", File: "build.gradle.kts", KeyInFile: "spring-boot"},

	// Ruby
	{Name: "Rails", Language: "Ruby", File: "Gemfile", KeyInFile: "rails"},
	{Name: "Sinatra", Language: "Ruby", File: "Gemfile", KeyInFile: "sinatra"},

	// PHP
	{Name: "Laravel", Language: "PHP", File: "composer.json", KeyInFile: "laravel/framework"},
	{Name: "Symfony", Language: "PHP", File: "composer.json", KeyInFile: "symfony/symfony"},

	// Dart / Flutter
	{Name: "Flutter", Language: "Dart", File: "pubspec.yaml", KeyInFile: "flutter"},
}
