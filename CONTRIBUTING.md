# Contributing to jensec

First off — thank you for taking the time to contribute. jensec is built in Kenya for the world, and every issue, idea, and pull request makes it better for developers everywhere.

---

## Ways to contribute

- **Report a bug** — open an issue with steps to reproduce
- **Suggest a feature** — open an issue describing the use case
- **Fix a bug** — open a PR referencing the issue
- **Improve docs** — typos, clarity, missing examples all count
- **Share feedback** — even just telling us how you use jensec helps

---

## Before you open a PR

1. **Open an issue first** for significant changes so we can discuss approach before you invest time writing code.
2. For small fixes (typos, obvious bugs) a PR without an issue is fine.

---

## Development setup

**Requirements**
- Go 1.22+
- [Gitleaks](https://github.com/gitleaks/gitleaks#installing)
- [Semgrep](https://semgrep.dev/docs/getting-started)

**Clone and build**
```bash
git clone https://github.com/isthobbit/vigyl.git
cd vigyl
go mod tidy
make build
```

**Run tests**
```bash
make test
# or
go test ./... -v
```

**Dogfood — run jensec on itself**
```bash
make scan
```

---

## Project structure

```
vigyl/
├── cmd/jensec/          # binary entry point
├── internal/
│   ├── cli/             # Cobra commands (scan, report, detect, config)
│   ├── config/          # config types and loader
│   ├── detect/          # language and framework detection
│   ├── installer/       # dependency install prompts
│   ├── scan/
│   │   ├── sast/        # Semgrep runner
│   │   └── secrets/     # Gitleaks runner
│   └── store/           # SQLite scan history
└── pkg/
    ├── output/          # terminal and JSON output
    └── version/         # version info
```

Adding a new scanner follows the same pattern as `internal/scan/sast` and `internal/scan/secrets` — a `runner.go` with a `Run(path string, verbose bool) (*Result, error)` function and a `types.go` for the result types.

---

## Code style

- Run `go fmt ./...` before committing
- Run `go vet ./...` and fix any warnings
- Keep functions small and focused
- Comment exported types and functions

---

## Commit messages

Use clear, present-tense commit messages:
```
feat: add SARIF output format
fix: correct failOn severity threshold logic
docs: add GitLab CI example to README
chore: update dependencies
```

---

## Reporting security issues

Please **do not** open a public GitHub issue for security vulnerabilities. Instead email the maintainer directly. We will respond within 48 hours and coordinate a fix before any public disclosure.

---

## Community

- Built in Kenya for the world
- Questions and discussion: open a GitHub issue with the `question` label

We appreciate every contribution, big or small.
