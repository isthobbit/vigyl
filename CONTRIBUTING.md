# Contributing to jensec

First off â€” thank you for taking the time to contribute. jensec is built in Kenya for the world, and every issue, idea, and pull request makes it better for developers everywhere.

---

## Ways to contribute

- **Report a bug** â€” open an issue with steps to reproduce
- **Suggest a feature** â€” open an issue describing the use case
- **Fix a bug** â€” open a PR referencing the issue
- **Improve docs** â€” typos, clarity, missing examples all count
- **Share feedback** â€” even just telling us how you use jensec helps

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

**Dogfood â€” run jensec on itself**
```bash
make scan
```

---

## Project structure

```
vigyl/
â”œâ”€â”€ cmd/jensec/          # binary entry point
â”œâ”€â”€ internal/
â”‚   â”œâ”€â”€ cli/             # Cobra commands (scan, report, detect, config)
â”‚   â”œâ”€â”€ config/          # config types and loader
â”‚   â”œâ”€â”€ detect/          # language and framework detection
â”‚   â”œâ”€â”€ installer/       # dependency install prompts
â”‚   â”œâ”€â”€ scan/
â”‚   â”‚   â”œâ”€â”€ sast/        # Semgrep runner
â”‚   â”‚   â””â”€â”€ secrets/     # Gitleaks runner
â”‚   â””â”€â”€ store/           # SQLite scan history
â””â”€â”€ pkg/
    â”œâ”€â”€ output/          # terminal and JSON output
    â””â”€â”€ version/         # version info
```

Adding a new scanner follows the same pattern as `internal/scan/sast` and `internal/scan/secrets` â€” a `runner.go` with a `Run(path string, verbose bool) (*Result, error)` function and a `types.go` for the result types.

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
