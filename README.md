# jensec

```
╭─────────────────────────────────────────╮
│  jensec · by KINGA                      │
│  Offline-first DevSecOps scanner        │
│  Built in Kenya for the world           │
╰─────────────────────────────────────────╯
```

**jensec** is a command-line security scanner for developers. It detects leaked secrets and code vulnerabilities in your project — no cloud account, no sign-up, no data leaving your machine.

Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) (secrets) and [Semgrep](https://semgrep.dev) (SAST), with a unified CLI and local scan history so you can track progress over time.

---

## Features

- **Secrets detection** — API keys, tokens, passwords committed to source
- **SAST** — common vulnerability patterns across 15+ languages
- **Local history** — every scan is stored in a local SQLite database; no cloud required
- **Developer-friendly output** — coloured terminal output or `--json` for CI pipelines
- **Configurable** — YAML config file, environment variables, or CLI flags

---

## Prerequisites

jensec wraps two best-in-class open source tools. Install both before running:

**Gitleaks** (secrets scanning)
```bash
# macOS
brew install gitleaks

# Linux / other — see https://github.com/gitleaks/gitleaks#installing
```

**Semgrep** (SAST)
```bash
# macOS / Linux
pip install semgrep

# or via Homebrew
brew install semgrep
```

---

## Installation

```bash
go install github.com/isthobbit/kinga/cmd/jensec@latest
```

Requires Go 1.22+. The binary is placed in `$GOPATH/bin` (usually `~/go/bin`).

---

## Quick start

```bash
# Scan the current directory — runs both secrets + SAST
jensec scan all

# Scan a specific path
jensec scan all ./my-project

# Secrets only
jensec scan secrets ./my-project

# SAST only
jensec scan sast ./my-project
```

---

## CI / CD integration

Use `--fail-on` to control which severity level causes a non-zero exit code:

```bash
# Fail the pipeline only on CRITICAL findings
jensec scan all --fail-on critical

# Fail on HIGH or above (default)
jensec scan all --fail-on high

# Never fail the pipeline, just report
jensec scan all --fail-on none
```

Severity levels: `critical` → `high` → `medium` → `low` → `none`

> **Important — secrets and `--fail-on critical`:** Gitleaks does not assign
> per-finding severity. jensec treats every detected secret as **HIGH** (a leaked
> credential is always significant). This means `--fail-on critical` will **not**
> trigger on secrets findings. Use `--fail-on high` (the default) or lower if
> you want the pipeline to fail when a secret is found.

Output machine-readable JSON for downstream processing:

```bash
jensec scan all --json
jensec scan all --json --output results.json
```

### GitHub Actions example

```yaml
- name: Build jensec
  run: go build -o /usr/local/bin/jensec ./cmd/jensec

- name: Security scan
  run: jensec scan all --fail-on high --json --output security-report.json
```

---

## Scan history

jensec stores every scan in `~/.kinga/jensec.db`. View past results:

```bash
jensec report list          # list recent scans
jensec report show <id>     # show findings for a specific scan
```

---

## Configuration

Create `~/.kinga/config.yaml` to set persistent defaults:

```yaml
scan:
  fail_on: high             # critical | high | medium | low | none
  timeout: 5m
  semgrep_rules: auto       # or a custom ruleset path / registry ID
  exclude_paths:
    - "**/*_test.go"
    - "fixtures/**"

output:
  json: false
  no_color: false
  verbose: false

storage:
  max_history: 100
  # db_path: /custom/path/to/jensec.db   # optional; default is ~/.kinga/jensec.db
```

Any config value can also be set with a `KINGA_` environment variable:

```bash
KINGA_SCAN_FAIL_ON=critical jensec scan all
KINGA_OUTPUT_NO_COLOR=true jensec scan all
```

---

## Supported languages

Go · TypeScript · JavaScript · Python · Rust · Java · Kotlin · C# · C/C++ · Ruby · PHP · Swift · Dart · Scala · Elixir · Shell

Framework detection: Gin, Echo, Fiber, Next.js, NestJS, Express, React, Vue, Django, FastAPI, Flask, Actix, Axum, Spring Boot, Rails, Laravel, Flutter, and more.

---

## Global flags

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |
| `--no-color` | Disable coloured output |
| `-v, --verbose` | Verbose output |
| `--config <path>` | Custom config file path |

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings at or above `--fail-on` threshold |
| `1` | Findings found at or above threshold |
| `2` | Scanner tool error (Semgrep or Gitleaks not installed / failed) |

---

## Contributing

Issues and PRs are welcome. Please open an issue before starting significant work so we can discuss approach.

```bash
git clone https://github.com/isthobbit/kinga
cd kinga
go mod tidy
go test ./...
```

---

## License

MIT © isthobbit

---

*Built in Kenya for the world.*

---

## CI/CD Integration

jensec ships with ready-to-use CI configurations.

### GitHub Actions

The workflow is already in `.github/workflows/jensec.yml`. It runs on every push and pull request to `main`, `master`, or `develop`.

To adjust the failure threshold, edit the `--fail-on` flag in the workflow:

```yaml
- name: Run secrets scan
  run: jensec scan secrets . --fail-on critical  # only fail on CRITICAL
```

### GitLab CI

Copy `.gitlab-ci.yml` to your repo root, or include it from your existing pipeline. The threshold is controlled by the `JENGSEC_FAIL_ON` variable:

```yaml
variables:
  JENGSEC_FAIL_ON: "critical"
```

Or set it in GitLab under **Settings → CI/CD → Variables**.

### Local CI (Makefile)

```bash
make build        # compile the binary
make scan         # run jensec against itself
make test         # run tests
make scan-secrets # secrets only
make scan-sast    # SAST only
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings at or above `--fail-on` threshold |
| `1` | Findings at or above threshold — fail the pipeline |
| `2` | Tool error — Gitleaks or Semgrep not installed or crashed |
