# jensec · by VIGYL

![Build](https://github.com/isthobbit/vigyl/actions/workflows/jensec.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/isthobbit/vigyl)
![License](https://img.shields.io/github/license/isthobbit/vigyl)
![Go](https://img.shields.io/badge/go-1.22+-blue)

```
╭─────────────────────────────────────────╮
│  jensec · by VIGYL                      │
│  Offline-first DevSecOps scanner        │
╰─────────────────────────────────────────╯
```

jensec is an open-source DevSecOps CLI tool that detects leaked secrets, code vulnerabilities (SAST), and dependency CVEs — all from your terminal, with no cloud account, no sign-up, and no data leaving your machine.

Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) (secrets), [Semgrep](https://semgrep.dev) (SAST), [Trivy](https://aquasecurity.github.io/trivy) and [OSV-Scanner](https://google.github.io/osv-scanner) (dependencies), with a correlation engine that links findings across all four scanners into a unified risk score.

---

## Features

- Secrets detection — API keys, tokens, and passwords committed to source code
- SAST — common vulnerability patterns across 15+ languages
- Dependency scanning — CVE detection via Trivy and OSV-Scanner across Go, Python, Node.js, and more
- Correlation engine — links findings across all four scanners; a secret in a file with a known CVE scores higher than either finding alone
- Risk scoring — every scan produces a named risk band: LOW → MEDIUM → HIGH → CRITICAL → SEVERE
- Recommendations — prioritised, actionable fixes ordered by effort (IMMEDIATE → SHORT TERM → LONG TERM)
- Trend analysis — tracks whether your codebase is getting more or less secure across scans
- Local history — every scan stored in a local SQLite database; no cloud required
- Developer-friendly output — coloured terminal output or `--json` for CI pipelines
- Configurable — YAML config file, environment variables, or CLI flags

---

## Installation

### Download a binary (recommended)

Download the latest release for your platform from the [Releases page](https://github.com/isthobbit/vigyl/releases).

Linux (amd64)
```bash
curl -L https://github.com/isthobbit/vigyl/releases/latest/download/jensec_linux_amd64.tar.gz | tar xz
sudo mv jensec /usr/local/bin/
```

macOS (Apple Silicon)
```bash
curl -L https://github.com/isthobbit/vigyl/releases/latest/download/jensec_darwin_arm64.tar.gz | tar xz
sudo mv jensec /usr/local/bin/
```

macOS (Intel)
```bash
curl -L https://github.com/isthobbit/vigyl/releases/latest/download/jensec_darwin_amd64.tar.gz | tar xz
sudo mv jensec /usr/local/bin/
```

Windows

Download `jensec_windows_amd64.zip` from the [Releases page](https://github.com/isthobbit/vigyl/releases), extract, and add the binary to your PATH.

> Windows note: Trivy and OSV-Scanner installed via winget may not be added to PATH automatically. If jensec cannot find them, add their install directories to your user PATH manually.

### Install with Go

```bash
go install github.com/isthobbit/vigyl/cmd/jensec@latest
```

Requires Go 1.22+. The binary is placed in `$GOPATH/bin` (usually `~/go/bin`).

---

## Prerequisites

jensec wraps four best-in-class open source tools. jensec will prompt you to install any missing tools automatically on first run, or you can install them manually:

Gitleaks (secrets scanning)
```bash
# macOS / Linux
brew install gitleaks
# Windows
winget install Gitleaks.Gitleaks
```

Semgrep (SAST)
```bash
pip install semgrep
```

Trivy (dependency vulnerability scanning)
```bash
# macOS / Linux
brew install trivy
# Windows
winget install AquaSecurity.Trivy
```

OSV-Scanner (dependency vulnerability scanning)
```bash
# macOS / Linux
brew install osv-scanner
# Windows
winget install Google.OSVScanner
```

---

## Quick start

```bash
# Run all scanners — secrets, SAST, and dependencies
jensec scan all .

# Scan a specific path
jensec scan all ./my-project

# Individual scanners
jensec scan secrets ./my-project
jensec scan sast ./my-project
jensec scan deps ./my-project
```

---

## What the output looks like

After a scan, jensec produces:

Findings — grouped by scanner, showing severity, file, line, and message for each issue.

Recommendations — prioritised list of actionable fixes, ordered by effort:
```
1. CRITICAL  [SHORT TERM]  Multiple vulnerabilities in python-jose@3.3.0
   Why: python-jose@3.3.0 has multiple known CVEs...
   Do:  Upgrade python-jose from 3.3.0 to 3.4.0.

2. HIGH  [LONG TERM]  Multiple vulnerabilities concentrated in .../docker-compose.prod.yml
   Why: Multiple vulnerabilities suggest a broader security review is needed.
   Do:  Review docker-compose.prod.yml holistically.
```

Trend analysis — compares against previous scans of the same path:
```
Trend Analysis

  Risk Score:  4.2 → 5.3  DEGRADING
  New:         +8
  Resolved:    -2

  Secrets:     +1
  SAST:        +3
  Deps:        +4

  ⚠  12 finding(s) have persisted across multiple scans
```

---

## CI/CD integration

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

> Important — secrets and `--fail-on critical`: Gitleaks does not assign
> per-finding severity. jensec treats every detected secret as *HIGH*. This means
> `--fail-on critical` will *not* trigger on secrets findings. Use `--fail-on high`
> (the default) or lower if you want the pipeline to fail when a secret is found.

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

The repository ships with a ready-to-use workflow in `.github/workflows/jensec.yml` that runs on every push and pull request to `main`, `master`, or `develop`.

### Local CI (Makefile)

```bash
make build        # compile the binary
make scan         # run jensec against itself
make test         # run unit tests
make scan-secrets # secrets only
make scan-sast    # SAST only
```

---

## Scan history

jensec stores every scan in `~/.vigyl/jensec.db`. View past results:

```bash
jensec report --list          # list recent scans with risk scores
jensec report <id>            # show findings for a specific scan
```

---

## Configuration

Create `~/.vigyl/config.yaml` to set persistent defaults:

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
  # db_path: /custom/path/to/jensec.db

correlation:
  weights:
    secret_in_vulnerable_file: 1.0
    vuln_code_in_vulnerable_file: 0.8
    cve_confirmed_by_multiple_scanners: 0.7
    secret_and_vuln_in_same_file: 0.6
    package_confirmed_by_multiple_scanners: 0.6
    multiple_cves_in_same_package: 0.5
    multiple_vulns_in_same_file: 0.4

trends:
  lookback_scans: 5
  min_scans_required: 2
  recurring_threshold: 3
```

Any config value can also be set with a `VIGYL_` environment variable:

```bash
VIGYL_SCAN_FAIL_ON=critical jensec scan all
VIGYL_OUTPUT_NO_COLOR=true jensec scan all
```

---

## Risk bands

Every scan produces an overall risk score mapped to a named band:

| Band | Score | Description |
|------|-------|-------------|
| LOW | 0.0 – 2.0 | No significant issues detected |
| MEDIUM | 2.1 – 4.0 | Some issues worth addressing |
| HIGH | 4.1 – 6.0 | Significant issues requiring attention |
| CRITICAL | 6.1 – 8.0 | Serious issues requiring immediate action |
| SEVERE | 8.1 – 10.0 | Multiple critical issues, do not ship |

---

## Supported languages

Go · TypeScript · JavaScript · Python · Rust · Java · Kotlin · C# · C/C++ · Ruby · PHP · Swift · Dart · Scala · Elixir · Shell

Framework detection: Gin, Echo, Fiber, Next.js, NestJS, Express, React, Vue, Django, FastAPI, Flask, Actix, Axum, Spring Boot, Rails, Laravel, Flutter, and more.

Dependency ecosystems: Go modules · PyPI · npm · Cargo · Maven · RubyGems · Composer

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
| `2` | Scanner tool error (tool not installed or failed) |

---

## Roadmap

- **v0.2** — Correlation engine, dependency scanning (Trivy + OSV), risk scoring with named bands (LOW → SEVERE), structured recommendations, and trend analysis
- **v0.3** — Docker image scanning, IaC scanning (Terraform, Kubernetes, CloudFormation), pre-commit hook installer, local web dashboard, M-Pesa and mobile money secret detection rules, Kenya DPA compliance report

---

## Contributing

Issues and PRs are welcome. Please open an issue before starting significant work so we can discuss approach. See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

```bash
git clone https://github.com/isthobbit/vigyl
cd vigyl
go mod tidy
go test ./...
```

---

## License

MIT © isthobbit