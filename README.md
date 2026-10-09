# jensec · by VIGYL

![Build](https://github.com/isthobbit/vigyl/actions/workflows/jensec.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/isthobbit/vigyl)
![License](https://img.shields.io/github/license/isthobbit/vigyl)
![Go](https://img.shields.io/badge/go-1.22+-blue)

```
  .-"""-.
 /  o o  \     jensec · by vigyl
 \   v   /     local-first DevSecOps scanner
  '.___.'
  /     \      secrets · SAST · dependencies
 /|     |\     → one prioritised risk score
(_|     |_)
  |  |  |      your code never leaves your machine
 _|  |  |_
(___/ \___)
```

jensec is an open-source DevSecOps CLI tool that detects leaked secrets, code vulnerabilities (SAST), and dependency CVEs — all from your terminal, with no cloud account and no sign-up. Your source code is never uploaded, and with `--offline` jensec makes no network calls at all, so it works on air-gapped machines.

Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) (secrets), [Semgrep](https://semgrep.dev) (SAST), [Trivy](https://aquasecurity.github.io/trivy) and [OSV-Scanner](https://google.github.io/osv-scanner) (dependencies), with a correlation engine that links findings across all four scanners into a unified risk score. See [a scan of OWASP NodeGoat](#example-owasp-nodegoat) for what that adds over running the scanners yourself.

---

## Features

- Secrets detection — API keys, tokens, and passwords committed to source code
- SAST — common vulnerability patterns across 15+ languages
- Dependency scanning — CVE detection via Trivy and OSV-Scanner across Go, Python, Node.js, and more
- Correlation engine — links findings across all four scanners: a secret or code vulnerability in a file that imports a package with a known CVE scores higher than any finding alone, and every raised score lists its reasons (see [How scoring works](#how-scoring-works))
- One finding per vulnerability — when Trivy and OSV-Scanner report the same CVE, it appears once, marked as found by both
- Risk scoring — every scan produces a named risk band: LOW → MEDIUM → HIGH → CRITICAL → SEVERE
- Recommendations — prioritised, actionable fixes ordered by effort (IMMEDIATE → SHORT TERM → LONG TERM)
- Trend analysis — tracks whether your codebase is getting more or less secure across scans
- Local history — every scan stored in a local SQLite database; no cloud required
- Offline mode — `--offline` runs every scanner with zero network access; `jensec offline` prepares and transfers the data for air-gapped machines
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

> Windows note: Trivy and OSV-Scanner installed via winget may not be added to PATH automatically. If jensec cannot find them, run `jensec doctor`: it finds them and tells you which directory to add to your user PATH.

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

### Check your setup

```bash
jensec doctor
```

`jensec doctor` checks that each scanner is installed, on your PATH and a supported
version, and reports the state of offline data, your config file and scan history.
Every problem comes with the fix. It changes nothing and exits 1 if any check fails,
so it also works as a CI pre-check. Add `--offline` to require offline data, or
`--json` for machine-readable output.

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

## Offline and air-gapped use

By default jensec never uploads your source code, but the scanners do use the
network:

| Scanner | Network use by default | With `--offline` |
|---|---|---|
| Gitleaks | none | none |
| Semgrep | downloads rules from the Semgrep registry and sends Semgrep usage metrics | local rule packs, metrics and version check off |
| Trivy | downloads its vulnerability DB; version check and telemetry | local DB, no updates, no version check or telemetry |
| OSV-Scanner | sends dependency names and versions to the osv.dev API | local OSV databases only |

`--offline` turns all of that off. If a scanner's data is missing, jensec skips
it and tells you how to fix it. It never falls back to the network.

```bash
# 1. On a machine with internet access, download the data (~/.vigyl/offline)
jensec offline sync

# 2. Scan with no network access
jensec scan all . --offline

# Check what is present and how old it is
jensec offline status
```

To make offline the default, set `scan.offline: true` in `~/.vigyl/config.yaml`.

### Air-gapped machines

```bash
# Connected machine
jensec offline sync
jensec offline export jensec-offline.tar.gz    # also writes jensec-offline.tar.gz.sha256

# Copy both files across, then on the air-gapped machine
jensec offline import jensec-offline.tar.gz    # verifies the checksum first
jensec scan all . --offline
```

The scanners must already be installed on the air-gapped machine. Offline mode
never offers to install them.

### What `sync` downloads

- **Trivy**: the vulnerability DB, fetched by your installed `trivy` so the
  format always matches. Add `--java-db` if you scan `.jar` files (several hundred MB).
- **OSV**: databases for Go, npm, PyPI, Maven, crates.io, RubyGems, Packagist
  and NuGet. Choose your own with `--ecosystems npm,PyPI`.
- **Semgrep**: the `p/default`, `p/secrets` and `p/owasp-top-ten` registry packs.
  Choose your own with `--semgrep-packs`, or point `scan.semgrep_rules` at your
  own local rules. Packs are downloaded onto your machine and are not bundled
  with jensec, because the Semgrep Rules License does not allow redistribution.

Vulnerability data goes out of date quickly. `jensec offline status` and
offline scans warn when data is more than 7 days old, so re-sync regularly.

### How this is verified

The [offline-proof](.github/workflows/offline-proof.yml) workflow builds jensec
and the scanners into a container, then runs `jensec scan all --offline` inside
a container started with `--network none`. It first confirms the network is
unreachable, then fails unless all four scanners find the planted issues in a
deliberately vulnerable fixture. To run it locally:

```bash
docker build -f test/offline/Dockerfile -t jensec-offline .
docker volume create jensec-data
docker run --rm -v jensec-data:/root/.vigyl jensec-offline jensec offline sync --ecosystems npm,PyPI
docker run --rm --network none -v jensec-data:/root/.vigyl jensec-offline offline-proof
```

---

## What the output looks like

After a scan, jensec produces:

Findings — grouped by scanner, showing severity, file, line, and message for each issue.

Top risks — the highest-scoring files and packages, each with the reasons behind its score:
```
Top risks  overall 6.5/10 CRITICAL

  HIGH      app/db.py  (file, score 6.0)
            • secret: github-pat (line 5)
            • CRITICAL tainted-sql-string (line 10)
            • secret in the same file as a code vulnerability
            • imports requests 2.19.0 — 5 known vulnerabilities, worst CVE-2018-18074 (HIGH), fixed in 2.20.0

  HIGH      minimist@1.2.0  (package, score 5.2)
            • 2 known vulnerabilities, worst CVE-2021-44906 (CRITICAL), fixed in 1.2.6
            • reported by both Trivy and OSV-Scanner
            • no direct import found; it may still be used by another dependency
```

The same list is in `--json` output as `top_risks`, with each reason in `why`.
A package installed at several versions is listed once, ranked by its
highest-scoring version, with the others under "also vulnerable".

Recommendations — prioritised list of actionable fixes, ordered by effort:
```
1. CRITICAL  [IMMEDIATE]  Secret in a file that imports vulnerable mongodb: artifacts/db-reset.js
   Why: artifacts/db-reset.js contains a detected-bcrypt-hash secret on line 19
        and imports mongodb 2.2.36, which has GHSA-mh5c-679w-hh4r (HIGH)...
   Do:  Rotate the credential and move it out of the source code, then upgrade
        mongodb from 2.2.36 to 3.1.13.

2. CRITICAL  [SHORT TERM]  Upgrade minimist (4 vulnerable versions installed)
   Why: minimist is installed at versions 0.0.8, 0.0.10, 1.2.0, 1.2.5, with 2
        known vulnerabilities between them; the worst is CVE-2021-44906 (CRITICAL).
   Do:  Upgrade 0.0.8 to 1.2.6; 0.0.10 to 1.2.6; 1.2.0 to 1.2.6; 1.2.5 to 1.2.6...
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

## Example: OWASP NodeGoat

[NodeGoat](https://github.com/OWASP/NodeGoat) is a deliberately vulnerable
Node.js app. These results are from commit `c5cb68a`, scanned with
`jensec scan all --offline` and offline data synced on 2026-10-05. Newer
vulnerability data will give somewhat different numbers.

**Running the four scanners yourself** gives 440 findings in four formats:

| Scanner | Findings |
|---------|----------|
| Gitleaks | 3 secrets |
| Semgrep | 35, of which 4 are secrets rather than code vulnerabilities |
| Trivy | 90 dependency vulnerabilities |
| OSV-Scanner | 312: 86 of them are vulnerabilities Trivy also reports, and 9 list a CVE a second time for the same package version |

None of them says which of the 132 vulnerable package versions the app's
code uses, or that a file with hardcoded password hashes also imports a
vulnerable database driver.

**jensec** reports each vulnerability once (307 dependency findings, 86
marked as found by both Trivy and OSV-Scanner), lists Semgrep's secrets with
the other secrets, and links packages to the files that import them:

```
Top risks  overall 4.9/10 HIGH

  HIGH      underscore@1.9.1, 1.8.3  (package, score 5.2)
            • 1.9.1: 2 known vulnerabilities, worst CVE-2021-23358 (CRITICAL), fixed in 1.12.1
            • reported by both Trivy and OSV-Scanner
            • imported by config/config.js
            • also vulnerable: 1.8.3 (score 4.5)
  ...
  HIGH      mongodb@2.2.36  (package, score 5.0)
            • GHSA-mh5c-679w-hh4r (HIGH), fixed in 3.1.13
            • reported by both Trivy and OSV-Scanner
            • imported by artifacts/db-reset.js, server.js
            • artifacts/db-reset.js, which imports it, contains a secret
            • server.js, which imports it, has a code vulnerability

  HIGH      server.js  (file, score 5.0)
            • HIGH express-cookie-session-default-name (line 78)
            • ...
            • imports body-parser 1.18.3 — 2 known vulnerabilities, worst CVE-2024-45590 (HIGH), fixed in 1.20.3
            • imports marked 0.3.5 — 7 known vulnerabilities, worst CVE-2017-16114 (HIGH), fixed in 0.3.9
            • imports mongodb 2.2.36 — GHSA-mh5c-679w-hh4r (HIGH), fixed in 3.1.13
            • ...
```

The omitted entries are packages such as `minimist` and `tar`, with CRITICAL
vulnerabilities but labelled "no direct import found". jensec keeps their
scores rather than guessing they are unused; see
[What jensec will not do](#what-jensec-will-not-do).

The first recommendation joins the two halves:

```
1. CRITICAL  [IMMEDIATE]  Secret in a file that imports vulnerable mongodb: artifacts/db-reset.js
   Do:  Rotate the credential and move it out of the source code, then upgrade
        mongodb from 2.2.36 to 3.1.13.
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
  offline: false            # true = always scan with local data only (same as --offline)
  parallel: true            # run the scanners at the same time; false on small CI runners
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
  # offline_dir: /custom/path/to/offline-data   # default ~/.vigyl/offline

correlation:
  weights:
    secret_in_vulnerable_file: 1.0
    secret_in_file_using_vulnerable_package: 0.9
    vuln_code_in_vulnerable_file: 0.8
    cve_confirmed_by_multiple_scanners: 0.7
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

## How scoring works

jensec scores every file and every vulnerable package version, then combines
them into the scan's overall score.

1. **Base score.** Each file or package starts at its worst finding's severity:
   LOW 1, MEDIUM 2, HIGH 3, CRITICAL 4.
2. **Correlation bonuses.** Each rule below that applies adds its weight. A
   rule counts once per link, so ten secrets next to one vulnerability count
   once, while a file importing two vulnerable packages counts twice.
3. **Cap.** Bonuses can raise a score by at most 2 above its base.
4. **Overall score.** The average of all file and package scores, plus 30% of
   the highest one, capped at 10. The band comes from the table above.

| Rule | Weight | Applies when |
|------|--------|--------------|
| `secret_in_vulnerable_file` | 1.0 | a secret sits in a file that also has a code vulnerability |
| `secret_in_file_using_vulnerable_package` | 0.9 | a secret sits in a file that imports a package with a known CVE |
| `vuln_code_in_vulnerable_file` | 0.8 | a code vulnerability sits in a file that imports a package with a known CVE |
| `cve_confirmed_by_multiple_scanners` | 0.7 | Trivy and OSV-Scanner both report the same CVE in the same package |
| `package_confirmed_by_multiple_scanners` | 0.6 | both scanners flag the same package, but under different advisory IDs |
| `multiple_cves_in_same_package` | 0.5 | a package has more than one distinct known vulnerability |
| `multiple_vulns_in_same_file` | 0.4 | a file has more than one code vulnerability |

Every weight can be changed under `correlation.weights` in the config file;
setting one to `0` removes that rule's bonus (the link is still shown).

### Linking dependencies to code

Trivy and OSV-Scanner report which package versions are vulnerable, not
where they are used. jensec reads the import statements in your source to
find which files import each vulnerable package:

- **Go** (`import`), **JavaScript/TypeScript** (`import`, `require()`,
  dynamic `import()`) and **Python** (`import`, `from … import`) are
  supported. Imports inside strings and comments are ignored.
- A package is only linked to files under the directory of the manifest it
  came from, so in a monorepo a CVE in one service is not blamed on another.
- `vendor/`, `node_modules/`, virtual environments and `scan.exclude_paths`
  are skipped.

### What jensec will not do

- **Downgrade on uncertainty.** A vulnerable package that no file imports
  directly is labelled "no direct import found; it may still be used by
  another dependency", but its score is not lowered: another dependency may
  still use it. For ecosystems jensec cannot read imports for (Java, Ruby,
  PHP, Rust), it says "import use unknown" rather than guessing. Where
  two scores are equal, packages your code imports are listed first; the
  scores themselves are unchanged.
- **Count one vulnerability twice.** Trivy and OSV-Scanner often name the same
  vulnerability differently (a CVE ID versus a GHSA or PYSEC ID). jensec
  matches them through OSV's aliases, and when it counts a package's
  vulnerabilities, it uses the larger of the two scanners' counts rather than
  adding them.
- **Count one secret twice.** Semgrep's secret rules (`generic.secrets.*`)
  find the same kind of thing Gitleaks does. jensec reports them as secrets,
  not code vulnerabilities, and drops one that Gitleaks already found on the
  same line, so a secret is never linked to itself.

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

Released (see [CHANGELOG.md](CHANGELOG.md) for details):

- **v0.1** — Secrets scanning (Gitleaks), SAST (Semgrep), local scan history, CI integration
- **v0.2** — Dependency scanning (Trivy + OSV), correlation engine, risk scoring with named bands (LOW → SEVERE), structured recommendations, trend analysis; v0.2.1 added `jensec ignore`
- **v0.3** — Offline and air-gapped scanning (`--offline`, `jensec offline`), `jensec doctor`, scan history moved to `~/.vigyl`

Planned:

- SARIF output for GitHub Code Scanning
- Pre-commit hook installer
- Docker image scanning and IaC scanning (Terraform, Kubernetes, CloudFormation)
- `govulncheck` integration for Go dependencies
- Local web dashboard, multi-repo scan history and self-hosted team sharing
- HTML and PDF report export
- M-Pesa and mobile money secret detection rules
- Kenya DPA compliance report

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