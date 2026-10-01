# Changelog

All notable changes to jensec will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `--offline` flag (and `scan.offline` config) on every `scan` command: all four
  scanners run against local data with no network access. Semgrep metrics and
  version checks, Trivy DB updates, version checks and telemetry, and OSV-Scanner
  API lookups are all turned off.
- `jensec offline sync` downloads the Trivy DB, OSV ecosystem databases and
  Semgrep rule packs; `status` reports their age and warns after 7 days.
- `jensec offline export` / `import` move that data to an air-gapped machine as
  one archive with a SHA-256 checksum. Import rejects path traversal and links.
- CI workflow `offline-proof.yml` scans a vulnerable fixture inside a container
  started with `--network none` and fails unless every scanner finds issues.

### Fixed
- `scan.semgrep_rules` is now honoured; it was previously ignored.
- OSV-Scanner exclusions use `--experimental-exclude` instead of adding a
  stray `--skip-git` per excluded path.

---

## [v0.1.0] â€” 2026-06-06

### Added
- Secrets scanning via [Gitleaks](https://github.com/gitleaks/gitleaks)
- SAST scanning via [Semgrep](https://semgrep.dev)
- Unified `jensec scan all / sast / secrets` CLI
- Local scan history stored in SQLite (`~/.vigyl/jensec.db`)
- Automatic dependency install prompt â€” jensec detects missing tools
  and offers to install them interactively (Y/N)
- `--fail-on` flag for pipeline threshold control (critical/high/medium/low/none)
- `--json` and `--output` flags for machine-readable output
- Language and framework auto-detection (15+ languages, 20+ frameworks)
- GitHub Actions workflow (`.github/workflows/jensec.yml`)
- GitLab CI configuration (`.gitlab-ci.yml`)
- Makefile with `build`, `install`, `test`, `scan`, `clean` targets
- Coloured terminal output with `--no-color` override
- Verbose mode with `-v`
- Config file support via `~/.vigyl/config.yaml` and `vigyl_` env vars

---

## Upcoming

### [v0.2.0] â€” planned
- SARIF output format (`--format sarif`) for GitHub Code Scanning integration
- `govulncheck` integration for Go dependency vulnerability scanning
- `jensec report export` â€” shareable HTML snapshot of scan results
- Asset management â€” `jensec assets` command surfacing multi-repo scan history

### [v0.3.0] â€” planned
- HTML and PDF report formats
- Risk scoring engine
- Team scan history sharing (self-hosted)
