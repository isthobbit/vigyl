# Changelog

All notable changes to jensec will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Meerkat sentry banner (the vigil in "vigyl") on `jensec`, `--help`, `version`
  and at the top of scans. Shown only in an interactive terminal; piped output,
  CI logs and `--json` get a single header line instead.
- `jensec doctor`: checks the four scanners (installed, on PATH, version against
  the minimum and tested versions), offline data, the config file and scan
  history, with a fix for each problem. On Windows it finds scanners that winget
  or pip installed but did not add to PATH. Exits 1 on any failure; `--json`.
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

### Changed
- Scan history moved from `~/.kinga/jensec.db` to `~/.vigyl/jensec.db`, alongside
  the config. On first run jensec moves `jensec.db` and `config.yaml` from
  `~/.kinga`, never overwriting existing files, and prints what it moved. A moved
  `config.yaml` was previously not read, so its settings now apply.

### Fixed
- `VIGYL_STORAGE_DB_PATH` and `VIGYL_AUTH_LICENSE_KEY` were ignored.
- `jensec report` ignored `storage.db_path`.
- `scan.semgrep_rules` is now honoured; it was previously ignored.
- OSV-Scanner exclusions use `--experimental-exclude` instead of adding a
  stray `--skip-git` per excluded path.
- `scan.exclude_paths` now applies to secrets scanning. Paths were written to a
  `.gitleaksignore`, which gitleaks reads as finding fingerprints, so they were
  silently ignored. They now go into a gitleaks config allowlist that extends
  any existing `.gitleaks.toml`.

---

## [v0.2.1] — 2026-08-01

Published on GitHub as `v2.1.0` by mistake; the tag was corrected to `v0.2.1`.

### Added
- `jensec ignore <finding-id>` suppresses a finding from future scan output and
  recommendations, with an optional `--reason`; `jensec ignore list` and
  `jensec ignore remove` manage ignore rules.
- Ignored findings are filtered from scan output.

---

## [v0.2.0] — 2026-07-29

### Added
- Dependency vulnerability scanning via [Trivy](https://aquasecurity.github.io/trivy)
  and [OSV-Scanner](https://google.github.io/osv-scanner)
- Correlation engine linking findings across all four scanners
- Risk scoring with named bands: LOW → MEDIUM → HIGH → CRITICAL → SEVERE
- Recommendations ordered by effort (IMMEDIATE → SHORT TERM → LONG TERM),
  deduplicated per rule and file
- Trend analysis across scans, with recurring findings capped to the top 10

### Security
- GitHub Actions pinned to commit SHAs

---

## [v0.1.0] — 2026-06-06

### Added
- Secrets scanning via [Gitleaks](https://github.com/gitleaks/gitleaks)
- SAST scanning via [Semgrep](https://semgrep.dev)
- Unified `jensec scan all / sast / secrets` CLI
- Local scan history stored in SQLite (`~/.vigyl/jensec.db`)
- Automatic dependency install prompt — jensec detects missing tools
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

Planned work is tracked in the [Roadmap](README.md#roadmap) section of the README.
