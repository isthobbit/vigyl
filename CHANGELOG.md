# Changelog

All notable changes to jensec will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Dependency findings are linked to the source files that import them (Go,
  JavaScript/TypeScript, Python), scoped to each manifest's directory so
  monorepos link correctly. New rule `secret_in_file_using_vulnerable_package`;
  `vuln_code_in_vulnerable_file` now uses real imports instead of matching the
  package name against the file path.
- "Top risks" after each scan: the highest-scoring files and packages with the
  reasons behind each score. Also in `--json` as `top_risks`, with
  `risk_score` and `risk_band`.
- `--json` dependency findings have `found_by` and `manifest`; a CVE reported by
  both Trivy and OSV-Scanner appears once.
- README section "How scoring works".
- `top_risks` entries for packages have `versions`.

### Changed
- Unimported vulnerable packages are labelled, never downgraded; unsupported
  ecosystems say "import use unknown".
- Each correlation counts once per link, so repeated findings no longer inflate
  a score.
- Removed `secret_and_vuln_in_same_file`, which duplicated
  `secret_in_vulnerable_file` and counted the same fact twice.
- Database schema v4 records each dependency finding's manifest.
- Semgrep's secret rules (`generic.secrets.*`) are reported as secrets, not
  code vulnerabilities, and one Gitleaks already found on the same line is
  dropped. Previously a private key could be reported as a secret in a file
  with a code vulnerability: itself.
- Top risks lists each package once with all its vulnerable versions, and at
  equal scores puts files and imported packages first. Scores are unchanged.
- One recommendation per vulnerable package, replacing the separate "CVE
  confirmed", "confirmed by multiple scanners" and "multiple
  vulnerabilities" ones for each version. It names, for each installed
  version, the lowest release that fixes all of its known vulnerabilities.
- File paths in `--json`, scan output and recommendations are relative to the
  scanned folder. Scan history still stores full paths, so `jensec ignore`
  rules keep matching.

### Fixed
- OSV-Scanner severities: CVSS vectors were scored as LOW, so OSV reported no
  HIGH or CRITICAL findings. The group's numeric score is now used, and an
  unscorable vector counts as MEDIUM.
- OSV findings now carry their CVE ID from the advisory's aliases, so they match
  Trivy's. Previously a finding could also be given an unrelated CVE.
- On Windows, gitleaks and semgrep report the same file with different path
  separators, so the same-file rules never matched. Paths are now normalised.
- `multiple_cves_in_same_package` counted one CVE reported by both scanners as
  two.
- `correlation.weights` and `trends` settings in the config were ignored.

### Removed
- The one-time move of scan history and config from the old data folder,
  added in v0.3.0. Every release before v0.3.0 had no users besides the
  maintainer, so jensec now only uses `~/.vigyl`.

---

## [v0.3.0] — 2026-10-05

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
- Release archives are named `jensec_<os>_<arch>` without the version, so the
  README's `releases/latest/download/...` install links work. They returned 404
  for every earlier release.
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
