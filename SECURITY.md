# Security policy

## Supported versions

Only the latest release of jensec gets security fixes. Fixes are not
backported, so upgrade to the newest release from
[Releases](https://github.com/isthobbit/vigyl/releases/latest).

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.

This opens a private advisory that only the maintainers can see. Include the
jensec version (`jensec version`), your operating system, and the steps or
files needed to reproduce the problem.

This is a one-person project, so replies can take a few days. A confirmed
vulnerability is fixed in a new release, published with a GitHub security
advisory that credits you unless you would rather not be named.

## What counts

jensec makes these promises, so anything that breaks them is a vulnerability:

- **Your code stays on your machine.** jensec never uploads source code.
- **`--offline` means no network access.** With `--offline`, neither jensec
  nor any scanner it runs makes a network connection.
- **Secrets are not shown in full.** Matched secret values are redacted in
  terminal output, `--json` output and scan history.
- **Imports are checked.** `jensec offline import` verifies the archive's
  checksum and refuses files that would land outside the offline data
  folder.
- **Scanning untrusted code is safe.** Scanning a repository you do not
  trust must not run code from it or write files outside jensec's own
  folders.

Other examples: command injection through config files or file names, and
jensec running a different program than the scanner it meant to run.

## What does not count

- **Vulnerabilities in Gitleaks, Semgrep, Trivy or OSV-Scanner.** Please
  report them to those projects. If jensec runs a scanner in an unsafe way,
  that is jensec's problem, so report it here.
- **Findings in your own code** that jensec reports, or misses. Those are
  bugs or feature requests; open a normal issue.
