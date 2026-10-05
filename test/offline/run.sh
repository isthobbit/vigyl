#!/bin/sh
# Offline proof: scans a deliberately vulnerable fixture with
# `jensec scan all --offline` and checks every scanner produced findings.
#
# Run it inside a container started with --network none (see
# .github/workflows/offline-proof.yml). The fixture is generated here rather
# than committed, so the repo's own dogfood scans and GitHub push protection
# never see the planted secret or vulnerable code.
set -eu

# 1. Prove the sandbox really has no network before trusting the result.
if python3 -c 'import socket; socket.create_connection(("1.1.1.1", 443), timeout=3)' 2>/dev/null; then
    echo "FAIL: network is reachable; run this container with --network none" >&2
    exit 1
fi
echo "ok: no network access"

# 2. Build the fixture.
FIXTURE=$(mktemp -d)
cat > "$FIXTURE/app.py" <<'PY'
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system("echo " + cmd)
    return str(eval(request.args.get("expr")))


@app.route("/user")
def user():
    conn = sqlite3.connect("app.db")
    name = request.args.get("name")
    return str(conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall())
PY

cat > "$FIXTURE/requirements.txt" <<'TXT'
flask==0.12.2
jinja2==2.10
requests==2.19.0
TXT

cat > "$FIXTURE/package-lock.json" <<'JSON'
{
  "name": "vulnerable-app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "vulnerable-app" },
    "node_modules/lodash": { "version": "4.17.15" }
  }
}
JSON

# A random token in GitHub PAT format: matched by gitleaks, valid for nothing.
TOKEN="ghp_$(python3 -c 'import secrets, string; a = string.ascii_letters + string.digits; print("".join(secrets.choice(a) for _ in range(36)))')"
printf 'GITHUB_TOKEN=%s\n' "$TOKEN" > "$FIXTURE/.env"

# 3. Scan offline.
REPORT=$(mktemp)
ERRORS=$(mktemp)
jensec scan all "$FIXTURE" --offline --json --fail-on none > "$REPORT" 2> "$ERRORS" || {
    echo "FAIL: jensec exited non-zero" >&2
    cat "$ERRORS" >&2
    exit 1
}
cat "$ERRORS" >&2

# 4. Every scanner must have run cleanly and found something.
python3 - "$REPORT" "$ERRORS" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
stderr = open(sys.argv[2]).read()

counts = {
    "secrets": len(report["secrets"]),
    "sast": len(report["sast"]),
    # A vulnerability both scanners report is merged into one finding;
    # found_by lists every scanner that reported it.
    "trivy": sum(1 for d in report["dependencies"] if "trivy" in d["found_by"]),
    "osv": sum(1 for d in report["dependencies"] if "osv" in d["found_by"]),
}
print("findings per scanner:", counts)

failed = False
for scanner, n in counts.items():
    if n == 0:
        print(f"FAIL: {scanner} produced no findings offline", file=sys.stderr)
        failed = True
for marker in ("scan error", "not installed", "no offline data"):
    if marker in stderr:
        print(f"FAIL: scanner problem reported on stderr ({marker!r})", file=sys.stderr)
        failed = True

if failed:
    sys.exit(1)
print("ok: all four scanners found issues with no network access")
PY
