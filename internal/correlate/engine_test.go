package correlate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/globs"
	"github.com/isthobbit/vigyl/internal/imports"
	"github.com/isthobbit/vigyl/internal/store"
)

// fixture builds a project on disk and returns its root and import index.
func fixture(t *testing.T, files map[string]string) (string, *imports.Index) {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ix, err := imports.Build(root, globs.Compile(nil))
	if err != nil {
		t.Fatal(err)
	}
	return root, ix
}

var nextID int64

func code(scanner, severity, file string, line int, rule string) store.CodeFindingRecord {
	nextID++
	return store.CodeFindingRecord{ID: nextID, Scanner: scanner, Severity: severity, File: file, Line: line, RuleID: rule}
}

func dep(scanner, severity, pkg, version, cve, eco, manifest string) store.DepFindingRecord {
	nextID++
	return store.DepFindingRecord{ID: nextID, Scanner: scanner, Severity: severity, Package: pkg, Version: version,
		CVEID: cve, Ecosystem: eco, Manifest: manifest, FixedVersion: "9.9.9"}
}

func reasons(a *analysis) map[string]int {
	out := map[string]int{}
	for _, c := range a.correlations {
		out[c.Reason]++
	}
	return out
}

func riskFor(t *testing.T, a *analysis, name string) Risk {
	t.Helper()
	for _, r := range a.result.Risks {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no risk entry for %q", name)
	return Risk{}
}

func hasWhy(r Risk, substr string) bool {
	for _, w := range r.Why {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// The README's headline case: a secret in a file that imports a vulnerable
// package. Previously no rule linked these at all.
func TestLinksCodeToTheFilesThatImportAVulnerablePackage(t *testing.T) {
	root, ix := fixture(t, map[string]string{
		"app/db.py":               "import requests\n",
		"app/other.py":            "import os\n",
		"app/requests_handler.py": "import json\n", // name contains the package; must NOT link
	})
	a := analyse(Input{Root: root, Imports: ix,
		CodeFindings: []store.CodeFindingRecord{
			code("secrets", "HIGH", filepath.Join(root, "app", "db.py"), 3, "github-pat"),
			code("sast", "HIGH", "app/db.py", 10, "python.lang.security.sqli.formatted-sql"),
			code("sast", "HIGH", "app/other.py", 4, "python.lang.security.eval-detected"),
			code("sast", "MEDIUM", "app/requests_handler.py", 2, "python.lang.x"),
		},
		DepFindings: []store.DepFindingRecord{
			dep("trivy", "HIGH", "requests", "2.19.0", "CVE-2018-18074", "PyPI", "requirements.txt"),
		},
	}, Weights(nil))

	got := reasons(a)
	if got[ReasonSecretUsingVulnerableDep] != 1 || got[ReasonVulnCodeInVulnerableFile] != 1 {
		t.Fatalf("expected one secret link and one code link (db.py only), got %v", got)
	}
	db := riskFor(t, a, "app/db.py")
	if !hasWhy(db, "imports requests 2.19.0 — CVE-2018-18074 (HIGH), fixed in 9.9.9") {
		t.Errorf("db.py explanation missing the import link: %v", db.Why)
	}
	if hasWhy(riskFor(t, a, "app/requests_handler.py"), "imports requests") {
		t.Error("a filename containing the package name must not count as importing it")
	}
	pkg := riskFor(t, a, "requests@2.19.0")
	if !hasWhy(pkg, "imported by app/db.py") {
		t.Errorf("package explanation should name its importer: %v", pkg.Why)
	}
}

// Gitleaks reports forward slashes and semgrep backslashes on Windows; both
// must land on the same file.
func TestSameFileAcrossPathForms(t *testing.T) {
	root := t.TempDir()
	secretPath := filepath.ToSlash(filepath.Join(root, "app", "db.py"))
	sastPath := filepath.Join(root, "app", "db.py")
	a := analyse(Input{Root: root, CodeFindings: []store.CodeFindingRecord{
		code("secrets", "HIGH", secretPath, 1, "aws-key"),
		code("sast", "CRITICAL", sastPath, 2, "x.sqli"),
	}}, Weights(nil))

	if reasons(a)[ReasonSecretInVulnerableFile] != 1 {
		t.Fatalf("secret and SAST finding in the same file were not linked: %v", reasons(a))
	}
	if n := len(a.result.Risks); n != 1 {
		t.Errorf("expected one file entry, got %d: %+v", n, a.result.Risks)
	}
}

// One fact is one bonus: many secrets next to one vulnerability count once.
func TestRepeatedLinksCountOnce(t *testing.T) {
	root := t.TempDir()
	findings := []store.CodeFindingRecord{code("sast", "HIGH", "a.py", 1, "x.y")}
	for i := 0; i < 10; i++ {
		findings = append(findings, code("secrets", "HIGH", "a.py", 10+i, "generic-api-key"))
	}
	a := analyse(Input{Root: root, CodeFindings: findings}, Weights(nil))
	if got := riskFor(t, a, "a.py").Score; got != 4.0 { // HIGH (3) + one secret_in_vulnerable_file (1.0)
		t.Errorf("score = %v, want 4.0", got)
	}
}

func TestScannerAgreementAndDistinctCVEs(t *testing.T) {
	root := t.TempDir()
	a := analyse(Input{Root: root, DepFindings: []store.DepFindingRecord{
		// The same CVE from both scanners: confirmation, not "multiple CVEs".
		dep("trivy", "HIGH", "lodash", "4.17.15", "CVE-2020-8203", "npm", "package-lock.json"),
		dep("osv", "HIGH", "lodash", "4.17.15", "CVE-2020-8203", "npm", "package-lock.json"),
		// Two real CVEs in another package, from one scanner.
		dep("trivy", "CRITICAL", "minimist", "1.2.0", "CVE-2021-44906", "npm", "package-lock.json"),
		dep("trivy", "MEDIUM", "minimist", "1.2.0", "CVE-2020-7598", "npm", "package-lock.json"),
	}}, Weights(nil))

	got := reasons(a)
	if got[ReasonCVEConfirmed] != 1 || got[ReasonPackageConfirmed] != 0 {
		t.Errorf("expected one CVE confirmation and no package-only confirmation: %v", got)
	}
	if got[ReasonMultipleCVEsInSamePackage] != 1 {
		t.Errorf("only minimist has two distinct CVEs: %v", got)
	}
	if !hasWhy(riskFor(t, a, "lodash@4.17.15"), "reported by both Trivy and OSV-Scanner") {
		t.Error("lodash should say both scanners reported it")
	}
}

func TestUsageWording(t *testing.T) {
	root, ix := fixture(t, map[string]string{"main.py": "import flask\n"})
	a := analyse(Input{Root: root, Imports: ix, DepFindings: []store.DepFindingRecord{
		dep("trivy", "HIGH", "django", "2.0", "CVE-1", "PyPI", "requirements.txt"),
		dep("trivy", "HIGH", "commons-text", "1.9", "CVE-2", "Java", "pom.xml"),
	}}, Weights(nil))

	if !hasWhy(riskFor(t, a, "django@2.0"), "no direct import found; it may still be used by another dependency") {
		t.Error("unimported package should be labelled, not downgraded")
	}
	if !hasWhy(riskFor(t, a, "commons-text@1.9"), "import use unknown for Java packages") {
		t.Error("unsupported ecosystem should say it is unknown")
	}
	// Labelling never lowers the score below the package's own severity.
	if s := riskFor(t, a, "django@2.0").Score; s != 3.0 {
		t.Errorf("django score = %v, want its HIGH base of 3.0", s)
	}
}

func TestMonorepoScopesImportsToTheManifest(t *testing.T) {
	root, ix := fixture(t, map[string]string{
		"api/app.py":    "import requests\n",
		"worker/job.py": "import requests\n",
	})
	a := analyse(Input{Root: root, Imports: ix,
		CodeFindings: []store.CodeFindingRecord{
			code("sast", "HIGH", "api/app.py", 1, "x"),
			code("sast", "HIGH", "worker/job.py", 1, "x"),
		},
		DepFindings: []store.DepFindingRecord{dep("osv", "HIGH", "requests", "2.19.0", "CVE-2018-18074", "PyPI", "api/requirements.txt")},
	}, Weights(nil))

	if hasWhy(riskFor(t, a, "worker/job.py"), "imports requests") {
		t.Error("a CVE from api/requirements.txt must not link to worker/")
	}
	if !hasWhy(riskFor(t, a, "api/app.py"), "imports requests") {
		t.Error("api/app.py should be linked")
	}
}

func TestWeightOverrides(t *testing.T) {
	w := Weights(map[string]float64{ReasonSecretInVulnerableFile: 0})
	a := analyse(Input{Root: t.TempDir(), CodeFindings: []store.CodeFindingRecord{
		code("secrets", "HIGH", "a.py", 1, "k"), code("sast", "HIGH", "a.py", 2, "x"),
	}}, w)
	if got := riskFor(t, a, "a.py").Score; got != 3.0 {
		t.Errorf("weight 0 should remove the bonus, score = %v", got)
	}
}

// Trivy names a vulnerability by CVE, OSV-Scanner often by GHSA: one
// vulnerability, two IDs. It must not count as "multiple vulnerabilities".
func TestAliasedAdvisoriesCountOnce(t *testing.T) {
	a := analyse(Input{Root: t.TempDir(), DepFindings: []store.DepFindingRecord{
		dep("trivy", "HIGH", "flask", "0.12.2", "CVE-2018-1000656", "PyPI", "requirements.txt"),
		dep("osv", "HIGH", "flask", "0.12.2", "GHSA-562c-5r94-xh97", "PyPI", "requirements.txt"),
	}}, Weights(nil))

	if n := reasons(a)[ReasonMultipleCVEsInSamePackage]; n != 0 {
		t.Errorf("one vulnerability under two IDs was counted as multiple (%d correlations)", n)
	}
	r := riskFor(t, a, "flask@0.12.2")
	if hasWhy(r, "known vulnerabilities") {
		t.Errorf("should describe a single vulnerability: %v", r.Why)
	}
	if reasons(a)[ReasonPackageConfirmed] != 1 {
		t.Errorf("both scanners flagged the package under different IDs: %v", reasons(a))
	}
}

// At equal scores a package the code imports ranks above one it does not,
// and Top shows each package once with all its vulnerable versions.
func TestTopRanksImportedFirstAndGroupsVersions(t *testing.T) {
	root, ix := fixture(t, map[string]string{
		"package-lock.json": "{}",
		"index.js":          "const _ = require('underscore')\n",
	})
	in := Input{Root: root, Imports: ix, DepFindings: []store.DepFindingRecord{
		// minimist sorts first by name and has two versions; nothing imports it.
		dep("trivy", "CRITICAL", "minimist", "0.0.8", "CVE-2021-44906", "npm", "package-lock.json"),
		dep("trivy", "CRITICAL", "minimist", "1.2.0", "CVE-2021-44906", "npm", "package-lock.json"),
		dep("trivy", "CRITICAL", "underscore", "1.9.1", "CVE-2021-23358", "npm", "package-lock.json"),
	}}
	a := analyse(in, Weights(nil))
	if a.result.Risks[0].Name != "underscore@1.9.1" {
		t.Fatalf("imported package should rank first at equal score, got %q", a.result.Risks[0].Name)
	}
	if got := riskFor(t, a, "minimist@0.0.8").Score; got != riskFor(t, a, "underscore@1.9.1").Score {
		t.Fatalf("ranking must not change scores: minimist %.1f", got)
	}

	top := a.result.Top(10)
	if len(top) != 2 {
		t.Fatalf("expected underscore and one grouped minimist entry, got %+v", top)
	}
	m := top[1]
	if m.Name != "minimist@0.0.8, 1.2.0" || len(m.Versions) != 2 || !hasWhy(m, "also vulnerable: 1.2.0") {
		t.Errorf("minimist versions not grouped: %+v", m)
	}
	if len(a.result.Risks) != 3 || a.result.Risks[1].Name == m.Name {
		t.Error("Top must not modify the stored per-version risks")
	}
	if got := a.result.Top(1); len(got) != 1 || got[0].Name != "underscore@1.9.1" {
		t.Errorf("Top(1) = %+v", got)
	}
}
