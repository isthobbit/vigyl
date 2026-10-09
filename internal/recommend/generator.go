package recommend

import (
	"cmp"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/isthobbit/vigyl/internal/store"
)

// Generate produces a prioritised list of recommendations from a set of
// correlations and their associated findings.
func Generate(
	correlations []store.CorrelationRecord,
	codeFindings []store.CodeFindingRecord,
	depFindings []store.DepFindingRecord,
) []Recommendation {
	// Build lookup maps for fast finding access.
	codeByID := make(map[int64]store.CodeFindingRecord, len(codeFindings))
	for _, f := range codeFindings {
		codeByID[f.ID] = f
	}
	depByID := make(map[int64]store.DepFindingRecord, len(depFindings))
	for _, f := range depFindings {
		depByID[f.ID] = f
	}

	var recs []Recommendation
	// Package rules are gathered per package name, so a package installed at
	// several versions, or flagged by several rules, gets one recommendation.
	flagged := map[string]*packageFlags{}

	for _, c := range correlations {
		var rec *Recommendation

		switch c.Reason {
		case "secret_in_vulnerable_file":
			rec = secretInVulnerableFile(c, codeByID)
		case "secret_in_file_using_vulnerable_package":
			rec = secretUsingVulnerablePackage(c, codeByID, depByID)
		case "multiple_vulns_in_same_file":
			rec = multipleVulnsInSameFile(c, codeByID)
		case "vuln_code_in_vulnerable_file":
			rec = vulnCodeInVulnerableFile(c, codeByID, depByID)
		case "cve_confirmed_by_multiple_scanners", "package_confirmed_by_multiple_scanners", "multiple_cves_in_same_package":
			if c.DepFindingID == nil {
				continue
			}
			dep, ok := depByID[*c.DepFindingID]
			if !ok {
				continue
			}
			f := flagged[dep.Package]
			if f == nil {
				f = &packageFlags{}
				flagged[dep.Package] = f
			}
			if c.Reason != "multiple_cves_in_same_package" {
				f.confirmed = true
			}
		}

		if rec != nil {
			rec.Rule = c.Reason
			recs = append(recs, *rec)
		}
	}

	for _, name := range sortedNames(flagged) {
		var findings []store.DepFindingRecord
		for _, f := range depFindings {
			if f.Package == name {
				findings = append(findings, f)
			}
		}
		if rec := vulnerablePackage(name, findings, flagged[name].confirmed); rec != nil {
			recs = append(recs, *rec)
		}
	}

	// Deduplicate — keep only the first recommendation per rule+title combination.
	// This prevents the same file appearing multiple times for the same rule
	// when there are many finding pairs (e.g. 7 findings = 6 correlations = 6 recs).
	seen := make(map[string]bool)
	var deduped []Recommendation
	for _, r := range recs {
		key := r.Rule + "|" + r.Title
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, r)
		}
	}

	// Sort by effort (IMMEDIATE first) then by priority (CRITICAL before HIGH etc).
	sort.Slice(deduped, func(i, j int) bool {
		ei := effortOrder[deduped[i].Effort]
		ej := effortOrder[deduped[j].Effort]
		if ei != ej {
			return ei < ej
		}
		return priorityOrder(deduped[i].Priority) > priorityOrder(deduped[j].Priority)
	})

	return deduped
}

// ── Per-rule recommendation generators ───────────────────────────────────────

func secretInVulnerableFile(c store.CorrelationRecord, codeByID map[int64]store.CodeFindingRecord) *Recommendation {
	if c.CodeFindingID == nil {
		return nil
	}
	secret, ok := codeByID[*c.CodeFindingID]
	if !ok {
		return nil
	}

	refs := []int64{secret.ID}
	vulnDesc, fixSuffix := "a code vulnerability", ""
	if c.SourceFindingID != nil {
		if vuln, ok := codeByID[*c.SourceFindingID]; ok {
			refs = append(refs, vuln.ID)
			vulnDesc = fmt.Sprintf("a %s %s vulnerability on line %d", vuln.Severity, vuln.RuleID, vuln.Line)
			fixSuffix = fmt.Sprintf(", and fix the %s finding on line %d", vuln.RuleID, vuln.Line)
		}
	}

	return &Recommendation{
		Priority: "CRITICAL",
		Title:    fmt.Sprintf("Exposed credential in exploitable file: %s", shortPath(secret.File)),
		Context: fmt.Sprintf(
			"A %s secret on line %d of %s sits in the same file as %s. "+
				"An attacker exploiting the vulnerability may also reach the credential.",
			secret.RuleID, secret.Line, secret.File, vulnDesc,
		),
		Action:      fmt.Sprintf("Rotate the credential immediately, move it out of the source code%s before redeploying.", fixSuffix),
		Effort:      EffortImmediate,
		FindingRefs: refs,
	}
}

func secretUsingVulnerablePackage(c store.CorrelationRecord, codeByID map[int64]store.CodeFindingRecord, depByID map[int64]store.DepFindingRecord) *Recommendation {
	if c.CodeFindingID == nil || c.DepFindingID == nil {
		return nil
	}
	secret, ok := codeByID[*c.CodeFindingID]
	if !ok {
		return nil
	}
	dep, ok := depByID[*c.DepFindingID]
	if !ok {
		return nil
	}

	upgrade := fmt.Sprintf("upgrade %s (no fixed version is published yet; consider replacing it)", dep.Package)
	if dep.FixedVersion != "" {
		upgrade = fmt.Sprintf("upgrade %s from %s to %s", dep.Package, dep.Version, dep.FixedVersion)
	}

	return &Recommendation{
		Priority: "CRITICAL",
		Title:    fmt.Sprintf("Secret in a file that imports vulnerable %s: %s", dep.Package, shortPath(secret.File)),
		Context: fmt.Sprintf(
			"%s contains a %s secret on line %d and imports %s %s, which has %s (%s). "+
				"Code that handles the credential depends on a package with a known vulnerability.",
			secret.File, secret.RuleID, secret.Line, dep.Package, dep.Version, dep.CVEID, dep.Severity,
		),
		Action:      fmt.Sprintf("Rotate the credential and move it out of the source code, then %s.", upgrade),
		Effort:      EffortImmediate,
		FindingRefs: []int64{secret.ID, dep.ID},
	}
}

func multipleVulnsInSameFile(c store.CorrelationRecord, codeByID map[int64]store.CodeFindingRecord) *Recommendation {
	if c.CodeFindingID == nil {
		return nil
	}
	anchor, ok := codeByID[*c.CodeFindingID]
	if !ok {
		return nil
	}

	refs := []int64{anchor.ID}
	if c.TargetFindingID != nil {
		refs = append(refs, *c.TargetFindingID)
	}

	return &Recommendation{
		Priority: anchor.Severity,
		Title:    fmt.Sprintf("Multiple vulnerabilities concentrated in %s", shortPath(anchor.File)),
		Context: fmt.Sprintf(
			"Multiple vulnerabilities in %s suggest it may need a broader security review "+
				"beyond fixing individual findings.",
			anchor.File,
		),
		Action:      fmt.Sprintf("Review %s holistically — consider a focused security review of this module.", anchor.File),
		Effort:      EffortLongTerm,
		FindingRefs: refs,
	}
}

func vulnCodeInVulnerableFile(c store.CorrelationRecord, codeByID map[int64]store.CodeFindingRecord, depByID map[int64]store.DepFindingRecord) *Recommendation {
	if c.CodeFindingID == nil || c.DepFindingID == nil {
		return nil
	}
	code, ok := codeByID[*c.CodeFindingID]
	if !ok {
		return nil
	}
	dep, ok := depByID[*c.DepFindingID]
	if !ok {
		return nil
	}

	fixMsg := fmt.Sprintf("Fix the %s finding in %s and upgrade %s.", code.RuleID, code.File, dep.Package)
	if dep.FixedVersion != "" {
		fixMsg = fmt.Sprintf("Fix the %s finding in %s and upgrade %s to %s.", code.RuleID, code.File, dep.Package, dep.FixedVersion)
	}

	return &Recommendation{
		Priority: code.Severity,
		Title:    fmt.Sprintf("Vulnerable code using vulnerable dependency in %s", shortPath(code.File)),
		Context: fmt.Sprintf(
			"%s contains a %s code vulnerability and imports %s@%s which has a known CVE. "+
				"Both issues compound each other.",
			code.File, code.Severity, dep.Package, dep.Version,
		),
		Action:      fixMsg,
		Effort:      EffortShortTerm,
		FindingRefs: []int64{code.ID, dep.ID},
	}
}

// packageFlags records which package rules applied to a package name.
type packageFlags struct {
	// confirmed is true when Trivy and OSV-Scanner both flagged the package.
	confirmed bool
}

// vulnerablePackage is the one recommendation for a vulnerable package,
// covering every installed version and every package rule that applied.
func vulnerablePackage(name string, findings []store.DepFindingRecord, confirmed bool) *Recommendation {
	if len(findings) == 0 {
		return nil
	}

	worst := findings[0]
	// upgradeTo maps each installed version to the lowest release that fixes
	// all of its known vulnerabilities, or "" if one of them has no fix.
	upgradeTo := map[string]string{}
	unfixed := map[string]bool{}
	ids := map[string]map[string]bool{} // scanner → distinct advisory IDs
	refs := make([]int64, 0, len(findings))
	for _, f := range findings {
		refs = append(refs, f.ID)
		if priorityOrder(f.Severity) > priorityOrder(worst.Severity) {
			worst = f
		}
		fix := nearestFix(f.Version, f.FixedVersion)
		if fix == "" {
			unfixed[f.Version] = true
		}
		if cur, ok := upgradeTo[f.Version]; !ok || compareVersions(fix, cur) > 0 {
			upgradeTo[f.Version] = fix
		}
		if ids[f.Scanner] == nil {
			ids[f.Scanner] = map[string]bool{}
		}
		ids[f.Scanner][f.CVEID] = true
	}
	// Trivy and OSV-Scanner can name one vulnerability differently, so the
	// larger of their counts is used rather than the sum.
	count := 0
	for _, set := range ids {
		count = max(count, len(set))
	}
	versions := sortedNames(upgradeTo)
	sort.SliceStable(versions, func(i, j int) bool { return compareVersions(versions[i], versions[j]) < 0 })
	for v := range unfixed {
		upgradeTo[v] = ""
	}

	advisory := worst.CVEID
	if advisory == "" {
		advisory = "an advisory"
	}
	confirmedNote := ""
	if confirmed {
		confirmedNote = " Both Trivy and OSV-Scanner report it."
	}
	vulns := fmt.Sprintf("%d known vulnerabilit%s", count, map[bool]string{true: "y", false: "ies"}[count == 1])

	if len(versions) == 1 {
		action := fmt.Sprintf("Not every vulnerability has a fixed release; consider replacing %s.", name)
		if fix := upgradeTo[worst.Version]; fix != "" {
			action = fmt.Sprintf("Upgrade %s from %s to %s.", name, worst.Version, fix)
		}
		return &Recommendation{
			Priority:    worst.Severity,
			Title:       fmt.Sprintf("Upgrade %s %s", name, worst.Version),
			Context:     fmt.Sprintf("%s %s has %s; the worst is %s (%s).%s", name, worst.Version, vulns, advisory, worst.Severity, confirmedNote),
			Action:      action,
			Effort:      EffortShortTerm,
			FindingRefs: refs,
			Rule:        "vulnerable_package",
		}
	}

	var steps []string
	for _, v := range versions {
		if fix := upgradeTo[v]; fix != "" {
			steps = append(steps, fmt.Sprintf("%s to %s", v, fix))
		} else {
			steps = append(steps, v+" (no fix published)")
		}
	}
	return &Recommendation{
		Priority: worst.Severity,
		Title:    fmt.Sprintf("Upgrade %s (%d vulnerable versions installed)", name, len(versions)),
		Context: fmt.Sprintf("%s is installed at versions %s, with %s between them; the worst is %s (%s).%s",
			name, strings.Join(versions, ", "), vulns, advisory, worst.Severity, confirmedNote),
		Action: fmt.Sprintf("Upgrade %s. Copies installed by other packages are upgraded by updating "+
			"the package that depends on them, or with an override in your package manager.", strings.Join(steps, "; ")),
		Effort:      EffortShortTerm,
		FindingRefs: refs,
		Rule:        "vulnerable_package",
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// nearestFix picks, from a scanner's list of fixed releases such as
// "1.2.6, 0.2.4" (one per release line), the lowest one above the installed
// version. It returns "" when no release is listed.
func nearestFix(installed, fixed string) string {
	best := ""
	for _, c := range strings.Split(fixed, ",") {
		c = strings.TrimSpace(c)
		if c == "" || compareVersions(c, installed) <= 0 {
			continue
		}
		if best == "" || compareVersions(c, best) < 0 {
			best = c
		}
	}
	if best == "" {
		// Nothing parsed as newer; show the scanner's own text.
		return strings.TrimSpace(fixed)
	}
	return best
}

// compareVersions compares dotted versions numerically, so 0.0.10 sorts
// after 0.0.8. A pre-release (1.0.0-beta) sorts before its release, and ""
// before everything.
func compareVersions(a, b string) int {
	if a == "" || b == "" {
		return strings.Compare(a, b)
	}
	ac, apre, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	bc, bpre, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	ap, bp := strings.Split(ac, "."), strings.Split(bc, ".")
	for i := 0; i < max(len(ap), len(bp)); i++ {
		var x, y int
		if i < len(ap) {
			x, _ = strconv.Atoi(ap[i])
		}
		if i < len(bp) {
			y, _ = strconv.Atoi(bp[i])
		}
		if x != y {
			return cmp.Compare(x, y)
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	return strings.Compare(apre, bpre)
}

func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// shortPath keeps titles readable: a path of up to three components is shown
// whole, a longer one as its last two.
func shortPath(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, "\\", "/"), "/")
	if len(parts) <= 3 {
		return path
	}
	return "..." + "/" + strings.Join(parts[len(parts)-2:], "/")
}

// priorityOrder maps severity strings to numeric order for sorting.
func priorityOrder(p string) int {
	switch strings.ToUpper(p) {
	case "SEVERE", "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
