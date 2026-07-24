package recommend

import (
	"fmt"
	"sort"
	"strings"

	"github.com/isthobbit/vigil/internal/store"
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

	for _, c := range correlations {
		var rec *Recommendation

		switch c.Reason {
		case "secret_in_vulnerable_file":
			rec = secretInVulnerableFile(c, codeByID)
		case "cve_confirmed_by_multiple_scanners":
			rec = cveConfirmedByMultipleScanners(c, depByID)
		case "secret_and_vuln_in_same_file":
			rec = secretAndVulnInSameFile(c, codeByID)
		case "multiple_cves_in_same_package":
			rec = multipleCVEsInSamePackage(c, depByID)
		case "multiple_vulns_in_same_file":
			rec = multipleVulnsInSameFile(c, codeByID)
		case "vuln_code_in_vulnerable_file":
			rec = vulnCodeInVulnerableFile(c, codeByID, depByID)
		case "package_confirmed_by_multiple_scanners":
			rec = packageConfirmedByMultipleScanners(c, depByID)
		}

		if rec != nil {
			rec.Rule = c.Reason
			recs = append(recs, *rec)
		}
	}

	// Sort by effort (IMMEDIATE first) then by priority (CRITICAL before HIGH etc).
	sort.Slice(recs, func(i, j int) bool {
		ei := effortOrder[recs[i].Effort]
		ej := effortOrder[recs[j].Effort]
		if ei != ej {
			return ei < ej
		}
		return priorityOrder(recs[i].Priority) > priorityOrder(recs[j].Priority)
	})

	return recs
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
	if c.SourceFindingID != nil {
		refs = append(refs, *c.SourceFindingID)
	}

	return &Recommendation{
		Priority: "CRITICAL",
		Title:    fmt.Sprintf("Exposed credential in exploitable file: %s", shortPath(secret.File)),
		Context: fmt.Sprintf(
			"A secret was found in %s which also contains a %s vulnerability. "+
				"An attacker exploiting the vulnerability may also access the credential.",
			secret.File, secret.Severity,
		),
		Action:      fmt.Sprintf("Rotate the credential immediately, then fix the vulnerability in %s before redeploying.", secret.File),
		Effort:      EffortImmediate,
		FindingRefs: refs,
	}
}

func cveConfirmedByMultipleScanners(c store.CorrelationRecord, depByID map[int64]store.DepFindingRecord) *Recommendation {
	if c.DepFindingID == nil {
		return nil
	}
	dep, ok := depByID[*c.DepFindingID]
	if !ok {
		return nil
	}

	fixMsg := "No fix currently available — consider replacing this dependency."
	if dep.FixedVersion != "" {
		fixMsg = fmt.Sprintf("Upgrade %s from %s to %s.", dep.Package, dep.Version, dep.FixedVersion)
	}

	refs := []int64{dep.ID}
	if c.TargetFindingID != nil {
		refs = append(refs, *c.TargetFindingID)
	}

	return &Recommendation{
		Priority: dep.Severity,
		Title:    fmt.Sprintf("CVE %s confirmed in %s", dep.CVEID, dep.Package),
		Context: fmt.Sprintf(
			"Both Trivy and OSV independently flagged %s in %s@%s, "+
				"increasing confidence it is exploitable in your environment.",
			dep.CVEID, dep.Package, dep.Version,
		),
		Action:      fixMsg,
		Effort:      EffortShortTerm,
		FindingRefs: refs,
	}
}

func secretAndVulnInSameFile(c store.CorrelationRecord, codeByID map[int64]store.CodeFindingRecord) *Recommendation {
	if c.CodeFindingID == nil {
		return nil
	}
	secret, ok := codeByID[*c.CodeFindingID]
	if !ok {
		return nil
	}

	refs := []int64{secret.ID}
	actionSuffix := ""
	if c.TargetFindingID != nil {
		if vuln, ok := codeByID[*c.TargetFindingID]; ok {
			refs = append(refs, vuln.ID)
			actionSuffix = fmt.Sprintf(" and address the %s finding on line %d.", vuln.RuleID, vuln.Line)
		}
	}

	return &Recommendation{
		Priority: "HIGH",
		Title:    fmt.Sprintf("Secret and vulnerability co-located in %s", shortPath(secret.File)),
		Context: fmt.Sprintf(
			"A leaked credential and a code vulnerability exist in %s, "+
				"creating two independent attack vectors.",
			secret.File,
		),
		Action:      "Rotate the credential" + actionSuffix,
		Effort:      EffortShortTerm,
		FindingRefs: refs,
	}
}

func multipleCVEsInSamePackage(c store.CorrelationRecord, depByID map[int64]store.DepFindingRecord) *Recommendation {
	if c.DepFindingID == nil {
		return nil
	}
	dep, ok := depByID[*c.DepFindingID]
	if !ok {
		return nil
	}

	fixMsg := fmt.Sprintf("Replace %s — no fix version is available.", dep.Package)
	if dep.FixedVersion != "" {
		fixMsg = fmt.Sprintf("Upgrade %s to %s or replace it if no fix is available.", dep.Package, dep.FixedVersion)
	}

	refs := []int64{dep.ID}
	if c.TargetFindingID != nil {
		refs = append(refs, *c.TargetFindingID)
	}

	return &Recommendation{
		Priority: dep.Severity,
		Title:    fmt.Sprintf("Multiple vulnerabilities in %s@%s", dep.Package, dep.Version),
		Context: fmt.Sprintf(
			"%s@%s has multiple known CVEs. Continued use increases your attack surface.",
			dep.Package, dep.Version,
		),
		Action:      fixMsg,
		Effort:      EffortShortTerm,
		FindingRefs: refs,
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

func packageConfirmedByMultipleScanners(c store.CorrelationRecord, depByID map[int64]store.DepFindingRecord) *Recommendation {
	if c.DepFindingID == nil {
		return nil
	}
	dep, ok := depByID[*c.DepFindingID]
	if !ok {
		return nil
	}

	fixMsg := fmt.Sprintf("Review and update %s — no fix version is available.", dep.Package)
	if dep.FixedVersion != "" {
		fixMsg = fmt.Sprintf("Upgrade %s from %s to %s.", dep.Package, dep.Version, dep.FixedVersion)
	}

	refs := []int64{dep.ID}
	if c.TargetFindingID != nil {
		refs = append(refs, *c.TargetFindingID)
	}

	return &Recommendation{
		Priority: dep.Severity,
		Title:    fmt.Sprintf("Vulnerability in %s confirmed by multiple scanners", dep.Package),
		Context: fmt.Sprintf(
			"%s@%s was flagged independently by both Trivy and OSV, "+
				"increasing confidence the vulnerability is real and exploitable.",
			dep.Package, dep.Version,
		),
		Action:      fixMsg,
		Effort:      EffortShortTerm,
		FindingRefs: refs,
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// shortPath returns the last two path components to keep titles readable.
func shortPath(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, "\\", "/"), "/")
	if len(parts) <= 2 {
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
