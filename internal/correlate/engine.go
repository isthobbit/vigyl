package correlate

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/isthobbit/vigyl/internal/imports"
	"github.com/isthobbit/vigyl/internal/paths"
	"github.com/isthobbit/vigyl/internal/store"
)

// Engine runs correlation rules against a set of scan findings and
// writes correlations and risk scores back to the database.
type Engine struct {
	db      *store.DB
	weights map[string]float64
}

// New creates a new Engine. weights overrides default rule weights — pass nil
// to use DefaultRules weights unchanged.
func New(db *store.DB, weights map[string]float64) *Engine {
	return &Engine{db: db, weights: Weights(weights)}
}

// Weights returns the default rule weights with overrides applied.
func Weights(overrides map[string]float64) map[string]float64 {
	w := make(map[string]float64, len(DefaultRules))
	for _, r := range DefaultRules {
		w[r.Reason] = r.Weight
	}
	for k, v := range overrides {
		w[k] = v
	}
	return w
}

// Run correlates all findings in the input, persists the correlations and
// risk scores, and returns the scored files and packages for display.
func (e *Engine) Run(input Input) (*Result, error) {
	a := analyse(input, e.weights)

	records := make([]store.CorrelationRecord, 0, len(a.correlations))
	for _, c := range a.correlations {
		records = append(records, store.CorrelationRecord{
			ScanID:           input.ScanID,
			CodeFindingID:    c.CodeFindingID,
			DepFindingID:     c.DepFindingID,
			Reason:           c.Reason,
			CorrelationScore: c.Score,
			Directional:      c.Directional,
			SourceFindingID:  c.SourceFindingID,
			TargetFindingID:  c.TargetFindingID,
		})
	}
	if err := e.db.SaveCorrelations(input.ScanID, records); err != nil {
		return nil, fmt.Errorf("saving correlations: %w", err)
	}

	var fileScores, pkgScores []store.RiskScoreRecord
	for _, r := range a.result.Risks {
		name := r.Name
		rec := store.RiskScoreRecord{ScanID: input.ScanID, Score: r.Score, ContributingFindingCount: a.findingCount[r.Kind+"|"+r.Name]}
		if r.Kind == "file" {
			rec.File = &name
			fileScores = append(fileScores, rec)
		} else {
			rec.Package = &name
			pkgScores = append(pkgScores, rec)
		}
	}
	if err := e.db.SaveRiskScores(input.ScanID, fileScores, pkgScores, a.result.Overall); err != nil {
		return nil, fmt.Errorf("saving risk scores: %w", err)
	}
	if err := e.db.UpdateScanRiskScore(input.ScanID, a.result.Overall); err != nil {
		return nil, fmt.Errorf("updating scan risk score: %w", err)
	}
	return a.result, nil
}

// ── Analysis ─────────────────────────────────────────────────────────────────

// pkgInfo gathers every finding for one package version across scanners.
type pkgInfo struct {
	key       string // name@version
	name      string
	version   string
	ecosystem string
	manifests []string
	scanners  map[string]bool
	// advisories maps each distinct advisory ID to its findings, one per scanner.
	advisories map[string][]store.DepFindingRecord
	worst      store.DepFindingRecord
	usage      imports.Usage
}

// vulnCount is how many distinct vulnerabilities a package has. Trivy and
// OSV-Scanner often name the same vulnerability differently (a CVE ID versus
// a GHSA or PYSEC ID), so counting the union of IDs would double-count.
// The larger of the two scanners' own counts never overstates.
func (p *pkgInfo) vulnCount() int {
	per := map[string]int{}
	for _, findings := range p.advisories {
		seen := map[string]bool{}
		for _, f := range findings {
			if !seen[f.Scanner] {
				per[f.Scanner]++
				seen[f.Scanner] = true
			}
		}
	}
	n := 0
	for _, c := range per {
		if c > n {
			n = c
		}
	}
	return n
}

type analysis struct {
	weights      map[string]float64
	correlations []correlation
	result       *Result
	findingCount map[string]int

	fileOf        map[int64]string // code finding ID → normalised path
	codeByFile    map[string][]store.CodeFindingRecord
	pkgs          map[string]*pkgInfo
	pkgOrder      []string
	vulnImportsOf map[string][]*pkgInfo // file → vulnerable packages it imports

	// bonuses records each rule that applied to a file or package, keyed so
	// the same link is only counted once (see addBonus).
	bonuses map[string]map[string]float64
	why     map[string][]string
}

func analyse(input Input, weights map[string]float64) *analysis {
	a := &analysis{
		weights:       weights,
		findingCount:  map[string]int{},
		fileOf:        map[int64]string{},
		codeByFile:    map[string][]store.CodeFindingRecord{},
		pkgs:          map[string]*pkgInfo{},
		vulnImportsOf: map[string][]*pkgInfo{},
		bonuses:       map[string]map[string]float64{},
		why:           map[string][]string{},
	}

	for _, f := range input.CodeFindings {
		file := paths.Rel(input.Root, f.File)
		a.fileOf[f.ID] = file
		a.codeByFile[file] = append(a.codeByFile[file], f)
	}
	for _, d := range input.DepFindings {
		key := d.Package + "@" + d.Version
		p, ok := a.pkgs[key]
		if !ok {
			p = &pkgInfo{key: key, name: d.Package, version: d.Version, ecosystem: d.Ecosystem,
				scanners: map[string]bool{}, advisories: map[string][]store.DepFindingRecord{}, worst: d}
			a.pkgs[key] = p
			a.pkgOrder = append(a.pkgOrder, key)
		}
		p.scanners[d.Scanner] = true
		if d.Manifest != "" && !contains(p.manifests, d.Manifest) {
			p.manifests = append(p.manifests, d.Manifest)
		}
		id := d.CVEID
		if id == "" {
			id = "unnamed advisory"
		}
		p.advisories[id] = append(p.advisories[id], d)
		if rank(d.Severity) > rank(p.worst.Severity) {
			p.worst = d
		}
	}
	sort.Strings(a.pkgOrder)

	// Which files import each vulnerable package?
	for _, key := range a.pkgOrder {
		p := a.pkgs[key]
		if input.Imports == nil {
			continue
		}
		manifests := p.manifests
		if len(manifests) == 0 {
			manifests = []string{""}
		}
		files := map[string]bool{}
		for _, m := range manifests {
			u := input.Imports.Importers(p.ecosystem, p.name, m)
			p.usage.Known = p.usage.Known || u.Known
			for _, f := range u.Files {
				files[f] = true
			}
		}
		for f := range files {
			p.usage.Files = append(p.usage.Files, f)
			a.vulnImportsOf[f] = append(a.vulnImportsOf[f], p)
		}
		sort.Strings(p.usage.Files)
	}

	a.secretInVulnerableFile()
	a.linkCodeToVulnerableImports()
	a.scannerAgreement()
	a.multipleCVEsInSamePackage()
	a.multipleVulnsInSameFile()
	a.result = a.score()
	return a
}

func (a *analysis) add(c correlation) {
	a.correlations = append(a.correlations, c)
}

// addBonus records that rule applies to entry (a "file|path" or
// "package|name@version" key). linkKey distinguishes separate links under
// the same rule; a repeated rule+linkKey is counted once, so ten secrets in
// one file do not count ten times for the same fact.
func (a *analysis) addBonus(entry, rule, linkKey string) {
	if a.bonuses[entry] == nil {
		a.bonuses[entry] = map[string]float64{}
	}
	a.bonuses[entry][rule+"|"+linkKey] = a.weights[rule]
}

func (a *analysis) explain(entry, line string) {
	if !contains(a.why[entry], line) {
		a.why[entry] = append(a.why[entry], line)
	}
}

// ── Rules ────────────────────────────────────────────────────────────────────

// secretInVulnerableFile: a secret and a SAST finding in the same file.
func (a *analysis) secretInVulnerableFile() {
	for _, file := range sortedKeys(a.codeByFile) {
		secrets, sasts := split(a.codeByFile[file])
		if len(secrets) == 0 || len(sasts) == 0 {
			continue
		}
		worst := worstCode(sasts)
		for _, s := range secrets {
			sID, wID := s.ID, worst.ID
			a.add(correlation{CodeFindingID: &sID, Reason: ReasonSecretInVulnerableFile,
				Score: a.weights[ReasonSecretInVulnerableFile], Directional: true,
				SourceFindingID: &wID, TargetFindingID: &sID})
		}
		a.addBonus("file|"+file, ReasonSecretInVulnerableFile, "")
		a.explain("file|"+file, "secret in the same file as a code vulnerability")
	}
}

// linkCodeToVulnerableImports: secrets and SAST findings in files that import
// a package with a known vulnerability.
func (a *analysis) linkCodeToVulnerableImports() {
	for _, file := range sortedKeys(a.codeByFile) {
		pkgs := a.vulnImportsOf[file]
		if len(pkgs) == 0 {
			continue
		}
		secrets, sasts := split(a.codeByFile[file])
		for _, p := range pkgs {
			depID := p.worst.ID
			for _, s := range secrets {
				sID := s.ID
				a.add(correlation{CodeFindingID: &sID, DepFindingID: &depID, Reason: ReasonSecretUsingVulnerableDep,
					Score: a.weights[ReasonSecretUsingVulnerableDep], Directional: true,
					SourceFindingID: &depID, TargetFindingID: &sID})
			}
			for _, s := range sasts {
				sID := s.ID
				a.add(correlation{CodeFindingID: &sID, DepFindingID: &depID, Reason: ReasonVulnCodeInVulnerableFile,
					Score: a.weights[ReasonVulnCodeInVulnerableFile], Directional: true,
					SourceFindingID: &depID, TargetFindingID: &sID})
			}
			if len(secrets) > 0 {
				a.addBonus("file|"+file, ReasonSecretUsingVulnerableDep, p.key)
				a.addBonus("package|"+p.key, ReasonSecretUsingVulnerableDep, "")
				a.explain("package|"+p.key, file+", which imports it, contains a secret")
			}
			if len(sasts) > 0 {
				a.addBonus("file|"+file, ReasonVulnCodeInVulnerableFile, p.key)
				a.addBonus("package|"+p.key, ReasonVulnCodeInVulnerableFile, "")
				a.explain("package|"+p.key, file+", which imports it, has a code vulnerability")
			}
			a.explain("file|"+file, "imports "+describePackage(p))
		}
	}
}

// scannerAgreement: Trivy and OSV-Scanner agree. When they report the same
// advisory, that is cve_confirmed_by_multiple_scanners; when they only agree
// on the package (different advisory IDs), package_confirmed_by_multiple_scanners.
func (a *analysis) scannerAgreement() {
	for _, key := range a.pkgOrder {
		p := a.pkgs[key]
		if !p.scanners["trivy"] || !p.scanners["osv"] {
			continue
		}
		confirmed := false
		for _, id := range sortedKeys(p.advisories) {
			t, o := byScanner(p.advisories[id], "trivy"), byScanner(p.advisories[id], "osv")
			if t == nil || o == nil {
				continue
			}
			tID, oID := t.ID, o.ID
			a.add(correlation{DepFindingID: &tID, Reason: ReasonCVEConfirmed, Score: a.weights[ReasonCVEConfirmed],
				Directional: true, SourceFindingID: &tID, TargetFindingID: &oID})
			confirmed = true
		}
		if confirmed {
			a.addBonus("package|"+key, ReasonCVEConfirmed, "")
		} else {
			t, o := firstByScanner(p, "trivy"), firstByScanner(p, "osv")
			tID, oID := t.ID, o.ID
			a.add(correlation{DepFindingID: &tID, Reason: ReasonPackageConfirmed, Score: a.weights[ReasonPackageConfirmed],
				SourceFindingID: &tID, TargetFindingID: &oID})
			a.addBonus("package|"+key, ReasonPackageConfirmed, "")
		}
	}
}

// multipleCVEsInSamePackage: more than one distinct advisory for a package.
// The same advisory reported by both scanners counts once.
func (a *analysis) multipleCVEsInSamePackage() {
	for _, key := range a.pkgOrder {
		p := a.pkgs[key]
		ids := sortedKeys(p.advisories)
		if p.vulnCount() < 2 {
			continue
		}
		anchorID := p.advisories[ids[0]][0].ID
		for _, id := range ids[1:] {
			fID := p.advisories[id][0].ID
			a.add(correlation{DepFindingID: &anchorID, Reason: ReasonMultipleCVEsInSamePackage,
				Score: a.weights[ReasonMultipleCVEsInSamePackage], SourceFindingID: &anchorID, TargetFindingID: &fID})
		}
		a.addBonus("package|"+key, ReasonMultipleCVEsInSamePackage, "")
	}
}

// multipleVulnsInSameFile: more than one SAST finding in a file.
func (a *analysis) multipleVulnsInSameFile() {
	for _, file := range sortedKeys(a.codeByFile) {
		_, sasts := split(a.codeByFile[file])
		if len(sasts) < 2 {
			continue
		}
		anchorID := sasts[0].ID
		for _, s := range sasts[1:] {
			sID := s.ID
			a.add(correlation{CodeFindingID: &anchorID, Reason: ReasonMultipleVulnsInSameFile,
				Score: a.weights[ReasonMultipleVulnsInSameFile], SourceFindingID: &anchorID, TargetFindingID: &sID})
		}
		a.addBonus("file|"+file, ReasonMultipleVulnsInSameFile, "")
		a.explain("file|"+file, fmt.Sprintf("%d code vulnerabilities in this file", len(sasts)))
	}
}

// ── Scoring ──────────────────────────────────────────────────────────────────

// score gives every file and package a base score (its worst severity) plus
// the bonuses of the rules that applied, capped at base + 2.
func (a *analysis) score() *Result {
	res := &Result{}
	var scores []float64

	for _, file := range sortedKeys(a.codeByFile) {
		findings := a.codeByFile[file]
		entry := "file|" + file
		base := 0.0
		for _, f := range findings {
			base = math.Max(base, rank(f.Severity))
		}
		why := append(describeCode(findings), a.why[entry]...)
		r := a.risk("file", file, base, entry, why)
		a.findingCount[entry] = len(findings)
		res.Risks = append(res.Risks, r)
		scores = append(scores, r.Score)
	}

	for _, key := range a.pkgOrder {
		p := a.pkgs[key]
		entry := "package|" + key
		why := []string{describeAdvisories(p)}
		if p.scanners["trivy"] && p.scanners["osv"] {
			why = append(why, "reported by both Trivy and OSV-Scanner")
		}
		why = append(why, describeUsage(p))
		why = append(why, a.why[entry]...)
		r := a.risk("package", key, rank(p.worst.Severity), entry, why)
		r.pkg, r.Versions = p.name, []string{p.version}
		switch {
		case !p.usage.Known:
			r.reach = 1
		case len(p.usage.Files) == 0:
			r.reach = 2
		}
		a.findingCount[entry] = p.vulnCount()
		res.Risks = append(res.Risks, r)
		scores = append(scores, r.Score)
	}

	sort.SliceStable(res.Risks, func(i, j int) bool {
		if res.Risks[i].Score != res.Risks[j].Score {
			return res.Risks[i].Score > res.Risks[j].Score
		}
		// At equal scores, what the code is known to use comes first. This
		// only orders the list; unimported packages are not scored lower.
		if res.Risks[i].reach != res.Risks[j].reach {
			return res.Risks[i].reach < res.Risks[j].reach
		}
		return res.Risks[i].Name < res.Risks[j].Name
	})
	res.Overall = calculateOverallScore(scores)
	return res
}

// Top returns the n highest risks that scored above zero, with every
// vulnerable version of a package shown as one entry, ranked by its
// highest-scoring version. The result's Risks are left as they are.
func (r *Result) Top(n int) []Risk {
	if r == nil {
		return []Risk{}
	}
	out := []Risk{}
	group := map[string]int{} // package name → index in out
	others := map[string][]string{}
	for _, risk := range r.Risks {
		if risk.Score <= 0 {
			continue
		}
		if risk.Kind == "package" && risk.pkg != "" {
			if i, ok := group[risk.pkg]; ok {
				out[i].Versions = append(out[i].Versions, risk.Versions...)
				others[risk.pkg] = append(others[risk.pkg], fmt.Sprintf("%s (score %.1f)", risk.Versions[0], risk.Score))
				continue
			}
			group[risk.pkg] = len(out)
		}
		risk.Why = append([]string(nil), risk.Why...)
		risk.Versions = append([]string(nil), risk.Versions...)
		out = append(out, risk)
	}
	for name, i := range group {
		if len(out[i].Versions) < 2 {
			continue
		}
		// The explanation is the top version's; say so and list the rest.
		out[i].Name = name + "@" + strings.Join(out[i].Versions, ", ")
		out[i].Why[0] = out[i].Versions[0] + ": " + out[i].Why[0]
		out[i].Why = append(out[i].Why, "also vulnerable: "+strings.Join(others[name], ", "))
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (a *analysis) risk(kind, name string, base float64, entry string, why []string) Risk {
	bonus := 0.0
	for _, w := range a.bonuses[entry] {
		bonus += w
	}
	score := math.Min(base+bonus, base+2.0)
	score = math.Round(score*10) / 10
	return Risk{Kind: kind, Name: name, Score: score, Band: BandFor(score), Why: why}
}

// calculateOverallScore computes the weighted average with peak penalty.
func calculateOverallScore(scores []float64) float64 {
	if len(scores) == 0 {
		return 0.0
	}
	var sum, peak float64
	for _, s := range scores {
		sum += s
		if s > peak {
			peak = s
		}
	}
	avg := sum / float64(len(scores))
	return math.Min(avg+peak*0.3, 10.0)
}

// ── Explanations ─────────────────────────────────────────────────────────────

// describeCode lists a file's findings, worst first, up to three.
func describeCode(findings []store.CodeFindingRecord) []string {
	sorted := append([]store.CodeFindingRecord(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		si, sj := sorted[i].Scanner == "secrets", sorted[j].Scanner == "secrets"
		if si != sj {
			return si // a leaked secret matters more than its severity label suggests
		}
		return rank(sorted[i].Severity) > rank(sorted[j].Severity)
	})
	var lines []string
	for _, f := range sorted {
		line := fmt.Sprintf("%s %s (line %d)", strings.ToUpper(f.Severity), shortRule(f.RuleID), f.Line)
		if f.Scanner == "secrets" {
			line = fmt.Sprintf("secret: %s (line %d)", f.RuleID, f.Line)
		}
		// Different rules often share a short name for the same issue.
		if !contains(lines, line) {
			lines = append(lines, line)
		}
	}
	if len(lines) > 3 {
		return append(lines[:3], fmt.Sprintf("+%d more finding(s)", len(lines)-3))
	}
	return lines
}

func describeAdvisories(p *pkgInfo) string {
	fix := ""
	if p.worst.FixedVersion != "" {
		fix = ", fixed in " + p.worst.FixedVersion
	}
	worst := p.worst.CVEID
	if worst == "" {
		worst = "an advisory"
	}
	if n := p.vulnCount(); n > 1 {
		return fmt.Sprintf("%d known vulnerabilities, worst %s (%s)%s", n, worst, strings.ToUpper(p.worst.Severity), fix)
	}
	return fmt.Sprintf("%s (%s)%s", worst, strings.ToUpper(p.worst.Severity), fix)
}

// describePackage is how a file's explanation refers to an imported package.
func describePackage(p *pkgInfo) string {
	return p.name + " " + p.version + " — " + describeAdvisories(p)
}

func describeUsage(p *pkgInfo) string {
	switch {
	case !p.usage.Known:
		return "import use unknown for " + p.ecosystem + " packages"
	case len(p.usage.Files) == 0:
		return "no direct import found; it may still be used by another dependency"
	case len(p.usage.Files) <= 3:
		return "imported by " + strings.Join(p.usage.Files, ", ")
	default:
		return fmt.Sprintf("imported by %s and %d more", strings.Join(p.usage.Files[:3], ", "), len(p.usage.Files)-3)
	}
}

// shortRule turns a long rule ID such as
// python.lang.security.audit.eval-detected.eval-detected into eval-detected.
func shortRule(id string) string {
	if i := strings.LastIndex(id, "."); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func rank(severity string) float64 { return severityRank[strings.ToUpper(severity)] }

func split(findings []store.CodeFindingRecord) (secrets, sasts []store.CodeFindingRecord) {
	for _, f := range findings {
		switch f.Scanner {
		case "secrets":
			secrets = append(secrets, f)
		case "sast":
			sasts = append(sasts, f)
		}
	}
	return secrets, sasts
}

func worstCode(findings []store.CodeFindingRecord) store.CodeFindingRecord {
	worst := findings[0]
	for _, f := range findings[1:] {
		if rank(f.Severity) > rank(worst.Severity) {
			worst = f
		}
	}
	return worst
}

func byScanner(findings []store.DepFindingRecord, scanner string) *store.DepFindingRecord {
	for i := range findings {
		if findings[i].Scanner == scanner {
			return &findings[i]
		}
	}
	return nil
}

func firstByScanner(p *pkgInfo, scanner string) store.DepFindingRecord {
	for _, id := range sortedKeys(p.advisories) {
		if f := byScanner(p.advisories[id], scanner); f != nil {
			return *f
		}
	}
	return store.DepFindingRecord{}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
