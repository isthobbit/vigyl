package correlate

import (
	"fmt"
	"math"
	"strings"

	"github.com/isthobbit/vigil/internal/store"
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
	w := make(map[string]float64, len(DefaultRules))
	for _, r := range DefaultRules {
		w[r.Reason] = r.Weight
	}
	for k, v := range weights {
		w[k] = v
	}
	return &Engine{db: db, weights: w}
}

// Run correlates all findings in the input and persists results to the database.
func (e *Engine) Run(input Input) error {
	correlations := e.correlate(input)

	// Convert internal correlations to store records.
	storeCorrelations := make([]store.CorrelationRecord, 0, len(correlations))
	for _, c := range correlations {
		storeCorrelations = append(storeCorrelations, store.CorrelationRecord{
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

	if err := e.db.SaveCorrelations(input.ScanID, storeCorrelations); err != nil {
		return fmt.Errorf("saving correlations: %w", err)
	}

	fileScores, pkgScores, overall := e.calculateRiskScores(input, correlations)
	if err := e.db.SaveRiskScores(input.ScanID, fileScores, pkgScores, overall); err != nil {
		return fmt.Errorf("saving risk scores: %w", err)
	}

	if err := e.db.UpdateScanRiskScore(input.ScanID, overall); err != nil {
		return fmt.Errorf("updating scan risk score: %w", err)
	}

	return nil
}

// correlate runs all seven rules and returns the resulting correlations.
func (e *Engine) correlate(input Input) []correlation {
	var results []correlation

	results = append(results, e.secretInVulnerableFile(input)...)
	results = append(results, e.vulnCodeInVulnerableFile(input)...)
	results = append(results, e.cveConfirmedByMultipleScanners(input)...)
	results = append(results, e.secretAndVulnInSameFile(input)...)
	results = append(results, e.packageConfirmedByMultipleScanners(input)...)
	results = append(results, e.multipleCVEsInSamePackage(input)...)
	results = append(results, e.multipleVulnsInSameFile(input)...)

	return results
}

// ── Rule implementations ──────────────────────────────────────────────────────

// secretInVulnerableFile: a secret and a SAST finding exist in the same file.
// Directional: the SAST finding is the source (context), the secret is the target.
func (e *Engine) secretInVulnerableFile(input Input) []correlation {
	weight := e.weights["secret_in_vulnerable_file"]
	var results []correlation

	secretsByFile := groupCodeByFile(input.CodeFindings, "secrets")
	sastByFile := groupCodeByFile(input.CodeFindings, "sast")

	for file, secrets := range secretsByFile {
		sasts, ok := sastByFile[file]
		if !ok {
			continue
		}
		for _, secret := range secrets {
			secretID := secret.ID
			for _, s := range sasts {
				sastID := s.ID
				results = append(results, correlation{
					CodeFindingID:   &secretID,
					Reason:          "secret_in_vulnerable_file",
					Score:           weight,
					Directional:     true,
					SourceFindingID: &sastID,   // SAST is the context
					TargetFindingID: &secretID, // secret is the risk
				})
			}
		}
	}
	return results
}

// vulnCodeInVulnerableFile: a SAST finding in a file that imports a vulnerable dependency.
// Directional: the dep finding is the source, the SAST finding is the target.
func (e *Engine) vulnCodeInVulnerableFile(input Input) []correlation {
	weight := e.weights["vuln_code_in_vulnerable_file"]
	var results []correlation

	sastByFile := groupCodeByFile(input.CodeFindings, "sast")

	for _, dep := range input.DepFindings {
		pkgName := strings.ToLower(dep.Package)
		for file, sasts := range sastByFile {
			// Heuristic: check if the filename or path contains the package name.
			if !strings.Contains(strings.ToLower(file), pkgName) {
				continue
			}
			depID := dep.ID
			for _, s := range sasts {
				sastID := s.ID
				results = append(results, correlation{
					CodeFindingID:   &sastID,
					DepFindingID:    &depID,
					Reason:          "vuln_code_in_vulnerable_file",
					Score:           weight,
					Directional:     true,
					SourceFindingID: &depID,  // dep is the upstream context
					TargetFindingID: &sastID, // SAST is the target
				})
			}
		}
	}
	return results
}

// cveConfirmedByMultipleScanners: same CVE flagged by both Trivy and OSV.
// Directional: OSV confirms Trivy (Trivy is source, OSV is target).
func (e *Engine) cveConfirmedByMultipleScanners(input Input) []correlation {
	weight := e.weights["cve_confirmed_by_multiple_scanners"]
	var results []correlation

	trivyByCVE := make(map[string]store.DepFindingRecord)
	osvByCVE := make(map[string]store.DepFindingRecord)

	for _, d := range input.DepFindings {
		if d.CVEID == "" {
			continue
		}
		if d.Scanner == "trivy" {
			trivyByCVE[d.CVEID] = d
		} else if d.Scanner == "osv" {
			osvByCVE[d.CVEID] = d
		}
	}

	for cve, trivy := range trivyByCVE {
		osv, ok := osvByCVE[cve]
		if !ok {
			continue
		}
		trivyID := trivy.ID
		osvID := osv.ID
		results = append(results, correlation{
			DepFindingID:    &trivyID,
			Reason:          "cve_confirmed_by_multiple_scanners",
			Score:           weight,
			Directional:     true,
			SourceFindingID: &trivyID,
			TargetFindingID: &osvID,
		})
	}
	return results
}

// secretAndVulnInSameFile: a secret and a SAST finding in the same file.
// Associative: neither causes the other.
func (e *Engine) secretAndVulnInSameFile(input Input) []correlation {
	weight := e.weights["secret_and_vuln_in_same_file"]
	var results []correlation

	secretsByFile := groupCodeByFile(input.CodeFindings, "secrets")
	sastByFile := groupCodeByFile(input.CodeFindings, "sast")

	for file, secrets := range secretsByFile {
		sasts, ok := sastByFile[file]
		if !ok {
			continue
		}
		for _, secret := range secrets {
			secretID := secret.ID
			for _, s := range sasts {
				sastID := s.ID
				results = append(results, correlation{
					CodeFindingID: &secretID,
					Reason:        "secret_and_vuln_in_same_file",
					Score:         weight,
					Directional:   false,
					// Also link the SAST finding.
					SourceFindingID: &secretID,
					TargetFindingID: &sastID,
				})
			}
		}
	}
	return results
}

// packageConfirmedByMultipleScanners: same package flagged by both Trivy and OSV.
// Associative.
func (e *Engine) packageConfirmedByMultipleScanners(input Input) []correlation {
	weight := e.weights["package_confirmed_by_multiple_scanners"]
	var results []correlation

	trivyByPkg := make(map[string]store.DepFindingRecord)
	osvByPkg := make(map[string]store.DepFindingRecord)

	for _, d := range input.DepFindings {
		key := d.Package + "@" + d.Version
		if d.Scanner == "trivy" {
			trivyByPkg[key] = d
		} else if d.Scanner == "osv" {
			osvByPkg[key] = d
		}
	}

	for key, trivy := range trivyByPkg {
		osv, ok := osvByPkg[key]
		if !ok {
			continue
		}
		trivyID := trivy.ID
		osvID := osv.ID
		_ = key
		results = append(results, correlation{
			DepFindingID:    &trivyID,
			Reason:          "package_confirmed_by_multiple_scanners",
			Score:           weight,
			Directional:     false,
			SourceFindingID: &trivyID,
			TargetFindingID: &osvID,
		})
	}
	return results
}

// multipleCVEsInSamePackage: multiple CVEs found in one package.
// Associative.
func (e *Engine) multipleCVEsInSamePackage(input Input) []correlation {
	weight := e.weights["multiple_cves_in_same_package"]
	var results []correlation

	byPkg := make(map[string][]store.DepFindingRecord)
	for _, d := range input.DepFindings {
		if d.CVEID == "" {
			continue
		}
		key := d.Package + "@" + d.Version
		byPkg[key] = append(byPkg[key], d)
	}

	for _, findings := range byPkg {
		if len(findings) < 2 {
			continue
		}
		// Link each finding to the first as the anchor.
		anchor := findings[0]
		anchorID := anchor.ID
		for _, f := range findings[1:] {
			fID := f.ID
			results = append(results, correlation{
				DepFindingID:    &anchorID,
				Reason:          "multiple_cves_in_same_package",
				Score:           weight,
				Directional:     false,
				SourceFindingID: &anchorID,
				TargetFindingID: &fID,
			})
		}
	}
	return results
}

// multipleVulnsInSameFile: multiple SAST findings in one file.
// Associative.
func (e *Engine) multipleVulnsInSameFile(input Input) []correlation {
	weight := e.weights["multiple_vulns_in_same_file"]
	var results []correlation

	sastByFile := groupCodeByFile(input.CodeFindings, "sast")

	for _, findings := range sastByFile {
		if len(findings) < 2 {
			continue
		}
		anchor := findings[0]
		anchorID := anchor.ID
		for _, f := range findings[1:] {
			fID := f.ID
			results = append(results, correlation{
				CodeFindingID:   &anchorID,
				Reason:          "multiple_vulns_in_same_file",
				Score:           weight,
				Directional:     false,
				SourceFindingID: &anchorID,
				TargetFindingID: &fID,
			})
		}
	}
	return results
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

func (e *Engine) calculateRiskScores(input Input, correlations []correlation) (
	fileScores []store.RiskScoreRecord,
	pkgScores []store.RiskScoreRecord,
	overall float64,
) {
	fileEntries := make(map[string]*fileRiskEntry)
	pkgEntries := make(map[string]*packageRiskEntry)

	// Base scores from code findings.
	for _, f := range input.CodeFindings {
		rank := severityRank[strings.ToUpper(f.Severity)]
		if e, ok := fileEntries[f.File]; ok {
			if rank > e.BaseScore {
				e.BaseScore = rank
			}
			e.FindingCount++
		} else {
			fileEntries[f.File] = &fileRiskEntry{
				File:         f.File,
				BaseScore:    rank,
				FindingCount: 1,
			}
		}
	}

	// Base scores from dependency findings.
	for _, f := range input.DepFindings {
		rank := severityRank[strings.ToUpper(f.Severity)]
		key := f.Package + "@" + f.Version
		if e, ok := pkgEntries[key]; ok {
			if rank > e.BaseScore {
				e.BaseScore = rank
			}
			e.FindingCount++
		} else {
			pkgEntries[key] = &packageRiskEntry{
				Package:      f.Package,
				BaseScore:    rank,
				FindingCount: 1,
			}
		}
	}

	// Apply compound bonuses from correlations.
	for _, c := range correlations {
		if c.CodeFindingID != nil {
			// Find which file this code finding belongs to.
			for _, f := range input.CodeFindings {
				if f.ID == *c.CodeFindingID {
					if entry, ok := fileEntries[f.File]; ok {
						entry.CompoundBonus += c.Score
					}
					break
				}
			}
		}
		if c.DepFindingID != nil {
			for _, f := range input.DepFindings {
				if f.ID == *c.DepFindingID {
					key := f.Package + "@" + f.Version
					if entry, ok := pkgEntries[key]; ok {
						entry.CompoundBonus += c.Score
					}
					break
				}
			}
		}
	}

	// Build file risk score records.
	var componentScores []float64
	for _, entry := range fileEntries {
		cap := entry.BaseScore + 2.0
		score := math.Min(entry.BaseScore+entry.CompoundBonus, cap)
		file := entry.File
		fileScores = append(fileScores, store.RiskScoreRecord{
			ScanID:                   input.ScanID,
			File:                     &file,
			Score:                    score,
			ContributingFindingCount: entry.FindingCount,
		})
		componentScores = append(componentScores, score)
	}

	// Build package risk score records.
	for _, entry := range pkgEntries {
		cap := entry.BaseScore + 2.0
		score := math.Min(entry.BaseScore+entry.CompoundBonus, cap)
		pkg := entry.Package
		pkgScores = append(pkgScores, store.RiskScoreRecord{
			ScanID:                   input.ScanID,
			Package:                  &pkg,
			Score:                    score,
			ContributingFindingCount: entry.FindingCount,
		})
		componentScores = append(componentScores, score)
	}

	// Calculate overall score.
	overall = calculateOverallScore(componentScores)
	return
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
	peakPenalty := peak * 0.3
	return math.Min(avg+peakPenalty, 10.0)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// groupCodeByFile groups code findings by file, optionally filtering by scanner.
func groupCodeByFile(findings []store.CodeFindingRecord, scanner string) map[string][]store.CodeFindingRecord {
	out := make(map[string][]store.CodeFindingRecord)
	for _, f := range findings {
		if scanner != "" && f.Scanner != scanner {
			continue
		}
		out[f.File] = append(out[f.File], f)
	}
	return out
}
