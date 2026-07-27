package trends

import (
	"github.com/isthobbit/vigil/internal/store"
)

// Analyse compares the current scan against previous scans of the same path
// and returns a trend report. Returns nil if there are not enough scans.
func Analyse(db *store.DB, currentScanID int64, scanPath string, cfg Config) (*Report, error) {
	// Fetch recent scans for this path, excluding the current scan.
	scans, err := db.RecentScansForPath(scanPath, cfg.LookbackScans+1)
	if err != nil {
		return nil, err
	}

	// Filter out the current scan — we want previous scans only.
	var previous []store.ScanRecord
	for _, s := range scans {
		if s.ID != currentScanID {
			previous = append(previous, s)
		}
	}

	if len(previous) < cfg.MinScansRequired-1 {
		// Not enough history yet.
		return nil, nil
	}

	// Get current scan record.
	current, err := db.ScanByID(currentScanID)
	if err != nil || current == nil {
		return nil, err
	}

	// Compare current against the most recent previous scan.
	prev := previous[0]
	delta := current.RiskScore - prev.RiskScore

	direction := DirectionStable
	switch {
	case delta < -0.5:
		direction = DirectionImproving
	case delta > 0.5:
		direction = DirectionDegrading
	}

	// Fetch findings for current and previous scan.
	currentCode, _ := db.CodeFindingsForScan(currentScanID)
	currentDep, _ := db.DepFindingsForScan(currentScanID)
	prevCode, _ := db.CodeFindingsForScan(prev.ID)
	prevDep, _ := db.DepFindingsForScan(prev.ID)

	// Build key sets for comparison.
	currentCodeKeys := make(map[string]bool)
	for _, f := range currentCode {
		currentCodeKeys[codeKey(f.Scanner, f.RuleID, f.File, f.Line)] = true
	}
	currentDepKeys := make(map[string]bool)
	for _, f := range currentDep {
		currentDepKeys[depKey(f.Scanner, f.Package, f.Version, f.CVEID)] = true
	}

	prevCodeKeys := make(map[string]bool)
	for _, f := range prevCode {
		prevCodeKeys[codeKey(f.Scanner, f.RuleID, f.File, f.Line)] = true
	}
	prevDepKeys := make(map[string]bool)
	for _, f := range prevDep {
		prevDepKeys[depKey(f.Scanner, f.Package, f.Version, f.CVEID)] = true
	}

	// Count new findings (in current but not in previous).
	newFindings := 0
	for k := range currentCodeKeys {
		if !prevCodeKeys[k] {
			newFindings++
		}
	}
	for k := range currentDepKeys {
		if !prevDepKeys[k] {
			newFindings++
		}
	}

	// Count resolved findings (in previous but not in current).
	resolvedFindings := 0
	for k := range prevCodeKeys {
		if !currentCodeKeys[k] {
			resolvedFindings++
		}
	}
	for k := range prevDepKeys {
		if !currentDepKeys[k] {
			resolvedFindings++
		}
	}

	// Per-category deltas.
	currentSecrets := countByScanner(currentCode, "secrets")
	currentSAST := countByScanner(currentCode, "sast")
	currentDeps := len(currentDep)
	prevSecrets := countByScanner(prevCode, "secrets")
	prevSAST := countByScanner(prevCode, "sast")
	prevDeps := len(prevDep)

	// Correlation deltas.
	currentCorrs, _ := db.CorrelationsForScan(currentScanID)
	prevCorrs, _ := db.CorrelationsForScan(prev.ID)

	// Find recurring findings across all lookback scans.
	recurring := findRecurring(db, currentScanID, currentCodeKeys, currentDepKeys, previous, cfg.RecurringThreshold, currentCode, currentDep)

	return &Report{
		Direction:         direction,
		CurrentScore:      current.RiskScore,
		PreviousScore:     prev.RiskScore,
		Delta:             delta,
		NewFindings:       newFindings,
		ResolvedFindings:  resolvedFindings,
		RecurringFindings: recurring,
		SecretsDelta:      currentSecrets - prevSecrets,
		SASTDelta:         currentSAST - prevSAST,
		DependencyDelta:   currentDeps - prevDeps,
		CorrelationDelta:  len(currentCorrs) - len(prevCorrs),
		ScansAnalysed:     len(previous) + 1,
	}, nil
}

// findRecurring identifies findings that have appeared in recurring_threshold
// or more consecutive scans including the current one.
func findRecurring(
	db *store.DB,
	currentScanID int64,
	currentCodeKeys map[string]bool,
	currentDepKeys map[string]bool,
	previous []store.ScanRecord,
	threshold int,
	currentCode []store.CodeFindingRecord,
	currentDep []store.DepFindingRecord,
) []RecurringFinding {
	// Track how many consecutive scans each finding key has appeared in.
	// Start with 1 (the current scan) for each current finding.
	consecutiveCount := make(map[string]int)
	for k := range currentCodeKeys {
		consecutiveCount[k] = 1
	}
	for k := range currentDepKeys {
		consecutiveCount[k] = 1
	}

	// Walk through previous scans in order (most recent first).
	for _, prev := range previous {
		prevCode, _ := db.CodeFindingsForScan(prev.ID)
		prevDep, _ := db.DepFindingsForScan(prev.ID)

		prevKeys := make(map[string]bool)
		for _, f := range prevCode {
			prevKeys[codeKey(f.Scanner, f.RuleID, f.File, f.Line)] = true
		}
		for _, f := range prevDep {
			prevKeys[depKey(f.Scanner, f.Package, f.Version, f.CVEID)] = true
		}

		// Only increment if the finding was in this previous scan too.
		for k := range consecutiveCount {
			if prevKeys[k] {
				consecutiveCount[k]++
			}
		}
	}

	// Build description lookup from current findings.
	descByKey := make(map[string]string)
	scannerByKey := make(map[string]string)
	for _, f := range currentCode {
		k := codeKey(f.Scanner, f.RuleID, f.File, f.Line)
		descByKey[k] = f.RuleID + " in " + f.File
		scannerByKey[k] = f.Scanner
	}
	for _, f := range currentDep {
		k := depKey(f.Scanner, f.Package, f.Version, f.CVEID)
		descByKey[k] = f.CVEID + " in " + f.Package + "@" + f.Version
		scannerByKey[k] = f.Scanner
	}

	var recurring []RecurringFinding
	for k, count := range consecutiveCount {
		if count >= threshold {
			recurring = append(recurring, RecurringFinding{
				Key:              k,
				Scanner:          scannerByKey[k],
				Description:      descByKey[k],
				ConsecutiveScans: count,
			})
		}
	}

	return recurring
}

// countByScanner counts code findings for a specific scanner.
func countByScanner(findings []store.CodeFindingRecord, scanner string) int {
	count := 0
	for _, f := range findings {
		if f.Scanner == scanner {
			count++
		}
	}
	return count
}
