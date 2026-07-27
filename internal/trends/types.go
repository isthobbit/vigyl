package trends

// Direction indicates whether the risk score is improving, stable, or degrading.
type Direction string

const (
	DirectionImproving Direction = "IMPROVING"
	DirectionStable    Direction = "STABLE"
	DirectionDegrading Direction = "DEGRADING"
)

// Config holds configurable trend analysis settings.
type Config struct {
	// LookbackScans is how many previous scans to include in trend analysis.
	LookbackScans int
	// MinScansRequired is the minimum number of scans before trends are shown.
	MinScansRequired int
	// RecurringThreshold is how many consecutive scans a finding must appear
	// in before it is flagged as recurring.
	RecurringThreshold int
}

// DefaultConfig returns the default trend configuration.
func DefaultConfig() Config {
	return Config{
		LookbackScans:      5,
		MinScansRequired:   2,
		RecurringThreshold: 3,
	}
}

// Report is the full trend analysis for the current scan compared to previous scans.
type Report struct {
	// Direction is whether risk is improving, stable, or degrading.
	Direction Direction

	// CurrentScore is the overall risk score of the current scan.
	CurrentScore float64

	// PreviousScore is the overall risk score of the most recent previous scan.
	PreviousScore float64

	// Delta is CurrentScore - PreviousScore. Positive = getting worse.
	Delta float64

	// NewFindings are findings in the current scan not present in the previous scan.
	NewFindings int

	// ResolvedFindings are findings in the previous scan not present in the current scan.
	ResolvedFindings int

	// RecurringFindings are findings present across RecurringThreshold consecutive scans.
	RecurringFindings []RecurringFinding

	// SecretsD is the change in secret finding count.
	SecretsDelta int

	// SASTDelta is the change in SAST finding count.
	SASTDelta int

	// DependencyDelta is the change in dependency finding count.
	DependencyDelta int

	// CorrelationDelta is the change in correlation count.
	CorrelationDelta int

	// ScansAnalysed is the number of scans that were compared.
	ScansAnalysed int
}

// RecurringFinding is a finding that has appeared across multiple consecutive scans.
type RecurringFinding struct {
	// Key is a unique identifier for the finding (scanner + rule + file/package).
	Key string
	// Scanner is which scanner flagged it.
	Scanner string
	// Description is a short human-readable description.
	Description string
	// ConsecutiveScans is how many consecutive scans it has appeared in.
	ConsecutiveScans int
}

// findingKey produces a stable string key for a finding that can be compared
// across scans — it deliberately excludes the scan ID and database ID.
func codeKey(scanner, ruleID, file string, line int) string {
	return scanner + "|" + ruleID + "|" + file
}

func depKey(scanner, pkg, version, cveID string) string {
	return scanner + "|" + pkg + "|" + version + "|" + cveID
}
