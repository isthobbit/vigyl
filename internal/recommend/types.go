package recommend

// Effort represents how urgently a recommendation should be acted on.
type Effort string

const (
	EffortImmediate Effort = "IMMEDIATE"
	EffortShortTerm Effort = "SHORT_TERM"
	EffortLongTerm  Effort = "LONG_TERM"
)

// Recommendation is a single actionable security recommendation
// generated from one or more correlated findings.
type Recommendation struct {
	// Priority mirrors the risk band of the findings that triggered this.
	Priority string

	// Title is a one-line summary specific to the finding cluster.
	Title string

	// Context explains why this combination of findings is dangerous.
	Context string

	// Action is a concrete next step referencing specific files, packages, or lines.
	Action string

	// Effort indicates how urgently this should be addressed.
	Effort Effort

	// FindingRefs are the finding IDs that triggered this recommendation.
	FindingRefs []int64

	// Rule is the correlation rule that generated this recommendation.
	Rule string
}

// effortOrder is used to sort recommendations — IMMEDIATE first.
var effortOrder = map[Effort]int{
	EffortImmediate: 0,
	EffortShortTerm: 1,
	EffortLongTerm:  2,
}
