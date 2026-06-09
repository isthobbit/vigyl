package sast

// Result is the top-level output returned by the runner.
type Result struct {
	Findings         []Finding
	ScanPath         string
	SemgrepAvailable bool
}

// Finding maps to a single entry in Semgrep's JSON output.
// Semgrep's full schema has more fields; we capture what's useful for output.
type Finding struct {
	RuleID   string   `json:"check_id"`
	Path     string   `json:"path"`
	Message  string   `json:"extra.message"` // flattened below in UnmarshalJSON
	Severity string   `json:"extra.severity"`
	Lines    string   `json:"extra.lines"`
	Start    Location `json:"-"`
	End      Location `json:"-"`
	Extra    Extra    `json:"extra"`
}

type Location struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// Extra is the nested object Semgrep puts most useful data inside.
type Extra struct {
	Message  string         `json:"message"`
	Severity string         `json:"severity"`
	Lines    string         `json:"lines"`
	Metadata map[string]any `json:"metadata"`
	Fix      string         `json:"fix"`
}

// semgrepReport is the top-level shape of `semgrep --json` output.
type semgrepReport struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
	Version string          `json:"version"`
}

type semgrepResult struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   Location `json:"start"`
	End     Location `json:"end"`
	Extra   Extra    `json:"extra"`
}

type semgrepError struct {
	Code    int    `json:"code"`
	Level   string `json:"level"`
	Message string `json:"message"`
}
