package secrets

// Finding maps to a single entry in gitleaks' JSON report output.
// Run `gitleaks detect --report-format json` to see the raw shape.
type Finding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	File        string `json:"File"`
	Commit      string `json:"Commit"`
	Author      string `json:"Author"`
	Email       string `json:"Email"`
	Date        string `json:"Date"`
	Message     string `json:"Message"`
	// Secret is the actual leaked value — we deliberately avoid printing it.
	Secret      string  `json:"Secret"`
	Match       string  `json:"Match"`
	Entropy     float64 `json:"Entropy"`
	Fingerprint string  `json:"Fingerprint"`
}

// Result is the top-level output returned by the runner.
type Result struct {
	Findings []Finding
	// ScanPath is the directory that was scanned.
	ScanPath string
	// GitleaksAvailable is false when the binary isn't installed.
	GitleaksAvailable bool
}
