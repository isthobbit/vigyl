package osv

// Result is the top-level output returned by the runner.
type Result struct {
	Findings     []Finding
	ScanPath     string
	OSVAvailable bool
}

// Finding is a single vulnerability found by OSV-Scanner.
type Finding struct {
	Package      string
	Version      string
	CVEID        string
	Severity     string
	Ecosystem    string
	FixedVersion string
	Description  string
	// Manifest is the manifest or lockfile the package came from,
	// slash-separated and relative to the scan root.
	Manifest string
}

// osvReport is the top-level shape of `osv-scanner --format json` output.
type osvReport struct {
	Results []osvResult `json:"results"`
}

// osvResult is one scanned source (e.g. go.mod, package-lock.json).
type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// osvPackage is one package with its associated vulnerabilities.
type osvPackage struct {
	Package         osvPackageInfo     `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
	Groups          []osvGroup         `json:"groups"`
}

type osvPackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID string `json:"id"`
	// Aliases are the same vulnerability's IDs in other databases,
	// usually including its CVE ID.
	Aliases  []string      `json:"aliases"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed      string `json:"fixed"`
	Introduced string `json:"introduced"`
}

// osvGroup links vulnerabilities to aliases (e.g. CVE IDs).
// osvGroup is a set of OSV IDs that describe one vulnerability.
type osvGroup struct {
	IDs     []string `json:"ids"`
	Aliases []string `json:"aliases"`
	// MaxSeverity is the highest CVSS base score in the group, as a number
	// such as "7.5" (empty when no score is published).
	MaxSeverity string `json:"max_severity"`
}
