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
	ID       string        `json:"id"`
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
type osvGroup struct {
	IDs []string `json:"ids"`
}
