package trivy

// Result is the top-level output returned by the runner.
type Result struct {
	Findings       []Finding
	ScanPath       string
	TrivyAvailable bool
}

// Finding is a single vulnerability found by Trivy.
type Finding struct {
	Package      string
	Version      string
	CVEID        string
	Severity     string
	Ecosystem    string
	FixedVersion string
	Description  string
}

// trivyReport is the top-level shape of `trivy fs --format json` output.
type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

// trivyResult is one scanned target (e.g. go.mod, package.json).
type trivyResult struct {
	Target          string            `json:"Target"`
	Type            string            `json:"Type"`
	Vulnerabilities []trivyVulnResult `json:"Vulnerabilities"`
}

// trivyVulnResult is one vulnerability entry inside a target.
type trivyVulnResult struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgName          string          `json:"PkgName"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	Severity         string          `json:"Severity"`
	Description      string          `json:"Description"`
	Vulnerability    trivyVulnDetail `json:"Vulnerability"`
}

type trivyVulnDetail struct {
	Description string `json:"Description"`
}
