package config

import "time"

// Config is the canonical in-memory representation of jensec configuration.
// Every field has a zero-value-safe default applied by Defaults().
type Config struct {
	Output      OutputConfig      `mapstructure:"output"`
	Scan        ScanConfig        `mapstructure:"scan"`
	Storage     StorageConfig     `mapstructure:"storage"`
	Auth        AuthConfig        `mapstructure:"auth"`
	Correlation CorrelationConfig `mapstructure:"correlation"`
	Trends      TrendsConfig      `mapstructure:"trends"`
}

// CorrelationConfig tunes the correlation engine.
type CorrelationConfig struct {
	// Weights overrides individual rule weights by rule name, e.g.
	// secret_in_vulnerable_file: 1.0. Unlisted rules keep their defaults.
	Weights map[string]float64 `mapstructure:"weights"`
}

// TrendsConfig tunes trend analysis across scans.
type TrendsConfig struct {
	// LookbackScans is how many previous scans to compare against.
	LookbackScans int `mapstructure:"lookback_scans"`
	// MinScansRequired is how many scans are needed before trends are shown.
	MinScansRequired int `mapstructure:"min_scans_required"`
	// RecurringThreshold is how many consecutive scans a finding must appear
	// in before it is flagged as recurring.
	RecurringThreshold int `mapstructure:"recurring_threshold"`
}

type OutputConfig struct {
	// JSON outputs results as machine-readable JSON when true.
	JSON bool `mapstructure:"json"`
	// NoColor disables ANSI colour codes.
	NoColor bool `mapstructure:"no_color"`
	// Verbose enables extra diagnostic output.
	Verbose bool `mapstructure:"verbose"`
}

type ScanConfig struct {
	// FailOn is the minimum severity that causes a non-zero exit code.
	// Values: critical | high | medium | low | none
	FailOn string `mapstructure:"fail_on"`
	// Timeout is the maximum time a single scanner is allowed to run.
	Timeout time.Duration `mapstructure:"timeout"`
	// ExcludePaths is a list of glob patterns to skip during scanning.
	ExcludePaths []string `mapstructure:"exclude_paths"`
	// SemgrepRules overrides the default "auto" ruleset.
	SemgrepRules string `mapstructure:"semgrep_rules"`
	// Offline runs every scanner against local data only, with no network
	// access. Data is prepared with `jensec offline sync`.
	Offline bool `mapstructure:"offline"`
	// Parallel runs the scanners at the same time. Turn it off on machines
	// with little memory or CPU.
	Parallel bool `mapstructure:"parallel"`
}

type StorageConfig struct {
	// DBPath overrides the default ~/.vigyl/jensec.db location.
	DBPath string `mapstructure:"db_path"`
	// MaxHistory is the maximum number of scan records to retain.
	MaxHistory int `mapstructure:"max_history"`
	// OfflineDir overrides the default ~/.vigyl/offline data location.
	OfflineDir string `mapstructure:"offline_dir"`
}

type AuthConfig struct {
	// LicenseKey is used for future commercial features.
	LicenseKey string `mapstructure:"license_key"`
}

// Defaults returns a Config populated with safe production defaults.
func Defaults() Config {
	return Config{
		Output: OutputConfig{
			JSON:    false,
			NoColor: false,
			Verbose: false,
		},
		Scan: ScanConfig{
			FailOn:       "high",
			Timeout:      5 * time.Minute,
			ExcludePaths: []string{},
			SemgrepRules: "auto",
			Parallel:     true,
		},
		Storage: StorageConfig{
			MaxHistory: 100,
		},
		Trends: TrendsConfig{
			LookbackScans:      5,
			MinScansRequired:   2,
			RecurringThreshold: 3,
		},
	}
}

// ValidFailOnValues is the set of accepted --fail-on values.
var ValidFailOnValues = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"none":     true,
}

// SeverityOrder maps severity names to a numeric rank for comparison.
// Higher number = more severe.
var SeverityOrder = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// MeetsSeverityThreshold returns true when foundSeverity is at or above threshold.
func MeetsSeverityThreshold(foundSeverity, threshold string) bool {
	if threshold == "none" {
		return false
	}
	found := SeverityOrder[foundSeverity]
	thresh := SeverityOrder[threshold]
	return found >= thresh
}
