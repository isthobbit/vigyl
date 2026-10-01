package trivy_test

import (
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/deps/trivy"
)

func all(string) bool  { return true }
func none(string) bool { return false }

func TestBuildArgs_OnlineHasNoOfflineFlags(t *testing.T) {
	joined := strings.Join(trivy.BuildArgsForTest("/src", false, nil, trivy.Options{}, all), " ")
	for _, f := range []string{"--skip-db-update", "--offline-scan", "--cache-dir", "--disable-telemetry"} {
		if strings.Contains(joined, f) {
			t.Errorf("online scan should not pass %s: %q", f, joined)
		}
	}
}

func TestBuildArgs_OfflineStopsNetworkCalls(t *testing.T) {
	opts := trivy.Options{Offline: true, CacheDir: "/data/trivy"}
	joined := strings.Join(trivy.BuildArgsForTest("/src", false, nil, opts, all), " ")
	for _, want := range []string{
		"--cache-dir /data/trivy",
		"--skip-db-update",
		"--skip-java-db-update",
		"--offline-scan",
		"--skip-version-check",
		"--disable-telemetry",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
}

func TestBuildArgs_OfflineOmitsUnsupportedFlags(t *testing.T) {
	opts := trivy.Options{Offline: true, CacheDir: "/data/trivy"}
	joined := strings.Join(trivy.BuildArgsForTest("/src", false, nil, opts, none), " ")
	if strings.Contains(joined, "--skip-version-check") || strings.Contains(joined, "--disable-telemetry") {
		t.Errorf("flags the trivy build lacks must not be passed: %q", joined)
	}
	if !strings.Contains(joined, "--skip-db-update") {
		t.Errorf("core offline flags must always be passed: %q", joined)
	}
}
