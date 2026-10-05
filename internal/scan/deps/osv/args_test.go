package osv_test

import (
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/deps/osv"
)

func all(string) bool  { return true }
func none(string) bool { return false }

func TestBuildArgs_OfflineFlag(t *testing.T) {
	online := strings.Join(osv.BuildArgsForTest("/src", nil, osv.Options{}, all), " ")
	if strings.Contains(online, "--offline") {
		t.Errorf("online scan should not pass --offline: %q", online)
	}
	offline := strings.Join(osv.BuildArgsForTest("/src", nil, osv.Options{Offline: true}, all), " ")
	if !strings.Contains(offline, "--offline") {
		t.Errorf("offline scan must pass --offline: %q", offline)
	}
}

func TestBuildArgs_ExcludesUseGlobFlag(t *testing.T) {
	args := osv.BuildArgsForTest("/src", []string{"vendor", "node_modules"}, osv.Options{}, all)
	joined := strings.Join(args, " ")
	for _, want := range []string{"--experimental-exclude g:vendor", "--experimental-exclude g:node_modules"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if strings.Contains(joined, "--skip-git") {
		t.Errorf("exclusions must not map to --skip-git: %q", joined)
	}
	if args[len(args)-1] != "/src" {
		t.Errorf("scan path must be last, got %v", args)
	}
}

func TestBuildArgs_ExcludesSkippedWhenUnsupported(t *testing.T) {
	joined := strings.Join(osv.BuildArgsForTest("/src", []string{"vendor"}, osv.Options{}, none), " ")
	if strings.Contains(joined, "--experimental-exclude") {
		t.Errorf("older osv-scanner does not know --experimental-exclude: %q", joined)
	}
}
