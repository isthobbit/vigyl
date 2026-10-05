package sast_test

import (
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/sast"
)

func TestBuildArgs_OnlineDefaultsToAuto(t *testing.T) {
	args, err := sast.BuildArgsForTest("/src", false, nil, sast.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--config auto") {
		t.Errorf("expected --config auto, got %q", joined)
	}
	if strings.Contains(joined, "--metrics") {
		t.Errorf("online scan should leave metrics to semgrep's default, got %q", joined)
	}
}

func TestBuildArgs_OnlineHonoursConfiguredRules(t *testing.T) {
	args, err := sast.BuildArgsForTest("/src", false, nil, sast.Options{Rules: "p/owasp-top-ten"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(strings.Join(args, " "), "--config p/owasp-top-ten") {
		t.Errorf("configured ruleset not used: %v", args)
	}
}

func TestBuildArgs_OfflineRejectsRegistryRulesets(t *testing.T) {
	for _, rules := range []string{"", "auto", "p/default", "r/python.lang", "https://example.com/rules.yml"} {
		_, err := sast.BuildArgsForTest("/src", false, nil, sast.Options{Rules: rules, Offline: true})
		if err == nil {
			t.Errorf("rules %q: expected offline error, got nil", rules)
		}
	}
}

func TestBuildArgs_OfflineLocalRulesDisablesMetrics(t *testing.T) {
	args, err := sast.BuildArgsForTest("/src", false, []string{"vendor"}, sast.Options{Rules: "/rules", Offline: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--config /rules", "--metrics off", "--exclude vendor"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
}
