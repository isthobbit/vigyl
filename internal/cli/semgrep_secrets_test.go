package cli

import (
	"path/filepath"
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/sast"
	"github.com/isthobbit/vigyl/internal/scan/secrets"
)

func TestMoveSemgrepSecrets(t *testing.T) {
	// gitleaks reports slash paths and Semgrep native ones; both must match.
	root := t.TempDir()
	key, db := filepath.Join(root, "cert", "server.key"), filepath.Join(root, "db.js")
	s := &secrets.Result{ScanPath: root, Findings: []secrets.Finding{
		{RuleID: "private-key", File: filepath.ToSlash(key), StartLine: 1, EndLine: 27, Match: "-----BEGIN"},
	}}
	a := &sast.Result{ScanPath: root, Findings: []sast.Finding{
		// Same key gitleaks found: dropped.
		{RuleID: "generic.secrets.security.detected-private-key.detected-private-key", Path: key, Start: sast.Location{Line: 1}},
		// Only Semgrep found it: becomes a secret, without the matched text.
		{RuleID: "generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash", Path: db, Start: sast.Location{Line: 19}, End: sast.Location{Line: 19}, Message: "bcrypt hash detected", Lines: "password: \"$2a$10$abc\""},
		// A real code vulnerability: stays.
		{RuleID: "javascript.lang.security.audit.code-string-concat", Path: db, Start: sast.Location{Line: 30}},
	}}

	s = moveSemgrepSecrets(s, a)

	if len(a.Findings) != 1 || a.Findings[0].Start.Line != 30 {
		t.Fatalf("SAST should keep only the code vulnerability, got %+v", a.Findings)
	}
	if len(s.Findings) != 2 {
		t.Fatalf("expected the gitleaks secret plus one from Semgrep, got %+v", s.Findings)
	}
	got := s.Findings[1]
	if got.RuleID != "detected-bcrypt-hash" || got.StartLine != 19 || got.File != db || got.Match != "" {
		t.Errorf("converted secret wrong: %+v", got)
	}
}

func TestMoveSemgrepSecrets_NoGitleaks(t *testing.T) {
	root := t.TempDir()
	a := &sast.Result{ScanPath: root, Findings: []sast.Finding{
		{RuleID: "generic.secrets.security.detected-aws-access-key.x", Path: filepath.Join(root, "a.py"), Start: sast.Location{Line: 2}},
	}}
	s := moveSemgrepSecrets(nil, a)
	if s == nil || len(s.Findings) != 1 || len(a.Findings) != 0 {
		t.Fatalf("expected the finding moved to a new secrets result, got %+v / %+v", s, a.Findings)
	}
	if s.GitleaksAvailable {
		t.Error("a secrets result created for Semgrep findings must not claim gitleaks ran")
	}
}
