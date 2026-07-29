package sast_test

import (
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/sast"
)

// goldenSASTOutput is a representative semgrep --json output with two findings.
var goldenSASTOutput = []byte(`{
  "results": [
    {
      "check_id": "python.lang.security.audit.eval-used.eval-used",
      "path": "app/utils.py",
      "start": {"line": 42, "col": 5, "offset": 1200},
      "end":   {"line": 42, "col": 30, "offset": 1225},
      "extra": {
        "message": "Use of eval() is a security risk.",
        "severity": "ERROR",
        "lines": "    eval(user_input)",
        "metadata": {},
        "fix": ""
      }
    },
    {
      "check_id": "python.lang.security.audit.hardcoded-password.hardcoded-password",
      "path": "app/db.py",
      "start": {"line": 8, "col": 1, "offset": 200},
      "end":   {"line": 8, "col": 40, "offset": 239},
      "extra": {
        "message": "Hardcoded password detected.",
        "severity": "WARNING",
        "lines": "password = 'hunter2'",
        "metadata": {},
        "fix": ""
      }
    }
  ],
  "errors": [],
  "version": "1.50.0"
}`)

func TestParseOutputForTest_WithFindings(t *testing.T) {
	findings, err := sast.ParseOutputForTest(goldenSASTOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// First finding â€” ERROR â†’ CRITICAL
	f0 := findings[0]
	if f0.RuleID != "python.lang.security.audit.eval-used.eval-used" {
		t.Errorf("finding[0] RuleID: got %q", f0.RuleID)
	}
	if f0.Path != "app/utils.py" {
		t.Errorf("finding[0] Path: got %q, want %q", f0.Path, "app/utils.py")
	}
	if f0.Severity != "CRITICAL" {
		t.Errorf("finding[0] Severity: got %q, want CRITICAL (ERROR normalised)", f0.Severity)
	}
	if f0.Start.Line != 42 {
		t.Errorf("finding[0] Start.Line: got %d, want 42", f0.Start.Line)
	}

	// Second finding â€” WARNING â†’ HIGH
	f1 := findings[1]
	if f1.Severity != "HIGH" {
		t.Errorf("finding[1] Severity: got %q, want HIGH (WARNING normalised)", f1.Severity)
	}
	if f1.Path != "app/db.py" {
		t.Errorf("finding[1] Path: got %q, want %q", f1.Path, "app/db.py")
	}
}

func TestParseOutputForTest_Empty(t *testing.T) {
	for _, input := range [][]byte{
		{},
		[]byte("   "),
	} {
		findings, err := sast.ParseOutputForTest(input)
		if err != nil {
			t.Errorf("input %q: unexpected error: %v", input, err)
		}
		if len(findings) != 0 {
			t.Errorf("input %q: expected 0 findings, got %d", input, len(findings))
		}
	}
}

func TestParseOutputForTest_NoResults(t *testing.T) {
	empty := []byte(`{"results": [], "errors": [], "version": "1.50.0"}`)
	findings, err := sast.ParseOutputForTest(empty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseOutputForTest_MalformedJSON(t *testing.T) {
	_, err := sast.ParseOutputForTest([]byte(`{broken`))
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestSeverityNormalisation(t *testing.T) {
	cases := []struct {
		input   string
		wantSev string
	}{
		// ERROR â†’ CRITICAL
		{`{"results":[{"check_id":"r","path":"f","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":1,"offset":0},"extra":{"message":"m","severity":"ERROR","lines":"","metadata":{},"fix":""}}],"errors":[],"version":"1"}`, "CRITICAL"},
		// WARNING â†’ HIGH
		{`{"results":[{"check_id":"r","path":"f","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":1,"offset":0},"extra":{"message":"m","severity":"WARNING","lines":"","metadata":{},"fix":""}}],"errors":[],"version":"1"}`, "HIGH"},
		// INFO â†’ MEDIUM
		{`{"results":[{"check_id":"r","path":"f","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":1,"offset":0},"extra":{"message":"m","severity":"INFO","lines":"","metadata":{},"fix":""}}],"errors":[],"version":"1"}`, "MEDIUM"},
	}

	for _, tc := range cases {
		findings, err := sast.ParseOutputForTest([]byte(tc.input))
		if err != nil {
			t.Errorf("input severity case: unexpected error: %v", err)
			continue
		}
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
			continue
		}
		if findings[0].Severity != tc.wantSev {
			t.Errorf("severity: got %q, want %q", findings[0].Severity, tc.wantSev)
		}
	}
}
