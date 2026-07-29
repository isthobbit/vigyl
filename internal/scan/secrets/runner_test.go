package secrets_test

import (
	"testing"

	"github.com/isthobbit/vigyl/internal/scan/secrets"
)

// goldenSecretsFindings is a representative gitleaks JSON output with two findings.
// Derived from real gitleaks v8 output shape.
var goldenSecretsFindings = []byte(`[
  {
    "RuleID": "aws-access-token",
    "Description": "AWS Access Token",
    "StartLine": 12,
    "EndLine": 12,
    "File": "config/settings.py",
    "Commit": "",
    "Author": "",
    "Email": "",
    "Date": "",
    "Message": "",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "Match": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "Entropy": 3.32,
    "Fingerprint": "abc123"
  },
  {
    "RuleID": "generic-api-key",
    "Description": "Generic API Key",
    "StartLine": 7,
    "EndLine": 7,
    "File": ".env",
    "Commit": "",
    "Author": "",
    "Email": "",
    "Date": "",
    "Message": "",
    "Secret": "supersecret123",
    "Match": "API_KEY=supersecret123",
    "Entropy": 2.8,
    "Fingerprint": "def456"
  }
]`)

func TestParseReportForTest_WithFindings(t *testing.T) {
	findings, err := secrets.ParseReportForTest(goldenSecretsFindings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// First finding
	f0 := findings[0]
	if f0.RuleID != "aws-access-token" {
		t.Errorf("finding[0] RuleID: got %q, want %q", f0.RuleID, "aws-access-token")
	}
	if f0.File != "config/settings.py" {
		t.Errorf("finding[0] File: got %q, want %q", f0.File, "config/settings.py")
	}
	if f0.StartLine != 12 {
		t.Errorf("finding[0] StartLine: got %d, want %d", f0.StartLine, 12)
	}
	if f0.Secret != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("finding[0] Secret: got %q, want %q", f0.Secret, "AKIAIOSFODNN7EXAMPLE")
	}

	// Second finding
	f1 := findings[1]
	if f1.RuleID != "generic-api-key" {
		t.Errorf("finding[1] RuleID: got %q, want %q", f1.RuleID, "generic-api-key")
	}
	if f1.File != ".env" {
		t.Errorf("finding[1] File: got %q, want %q", f1.File, ".env")
	}
}

func TestParseReportForTest_Empty(t *testing.T) {
	for _, input := range [][]byte{
		{},
		[]byte("null"),
		[]byte("   \n  "),
	} {
		findings, err := secrets.ParseReportForTest(input)
		if err != nil {
			t.Errorf("input %q: unexpected error: %v", input, err)
		}
		if len(findings) != 0 {
			t.Errorf("input %q: expected 0 findings, got %d", input, len(findings))
		}
	}
}

func TestParseReportForTest_InvalidJSON(t *testing.T) {
	_, err := secrets.ParseReportForTest([]byte(`{"not": "an array"}`))
	if err == nil {
		t.Error("expected error for invalid JSON shape, got nil")
	}
}

func TestParseReportForTest_MalformedJSON(t *testing.T) {
	_, err := secrets.ParseReportForTest([]byte(`[{broken`))
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestParseReportForTest_SingleFinding(t *testing.T) {
	single := []byte(`[{
		"RuleID": "github-pat",
		"Description": "GitHub Personal Access Token",
		"StartLine": 3,
		"EndLine": 3,
		"File": "Makefile",
		"Secret": "ghp_abc123xyz", // gitleaks:allow
		"Match": "GITHUB_TOKEN=ghp_abc123xyz", // gitleaks:allow
		"Entropy": 4.1,
		"Fingerprint": "ggg999"
	}]`)

	findings, err := secrets.ParseReportForTest(single)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "github-pat" {
		t.Errorf("RuleID: got %q, want %q", findings[0].RuleID, "github-pat")
	}
}
