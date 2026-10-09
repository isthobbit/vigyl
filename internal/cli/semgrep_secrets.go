package cli

import (
	"strings"

	"github.com/isthobbit/vigyl/internal/paths"
	"github.com/isthobbit/vigyl/internal/scan/sast"
	"github.com/isthobbit/vigyl/internal/scan/secrets"
)

// semgrepSecretRules is the prefix of Semgrep's secret-detection rules. They
// find the same kind of thing gitleaks does, so they are not code
// vulnerabilities.
const semgrepSecretRules = "generic.secrets."

// moveSemgrepSecrets takes Semgrep's secret findings out of the SAST results
// and adds them to the secrets results. A secret gitleaks also found on the
// same line is dropped, so one secret is reported once. Without this, a
// secret would count both as a secret and as a code vulnerability in the
// same file, and the correlation engine would link it to itself.
//
// The returned secrets result is s, or a new one if s is nil and Semgrep
// found secrets. Matched text is not copied: Semgrep does not say which part
// of the line is the secret, so it cannot be redacted.
func moveSemgrepSecrets(s *secrets.Result, a *sast.Result) *secrets.Result {
	if a == nil {
		return s
	}
	type at struct {
		file string
		line int
	}
	covered := map[at]bool{}
	if s != nil {
		for _, f := range s.Findings {
			file := paths.Rel(s.ScanPath, f.File)
			for line := f.StartLine; line <= max(f.StartLine, f.EndLine); line++ {
				covered[at{file, line}] = true
			}
		}
	}

	kept := a.Findings[:0:0]
	for _, f := range a.Findings {
		if !strings.HasPrefix(f.RuleID, semgrepSecretRules) {
			kept = append(kept, f)
			continue
		}
		if covered[at{paths.Rel(a.ScanPath, f.Path), f.Start.Line}] {
			continue
		}
		if s == nil {
			s = &secrets.Result{ScanPath: a.ScanPath}
		}
		s.Findings = append(s.Findings, secrets.Finding{
			RuleID:      f.RuleID[strings.LastIndex(f.RuleID, ".")+1:],
			Description: f.Message,
			StartLine:   f.Start.Line,
			EndLine:     f.End.Line,
			File:        f.Path,
		})
	}
	a.Findings = kept
	return s
}
