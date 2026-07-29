package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/isthobbit/vigyl/internal/recommend"
	"github.com/isthobbit/vigyl/internal/scan/sast"
	"github.com/isthobbit/vigyl/internal/scan/secrets"
)

// ANSI colour codes — disabled when noColor is true.
const (
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	cyan   = "\033[36m"
	bold   = "\033[1m"
	reset  = "\033[0m"
)

func colorize(noColor bool, code, text string) string {
	if noColor {
		return text
	}
	return code + text + reset
}

// PrintSecretsResult renders the secrets scan result to stdout.
func PrintSecretsResult(result *secrets.Result, noColor bool) {
	header := colorize(noColor, bold, "Secrets Scan Results")
	fmt.Println(header)
	fmt.Printf("   Path: %s\n\n", result.ScanPath)

	if len(result.Findings) == 0 {
		fmt.Println(colorize(noColor, green, "  No secrets found."))
		return
	}

	byFile := make(map[string][]secrets.Finding)
	for _, f := range result.Findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	for file, findings := range byFile {
		fmt.Printf("  %s\n", colorize(noColor, cyan, file))
		fmt.Println("  " + strings.Repeat("─", 60))

		for _, f := range findings {
			fmt.Printf("    %s  %s\n",
				colorize(noColor, red, "LEAK"),
				colorize(noColor, bold, f.Description),
			)
			fmt.Printf("    Rule:    %s\n", f.RuleID)
			fmt.Printf("    Line:    %d\n", f.StartLine)
			fmt.Printf("    Match:   %s\n", redactSecret(f.Match, f.Secret))
			if f.Commit != "" {
				fmt.Printf("    Commit:  %s (%s)\n", f.Commit[:min(8, len(f.Commit))], f.Author)
			}
			fmt.Println()
		}
	}

	total := len(result.Findings)
	fmt.Printf("  %s  %d secret%s detected. Rotate any exposed credentials immediately.\n\n",
		colorize(noColor, red, "WARNING"),
		total,
		plural(total),
	)
}

// redactSecret replaces the actual secret value in the match string with stars.
func redactSecret(match, secret string) string {
	if secret == "" || match == "" {
		return match
	}
	stars := strings.Repeat("*", min(len(secret), 12))
	return strings.ReplaceAll(match, secret, stars)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// severityColour returns an ANSI colour code for a severity level.
func severityColour(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "SEVERE":
		return red
	case "HIGH":
		return red
	case "MEDIUM":
		return yellow
	default:
		return cyan
	}
}

// wordWrap wraps text at maxWidth characters, indenting continuation lines.
func wordWrap(text string, maxWidth int, indent string) string {
	if len(text) <= maxWidth {
		return text
	}
	var result strings.Builder
	words := strings.Fields(text)
	line := ""
	for _, word := range words {
		if len(line)+len(word)+1 > maxWidth && line != "" {
			result.WriteString(line)
			result.WriteString("\n")
			result.WriteString(indent)
			line = word
		} else {
			if line == "" {
				line = word
			} else {
				line += " " + word
			}
		}
	}
	result.WriteString(line)
	return result.String()
}

// PrintScanHeader prints the scan banner.
func PrintScanHeader(path string, scanners []string, noColor bool) {
	fmt.Printf("%s\n", colorize(noColor, bold, "╭─────────────────────────────────────────╮"))
	fmt.Printf("%s\n", colorize(noColor, bold, "│  jensec · by vigyl                      │"))
	fmt.Printf("%s\n", colorize(noColor, bold, "╰─────────────────────────────────────────╯"))
	fmt.Printf("\n   Path:     %s\n", path)
	fmt.Printf("   Scanners: %s\n\n", strings.Join(scanners, ", "))
}

// PrintSASTResult renders the SAST scan result to stdout.
func PrintSASTResult(result *sast.Result, noColor bool) {
	header := colorize(noColor, bold, "SAST Scan Results")
	fmt.Println(header)
	fmt.Printf("   Path: %s\n\n", result.ScanPath)

	if len(result.Findings) == 0 {
		fmt.Println(colorize(noColor, green, "  No SAST findings."))
		return
	}

	for _, f := range result.Findings {
		sevColor := severityColour(f.Severity)
		fmt.Printf("  %s  %s\n",
			colorize(noColor, sevColor, f.Severity),
			colorize(noColor, cyan, f.Path),
		)
		fmt.Printf("    Rule:    %s\n", f.RuleID)
		fmt.Printf("    Line:    %d\n", f.Start.Line)
		fmt.Printf("    Message: %s\n", wordWrap(f.Message, 70, "             "))
		if f.Lines != "" {
			fmt.Printf("    Code:    %s\n", f.Lines)
		}
		fmt.Println()
	}

	total := len(result.Findings)
	fmt.Printf("  %s  %d SAST finding%s detected.\n\n",
		colorize(noColor, yellow, "WARNING"),
		total,
		plural(total),
	)
}

// PrintScanSummary prints the total finding counts and elapsed time.
func PrintScanSummary(secretsCount, sastCount int, elapsed time.Duration, noColor bool) {
	total := secretsCount + sastCount
	fmt.Println(strings.Repeat("─", 50))
	fmt.Printf("  Total findings: %d  (secrets: %d, sast: %d)\n", total, secretsCount, sastCount)
	fmt.Printf("  Elapsed:        %s\n\n", elapsed)
}

// PrintRecommendations renders the prioritised recommendation list to stdout.
func PrintRecommendations(recs []recommend.Recommendation, noColor bool) {
	if len(recs) == 0 {
		return
	}

	fmt.Printf("\n%s\n\n", colorize(noColor, bold, "Recommendations"))

	for i, r := range recs {
		sevColor := severityColour(r.Priority)
		effortLabel := effortBadge(r.Effort)

		fmt.Printf("  %d. %s  %s  %s\n",
			i+1,
			colorize(noColor, sevColor, r.Priority),
			colorize(noColor, yellow, effortLabel),
			colorize(noColor, bold, r.Title),
		)
		fmt.Printf("     %s\n", colorize(noColor, bold, "Why:"))
		fmt.Printf("     %s\n", wordWrap(r.Context, 72, "     "))
		fmt.Printf("     %s\n", colorize(noColor, bold, "Do:"))
		fmt.Printf("     %s\n", wordWrap(r.Action, 72, "     "))
		fmt.Println()
	}
}

// effortBadge returns a short label for the effort level.
func effortBadge(e recommend.Effort) string {
	switch e {
	case recommend.EffortImmediate:
		return "[IMMEDIATE]"
	case recommend.EffortShortTerm:
		return "[SHORT TERM]"
	case recommend.EffortLongTerm:
		return "[LONG TERM]"
	default:
		return ""
	}
}
