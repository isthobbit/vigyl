package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/isthobbit/vigil/internal/scan/sast"
	"github.com/isthobbit/vigil/internal/scan/secrets"
)

// ANSI colour codes â€” disabled when noColor is true.
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

	// Group findings by file for readability.
	byFile := make(map[string][]secrets.Finding)
	for _, f := range result.Findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	for file, findings := range byFile {
		fmt.Printf("  %s\n", colorize(noColor, cyan, file))
		fmt.Println("  " + strings.Repeat("â”€", 60))

		for _, f := range findings {
			fmt.Printf("    %s  %s\n",
				colorize(noColor, red, "LEAK"),
				colorize(noColor, bold, f.Description),
			)
			fmt.Printf("    Rule:    %s\n", f.RuleID)
			fmt.Printf("    Line:    %d\n", f.StartLine)
			// Print the match but redact the actual secret value.
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

// redactSecret replaces the actual secret value in the match string with stars,
// so we show context without exposing the credential in terminal output.
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
	switch severity {
	case "CRITICAL":
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
	fmt.Printf("%s\n", colorize(noColor, bold, "â•­â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•®"))
	fmt.Printf("%s\n", colorize(noColor, bold, "â”‚  jensec Â· by vigil                      â”‚"))
	fmt.Printf("%s\n", colorize(noColor, bold, "â•°â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•¯"))
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
	fmt.Println(strings.Repeat("â”€", 50))
	fmt.Printf("  Total findings: %d  (secrets: %d, sast: %d)\n", total, secretsCount, sastCount)
	fmt.Printf("  Elapsed:        %s\n\n", elapsed)
}
