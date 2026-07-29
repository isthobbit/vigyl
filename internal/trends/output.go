package trends

import (
	"fmt"
	"sort"
	"strings"
)

// Print renders the trend report to stdout.
func Print(report *Report, noColor bool) {
	if report == nil {
		return
	}

	fmt.Printf("\n%s\n\n", colorize(noColor, "\033[1m", "Trend Analysis"))

	// Direction line.
	dirColor := directionColor(report.Direction)
	dirLabel := string(report.Direction)
	fmt.Printf("  Risk Score:  %.1f → %.1f  %s\n",
		report.PreviousScore,
		report.CurrentScore,
		colorize(noColor, dirColor, dirLabel),
	)

	// Delta breakdown.
	fmt.Printf("  New:         %s\n", signedInt(report.NewFindings))
	fmt.Printf("  Resolved:    %s\n", signedInt(-report.ResolvedFindings))
	fmt.Println()

	// Per-category deltas.
	fmt.Printf("  Secrets:     %s\n", signedInt(report.SecretsDelta))
	fmt.Printf("  SAST:        %s\n", signedInt(report.SASTDelta))
	fmt.Printf("  Deps:        %s\n", signedInt(report.DependencyDelta))
	fmt.Printf("  Correlations:%s\n", signedInt(report.CorrelationDelta))
	fmt.Println()

	// Recurring findings — sort by most persistent first, cap at 10.
	if len(report.RecurringFindings) > 0 {
		fmt.Printf("  %s\n", colorize(noColor, "\033[33m", fmt.Sprintf(
			"⚠  %d finding(s) have persisted across multiple scans:",
			len(report.RecurringFindings),
		)))

		// Sort by consecutive scan count descending.
		sorted := make([]RecurringFinding, len(report.RecurringFindings))
		copy(sorted, report.RecurringFindings)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].ConsecutiveScans > sorted[j].ConsecutiveScans
		})

		// Show top 10 only.
		shown := sorted
		if len(shown) > 10 {
			shown = shown[:10]
		}
		for _, r := range shown {
			fmt.Printf("     [%s] %s (%d scans)\n", r.Scanner, r.Description, r.ConsecutiveScans)
		}
		if len(report.RecurringFindings) > 10 {
			fmt.Printf("     ... and %d more.\n", len(report.RecurringFindings)-10)
		}
		fmt.Println()
		fmt.Printf("  Review whether these are accepted risks — if so, add them to your ignore list.\n\n")
	}

	fmt.Printf("  Based on %d scan(s).\n\n", report.ScansAnalysed)
}

func directionColor(d Direction) string {
	switch d {
	case DirectionImproving:
		return "\033[32m" // green
	case DirectionDegrading:
		return "\033[31m" // red
	default:
		return "\033[36m" // cyan
	}
}

func signedInt(n int) string {
	if n > 0 {
		return fmt.Sprintf("+%d", n)
	}
	return fmt.Sprintf("%d", n)
}

func colorize(noColor bool, code, text string) string {
	if noColor {
		return text
	}
	return code + text + "\033[0m"
}

// directionArrow returns a simple arrow for the direction.
func directionArrow(d Direction) string {
	switch d {
	case DirectionImproving:
		return "↓"
	case DirectionDegrading:
		return "↑"
	default:
		return "→"
	}
}

// unused — kept for future use
var _ = strings.ToLower
var _ = directionArrow
