package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/isthobbit/vigyl/internal/detect"
	"github.com/spf13/cobra"
)

var detectCmd = &cobra.Command{
	Use:   "detect [path]",
	Short: "Detect languages and frameworks in a project",
	Long:  `Walk a project directory and report what languages and frameworks are present.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDetect,
}

func init() {
	rootCmd.AddCommand(detectCmd)
}

func runDetect(cmd *cobra.Command, args []string) error {
	path, err := resolvePath(args)
	if err != nil {
		return err
	}

	stack, err := detect.Analyse(path)
	if err != nil {
		return fmt.Errorf("stack detection failed: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(stack)
	}

	printStack(stack, path)
	return nil
}

func printStack(stack *detect.Stack, path string) {
	fmt.Printf("Stack Detection â€” %s\n\n", path)

	if len(stack.Languages) == 0 {
		fmt.Println("  No source files detected.")
		return
	}

	// Languages table.
	fmt.Println("  Languages:")
	fmt.Println("  " + strings.Repeat("â”€", 40))
	for _, l := range stack.Languages {
		bar := progressBar(l.Confidence, 20)
		fmt.Printf("  %-14s  %s  %5.1f%%  (%d files)\n",
			l.Name, bar, l.Confidence*100, l.FileCount,
		)
	}

	// Frameworks.
	if len(stack.Frameworks) > 0 {
		fmt.Println()
		fmt.Println("  Frameworks detected:")
		fmt.Println("  " + strings.Repeat("â”€", 40))
		for _, f := range stack.Frameworks {
			fmt.Printf("  %-16s  [%s]\n", f.Name, f.Language)
		}
	}

	fmt.Printf("\n  Primary language: %s\n", stack.Primary.Name)
}

// progressBar renders a simple ASCII bar scaled to width characters.
func progressBar(ratio float64, width int) string {
	filled := int(ratio * float64(width))
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("â–ˆ", filled) + strings.Repeat("â–‘", width-filled) + "]"
}
