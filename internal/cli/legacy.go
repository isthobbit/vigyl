package cli

import (
	"fmt"
	"os"

	"github.com/isthobbit/vigyl/internal/config"
)

// migrateLegacyDir moves files from ~/.kinga to ~/.vigyl on first run after
// upgrading and says what it did. It never blocks a command: on failure the
// user is warned and the old files stay where they were.
func migrateLegacyDir() {
	m, err := config.MigrateLegacyDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not move jensec data from ~/.kinga to ~/.vigyl: %v\n", err)
		return
	}
	if len(m.Moved) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, "jensec now keeps its data in ~/.vigyl. Moved:")
	for _, mv := range m.Moved {
		fmt.Fprintf(os.Stderr, "  %s\n", mv)
	}
	if m.MovedConfig {
		fmt.Fprintln(os.Stderr, "Settings in the moved config.yaml were not being read before and now apply. Review them with 'jensec config view'.")
	}
	fmt.Fprintln(os.Stderr)
}
