package cli

import (
	"fmt"
	"runtime"

	"github.com/isthobbit/kinga/pkg/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("jensec %s\n", version.Version)
		fmt.Printf("  commit:   %s\n", version.Commit)
		fmt.Printf("  built:    %s\n", version.BuildDate)
		fmt.Printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
