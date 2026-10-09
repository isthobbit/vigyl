package cli

import (
	"fmt"
	"os"

	"github.com/isthobbit/vigyl/pkg/output"
	"github.com/isthobbit/vigyl/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Global flags shared across all subcommands.
var (
	cfgFile string
	jsonOut bool
	noColor bool
	verbose bool
)

// rootCmd is the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:     "jensec",
	Short:   "vigyl — local-first security scanner for developers",
	Version: version.Version,
	// Plain-text banner: help is often piped or read in a pager.
	Long: "\n" + output.Banner(true) + `
Scan your code for leaked secrets, vulnerable code and vulnerable
dependencies. No cloud account required. Add --offline to scan with no
network access at all.`,
}

// Execute is the entry point called from main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Execute prints the returned error itself; stop cobra printing it too.
	rootCmd.SilenceErrors = true

	// Persistent flags are available to every subcommand.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.vigyl/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "output results as JSON")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Bind flags to viper so they can also be set via config file or env vars.
	viper.BindPFlag("output.json", rootCmd.PersistentFlags().Lookup("json"))
	viper.BindPFlag("output.no_color", rootCmd.PersistentFlags().Lookup("no-color"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not find home directory:", err)
			return
		}
		viper.AddConfigPath(fmt.Sprintf("%s/.vigyl", home))
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Allow any config key to be overridden with a vigyl_ env var.
	// e.g. vigyl_VERBOSE=true
	viper.SetEnvPrefix("vigyl")
	viper.AutomaticEnv()

	// Silently ignore missing config file — it's optional.
	_ = viper.ReadInConfig()
}
