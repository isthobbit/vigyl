package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View or modify jensec configuration",
}

var configViewCmd = &cobra.Command{
	Use:   "view",
	Short: "Print current configuration",
	RunE:  runConfigView,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

func init() {
	configCmd.AddCommand(configViewCmd)
	configCmd.AddCommand(configSetCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfigView(cmd *cobra.Command, args []string) error {
	settings := viper.AllSettings()
	if len(settings) == 0 {
		fmt.Println("No configuration found. Using defaults.")
		fmt.Println("Config file location: ~/.kinga/config.yaml")
		return nil
	}
	fmt.Println("Current configuration:")
	for k, v := range settings {
		fmt.Printf("  %-20s = %v\n", k, v)
	}
	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key, value := args[0], args[1]
	viper.Set(key, value)

	if err := viper.WriteConfig(); err != nil {
		// Config file may not exist yet — try creating it.
		if err := viper.SafeWriteConfig(); err != nil {
			return fmt.Errorf("could not write config: %w", err)
		}
	}

	fmt.Printf("Set %s = %s\n", key, value)
	return nil
}
