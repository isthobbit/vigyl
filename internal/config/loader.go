package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Load reads configuration from disk and environment variables,
// merges it with defaults, validates it, and returns the result.
//
// Priority order (highest â†’ lowest):
//  1. Environment variables (vigyl_*)
//  2. Config file (~/.vigyl/config.yaml or --config flag)
//  3. Built-in defaults
func Load(cfgFile string) (*Config, error) {
	v := viper.New()
	applyDefaults(v)

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(filepath.Join(home, ".vigyl"))
		}
		v.AddConfigPath(".")
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	v.SetEnvPrefix("vigyl")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// A missing config file is fine â€” we fall back to defaults.
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("could not parse config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Write persists the current viper settings to the config file.
// Creates ~/.vigyl/config.yaml if it does not exist.
func Write(key, value string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %w", err)
	}

	dir := filepath.Join(home, ".vigyl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("could not create config directory: %w", err)
	}

	cfgPath := filepath.Join(dir, "config.yaml")

	v := viper.New()
	v.SetConfigFile(cfgPath)
	v.SetConfigType("yaml")

	// Load existing config so we don't overwrite other keys.
	_ = v.ReadInConfig()

	v.Set(key, value)

	return v.WriteConfigAs(cfgPath)
}

// validate checks that config values are within acceptable ranges.
func validate(cfg *Config) error {
	if !ValidFailOnValues[strings.ToLower(cfg.Scan.FailOn)] {
		return fmt.Errorf(
			"invalid scan.fail_on value %q â€” must be one of: critical, high, medium, low, none",
			cfg.Scan.FailOn,
		)
	}
	return nil
}

// applyDefaults registers default values with a viper instance.
func applyDefaults(v *viper.Viper) {
	d := Defaults()
	v.SetDefault("output.json", d.Output.JSON)
	v.SetDefault("output.no_color", d.Output.NoColor)
	v.SetDefault("output.verbose", d.Output.Verbose)
	v.SetDefault("scan.fail_on", d.Scan.FailOn)
	v.SetDefault("scan.timeout", d.Scan.Timeout.String())
	v.SetDefault("scan.exclude_paths", d.Scan.ExcludePaths)
	v.SetDefault("scan.semgrep_rules", d.Scan.SemgrepRules)
	v.SetDefault("storage.max_history", d.Storage.MaxHistory)
}
