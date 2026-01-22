package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

// Config holds application configuration.
type Config struct {
	Logger struct {
		Level  string `koanf:"level"`
		Format string `koanf:"format"` // "json" or "text"
	} `koanf:"logger"`
	Server struct {
		Port int `koanf:"port"`
	} `koanf:"server"`
	DB struct {
		URL string `koanf:"url"`
	} `koanf:"db"`
	JWT struct {
		PrivateKeyPath string `koanf:"privateKeyPath"`
		// If empty, generates ephemeral key (for dev)
	} `koanf:"jwt"`
}

func loadConfig() (*Config, error) {
	k := koanf.New(".")

	// Default values
	defaults := map[string]any{
		"logger.level":  "info",
		"logger.format": "json",
		"server.port":   8080,
	}
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return nil, fmt.Errorf("load defaults: %w", err)
	}

	// Command line flags
	f := pflag.NewFlagSet("psina", pflag.ContinueOnError)
	f.Usage = func() {
		fmt.Println("psina - authentication service")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  psina [flags]")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println(f.FlagUsages())
	}
	configFile := f.StringP("config", "c", "", "Path to config file (yaml)")
	if err := f.Parse(os.Args[1:]); err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}

	// Load config file if provided
	if *configFile != "" {
		if err := k.Load(file.Provider(*configFile), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("load config file: %w", err)
		}
	}

	// Load environment variables (PSINA_SERVER_PORT -> server.port)
	if err := k.Load(env.Provider("PSINA_", ".", func(s string) string {
		return strings.ReplaceAll(
			strings.ToLower(strings.TrimPrefix(s, "PSINA_")),
			"_", ".",
		)
	}), nil); err != nil {
		return nil, fmt.Errorf("load env: %w", err)
	}

	// Unmarshal
	var config Config
	if err := k.Unmarshal("", &config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &config, nil
}
