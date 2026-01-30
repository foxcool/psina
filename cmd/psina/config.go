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
		URL         string `koanf:"url"`
		TablePrefix string `koanf:"tableprefix"` // Table name prefix (default: "psina_")
	} `koanf:"db"`
	JWT struct {
		PrivateKeyPath string `koanf:"privatekeypath"`
		PrivateKey     string `koanf:"privatekey"` // PEM-encoded key (alternative to path)
		Algorithm      string `koanf:"algorithm"`  // "RS256" or "ES256" (default: RS256)
	} `koanf:"jwt"`
	Cookie struct {
		Enabled  bool   `koanf:"enabled"`
		Domain   string `koanf:"domain"`
		Secure   bool   `koanf:"secure"`   // HTTPS only
		SameSite string `koanf:"samesite"` // "strict", "lax", "none"
		Path     string `koanf:"path"`     // Cookie path (default: "/")
	} `koanf:"cookie"`
}

func loadConfig() (*Config, error) {
	k := koanf.New(".")

	// Default values
	defaults := map[string]any{
		"logger.level":    "info",
		"logger.format":   "json",
		"server.port":     8080,
		"db.tableprefix":  "",
		"jwt.algorithm":   "RS256",
		"cookie.enabled":  false,
		"cookie.secure":   true,
		"cookie.samesite": "strict",
		"cookie.path":     "/",
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

	// Validate
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &config, nil
}

func validateConfig(c *Config) error {
	// Validate JWT algorithm
	switch c.JWT.Algorithm {
	case "RS256", "ES256":
		// OK
	default:
		return fmt.Errorf("unsupported JWT algorithm: %s (supported: RS256, ES256)", c.JWT.Algorithm)
	}

	// Validate SameSite
	switch strings.ToLower(c.Cookie.SameSite) {
	case "strict", "lax", "none", "":
		// OK
	default:
		return fmt.Errorf("invalid cookie.samesite: %s (supported: strict, lax, none)", c.Cookie.SameSite)
	}

	// Cookie domain required if cookies enabled
	if c.Cookie.Enabled && c.Cookie.Domain == "" {
		return fmt.Errorf("cookie.domain is required when cookies are enabled")
	}

	return nil
}
