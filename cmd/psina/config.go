package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/foxcool/psina/auth"
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
	Token struct {
		RefreshReuseLeeway time.Duration `koanf:"refreshreuseleeway"` // Grace for duplicate refreshes; 0 = strict (default: 10s)
	} `koanf:"token"`
	Cookie struct {
		Enabled  bool   `koanf:"enabled"`
		Domain   string `koanf:"domain"`
		Secure   bool   `koanf:"secure"`   // HTTPS only
		SameSite string `koanf:"samesite"` // "strict", "lax", "none"
		Path     string `koanf:"path"`     // Cookie path (default: "/")
	} `koanf:"cookie"`
	PAT struct {
		Enabled       bool          `koanf:"enabled"`       // Personal access tokens (default: true)
		MaxPerUser    int           `koanf:"maxperuser"`    // Max tokens per user; -1 = unlimited (default: 50)
		MaxTTL        time.Duration `koanf:"maxttl"`        // Max token lifetime; 0 = unlimited
		TouchInterval time.Duration `koanf:"touchinterval"` // Min interval between last-used updates; -1 = every verify (default: 1m)
	} `koanf:"pat"`
	OAuth struct {
		AutoLinkEmail bool              `koanf:"autolinkemail"` // Link a first sign-in to a passwordless account with the same verified email (default: true)
		Google        OAuthClientConfig `koanf:"google"`
		GitHub        OAuthClientConfig `koanf:"github"`
	} `koanf:"oauth"`
}

// OAuthClientConfig holds one OAuth provider's client registration.
type OAuthClientConfig struct {
	ClientID     string   `koanf:"clientid"`
	ClientSecret string   `koanf:"clientsecret"`
	RedirectURIs []string `koanf:"redirecturis"` // Exact-match whitelist; comma-separated in env
}

func loadConfig(args []string) (*Config, error) {
	k := koanf.New(".")

	// Default values
	defaults := map[string]any{
		"logger.level":             "info",
		"logger.format":            "json",
		"server.port":              8080,
		"db.tableprefix":           "",
		"jwt.algorithm":            "RS256",
		"token.refreshreuseleeway": auth.DefaultRefreshReuseLeeway.String(),
		"cookie.enabled":           false,
		"cookie.secure":            true,
		"cookie.samesite":          "strict",
		"cookie.path":              "/",
		"pat.enabled":              true,
		"pat.maxperuser":           auth.DefaultPATMaxPerUser,
		"pat.maxttl":               "0s",
		"pat.touchinterval":        auth.DefaultPATTouchInterval.String(),
		"oauth.autolinkemail":      true,
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
	if err := f.Parse(args); err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}

	// Load config file if provided. Keys are lowercased to match the defaults
	// and env keys: koanf keeps YAML keys as written, so a documented
	// "tablePrefix" would sit beside the default "tableprefix" and lose to it.
	if *configFile != "" {
		fk := koanf.New(".")
		if err := fk.Load(file.Provider(*configFile), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("load config file: %w", err)
		}
		lowered := make(map[string]any, len(fk.Keys()))
		for key, value := range fk.All() {
			lowered[strings.ToLower(key)] = value
		}
		if err := k.Load(confmap.Provider(lowered, "."), nil); err != nil {
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

	config.OAuth.Google.RedirectURIs = splitList(config.OAuth.Google.RedirectURIs)
	config.OAuth.GitHub.RedirectURIs = splitList(config.OAuth.GitHub.RedirectURIs)

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

	if c.Token.RefreshReuseLeeway < 0 {
		return fmt.Errorf("token.refreshreuseleeway must not be negative: %s", c.Token.RefreshReuseLeeway)
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

	if err := validateOAuthClient("google", c.OAuth.Google); err != nil {
		return err
	}
	if err := validateOAuthClient("github", c.OAuth.GitHub); err != nil {
		return err
	}

	return nil
}

// validateOAuthClient rejects a half-configured provider. A provider is
// enabled by its client id; a partial config is a typo, not a request to run
// without it.
func validateOAuthClient(name string, o OAuthClientConfig) error {
	if o.ClientID != "" || o.ClientSecret != "" || len(o.RedirectURIs) > 0 {
		if o.ClientID == "" || o.ClientSecret == "" || len(o.RedirectURIs) == 0 {
			return fmt.Errorf("oauth.%s needs clientid, clientsecret and redirecturis together", name)
		}
	}
	return nil
}

// splitList normalizes a list setting: an env variable arrives as one
// comma-separated string, a YAML list as items. Values are trimmed, empty
// ones (e.g. from a trailing comma) dropped.
func splitList(values []string) []string {
	var out []string
	for _, v := range values {
		for item := range strings.SplitSeq(v, ",") {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}
