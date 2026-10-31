package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
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
	// Dev allows the fallbacks that lose data on restart: the in-memory store
	// (empty db.url) and an ephemeral JWT key. Without it either is a startup
	// error, so a deploy that lost its DB URL or key fails instead of serving.
	Dev    bool `koanf:"dev"`
	Logger struct {
		Level  string `koanf:"level"`
		Format string `koanf:"format"` // "json" or "text"
	} `koanf:"logger"`
	Server struct {
		Port           int      `koanf:"port"`
		TrustedProxies []string `koanf:"trustedproxies"` // CIDRs or IPs whose X-Forwarded-For is believed; comma-separated in env (default: none)
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
	Wallet struct {
		Domain       string        `koanf:"domain"`       // SIWE domain; wallet sign-in is enabled when set
		URI          string        `koanf:"uri"`          // SIWE URI; required with domain
		Statement    string        `koanf:"statement"`    // Shown to the signer; optional
		ChallengeTTL time.Duration `koanf:"challengettl"` // Time to sign (default: 5m)
		EVMChains    []string      `koanf:"evmchains"`    // name=chainID pairs; comma-separated in env (default: ethereum=1)
	} `koanf:"wallet"`
}

// evmChain is one parsed wallet.evmchains entry.
type evmChain struct {
	Name string
	ID   int
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
		"dev":                      false,
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
		"wallet.challengettl":      auth.DefaultWalletChallengeTTL.String(),
		"wallet.evmchains":         []string{"ethereum=1"},
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

	if *configFile != "" {
		fileConf, err := loadConfigFile(*configFile)
		if err != nil {
			return nil, err
		}
		if err := k.Load(confmap.Provider(fileConf, "."), nil); err != nil {
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
	config.Wallet.EVMChains = splitList(config.Wallet.EVMChains)
	config.Server.TrustedProxies = splitList(config.Server.TrustedProxies)

	// Validate
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &config, nil
}

// loadConfigFile reads a YAML config as flat lowercased keys. Lowercasing
// matches the defaults and env keys: koanf keeps YAML keys as written, so a
// documented "tablePrefix" would sit beside the default "tableprefix" and lose
// to it. Two spellings of one key are an error rather than a map-order coin
// toss. A null (a section or key written with no value) is dropped: merged as
// is, it would replace the whole default subtree beneath it.
func loadConfigFile(path string) (map[string]any, error) {
	fk := koanf.New(".")
	if err := fk.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("load config file: %w", err)
	}
	all := fk.All()
	lowered := make(map[string]any, len(all))
	spelling := make(map[string]string, len(all))
	for key, value := range all {
		lower := strings.ToLower(key)
		if prev, ok := spelling[lower]; ok {
			return nil, fmt.Errorf("load config file: duplicate key %q and %q", prev, key)
		}
		spelling[lower] = key
		if value != nil {
			lowered[lower] = value
		}
	}
	return lowered, nil
}

func validateConfig(c *Config) error {
	if err := validateDevFallbacks(c); err != nil {
		return err
	}

	if _, err := parseLogLevel(c.Logger.Level); err != nil {
		return err
	}
	switch strings.ToLower(c.Logger.Format) {
	case "json", "text", "":
		// OK
	default:
		return fmt.Errorf("invalid logger.format: %s (supported: json, text)", c.Logger.Format)
	}

	// Validate JWT algorithm
	switch c.JWT.Algorithm {
	case "RS256", "ES256":
		// OK
	default:
		return fmt.Errorf("unsupported JWT algorithm: %s (supported: RS256, ES256)", c.JWT.Algorithm)
	}

	if _, err := parseTrustedProxies(c.Server.TrustedProxies); err != nil {
		return err
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

	return validateWallet(c)
}

// validateDevFallbacks refuses the data-losing fallbacks outside dev mode;
// see Config.Dev.
func validateDevFallbacks(c *Config) error {
	if c.Dev {
		return nil
	}
	if c.DB.URL == "" {
		return fmt.Errorf("db.url is empty: set it, or set dev: true (PSINA_DEV) to use the in-memory store")
	}
	if c.JWT.PrivateKey == "" && c.JWT.PrivateKeyPath == "" {
		return fmt.Errorf("no jwt key: set jwt.privatekeypath or jwt.privatekey, or set dev: true (PSINA_DEV) to use an ephemeral key")
	}
	return nil
}

// parseLogLevel maps logger.level; empty means the default, info. An unknown
// level is an error and also yields info.
func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid logger.level: %s (supported: debug, info, warn, error)", level)
	}
}

// validateWallet rejects a half-configured wallet sign-in and values that
// would corrupt the line-oriented message a wallet signs.
func validateWallet(c *Config) error {
	w := c.Wallet
	// Chains are checked even while wallet sign-in is off: a typo there should
	// not wait for the day the domain is set.
	if _, err := parseEVMChains(w.EVMChains); err != nil {
		return err
	}
	if w.Domain == "" && w.URI == "" {
		return nil
	}
	if w.Domain == "" || w.URI == "" {
		return fmt.Errorf("wallet needs domain and uri together")
	}
	if strings.ContainsAny(w.Domain+w.URI+w.Statement, "\r\n") {
		return fmt.Errorf("wallet.domain, wallet.uri and wallet.statement must be single-line")
	}
	if w.ChallengeTTL < 0 {
		return fmt.Errorf("wallet.challengettl must not be negative: %s", w.ChallengeTTL)
	}
	return nil
}

// parseEVMChains reads name=chainID pairs, e.g. "polygon=137". A chain id
// may appear once: two names for one chain would give one wallet two users.
func parseEVMChains(entries []string) ([]evmChain, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("wallet.evmchains is empty")
	}
	chains := make([]evmChain, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	seenID := make(map[int]bool, len(entries))
	for _, entry := range entries {
		name, rawID, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		id, err := strconv.Atoi(strings.TrimSpace(rawID))
		if !ok || name == "" || err != nil || id <= 0 {
			return nil, fmt.Errorf("wallet.evmchains: %q is not name=chainID", entry)
		}
		if seen[name] {
			return nil, fmt.Errorf("wallet.evmchains: duplicate chain %q", name)
		}
		if seenID[id] {
			return nil, fmt.Errorf("wallet.evmchains: duplicate chain id %d", id)
		}
		seen[name], seenID[id] = true, true
		chains = append(chains, evmChain{Name: name, ID: id})
	}
	return chains, nil
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

// parseTrustedProxies reads CIDRs; a bare IP is a single-host prefix.
// IPv4-mapped entries are unmapped: the addresses matched against them are, and
// a 128-bit prefix never contains a 32-bit address.
func parseTrustedProxies(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		p, err := netip.ParsePrefix(e)
		if err != nil {
			a, addrErr := netip.ParseAddr(e)
			if addrErr != nil {
				return nil, fmt.Errorf("server.trustedproxies: %q is not a CIDR or IP", e)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = p.Masked()
		// Masking keeps the ::ffff: marker only when Bits() >= 96.
		if a := p.Addr(); a.Is4In6() {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
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
