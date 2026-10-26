package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/provider/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_OAuthFromEnv(t *testing.T) {
	tests := []struct {
		name   string
		client func(*Config) OAuthClientConfig
	}{
		{"google", func(c *Config) OAuthClientConfig { return c.OAuth.Google }},
		{"github", func(c *Config) OAuthClientConfig { return c.OAuth.GitHub }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := "PSINA_OAUTH_" + strings.ToUpper(tt.name) + "_"
			t.Setenv(prefix+"CLIENTID", "client")
			t.Setenv(prefix+"CLIENTSECRET", "secret")
			t.Setenv(prefix+"REDIRECTURIS", "https://a.example/cb, https://b.example/cb,")

			config, err := loadConfig(nil)
			require.NoError(t, err)
			assert.Equal(t, []string{"https://a.example/cb", "https://b.example/cb"}, tt.client(config).RedirectURIs)
			assert.True(t, config.OAuth.AutoLinkEmail, "auto-link defaults to on")

			providers, err := createOAuthProviders(config)
			require.NoError(t, err)
			require.Len(t, providers, 1)
			assert.Equal(t, tt.name, providers[0].ProviderName())
		})
	}
}

func TestLoadConfig_OAuthBothProviders(t *testing.T) {
	for _, name := range []string{"GOOGLE", "GITHUB"} {
		t.Setenv("PSINA_OAUTH_"+name+"_CLIENTID", "client")
		t.Setenv("PSINA_OAUTH_"+name+"_CLIENTSECRET", "secret")
		t.Setenv("PSINA_OAUTH_"+name+"_REDIRECTURIS", "https://a.example/cb")
	}

	config, err := loadConfig(nil)
	require.NoError(t, err)
	providers, err := createOAuthProviders(config)
	require.NoError(t, err)
	assert.Len(t, providers, 2)
}

func TestLoadConfig_OAuthDisabledByDefault(t *testing.T) {
	config, err := loadConfig(nil)
	require.NoError(t, err)
	providers, err := createOAuthProviders(config)
	require.NoError(t, err)
	assert.Empty(t, providers)
}

func TestValidateConfig_OAuthIncomplete(t *testing.T) {
	tests := []struct {
		name             string
		clientID, secret string
		redirectURIs     []string
	}{
		{"id only", "client", "", nil},
		{"no redirect uris", "client", "secret", nil},
		{"secret without id", "", "secret", []string{"https://a.example/cb"}},
	}
	for _, tt := range tests {
		client := OAuthClientConfig{ClientID: tt.clientID, ClientSecret: tt.secret, RedirectURIs: tt.redirectURIs}
		t.Run("google "+tt.name, func(t *testing.T) {
			c := &Config{}
			c.JWT.Algorithm = "RS256"
			c.OAuth.Google = client
			assert.ErrorContains(t, validateConfig(c), "oauth.google")
		})
		t.Run("github "+tt.name, func(t *testing.T) {
			c := &Config{}
			c.JWT.Algorithm = "RS256"
			c.OAuth.GitHub = client
			assert.ErrorContains(t, validateConfig(c), "oauth.github")
		})
	}
}

// YAML keys are written in camelCase in the docs; they must win over the
// lowercase defaults instead of sitting beside them.
func TestLoadConfig_YAMLCamelCaseKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
db:
  tablePrefix: "auth_"
pat:
  maxPerUser: 7
cookie:
  sameSite: lax
oauth:
  autoLinkEmail: false
  google:
    clientID: client
    clientSecret: secret
    redirectURIs: ["https://a.example/cb"]
  github:
    clientID: gh-client
    clientSecret: gh-secret
    redirectURIs: ["https://b.example/cb"]
`), 0o600))

	config, err := loadConfig([]string{"-c", path})
	require.NoError(t, err)
	assert.Equal(t, "auth_", config.DB.TablePrefix)
	assert.Equal(t, 7, config.PAT.MaxPerUser)
	assert.Equal(t, "lax", config.Cookie.SameSite)
	assert.False(t, config.OAuth.AutoLinkEmail, "a safety toggle set in YAML must not be ignored")
	assert.Equal(t, []string{"https://a.example/cb"}, config.OAuth.Google.RedirectURIs)
	assert.Equal(t, "gh-client", config.OAuth.GitHub.ClientID)
	assert.Equal(t, []string{"https://b.example/cb"}, config.OAuth.GitHub.RedirectURIs)
}

func TestLoadConfig_OAuthGoogleBlankRedirectURIs(t *testing.T) {
	t.Setenv("PSINA_OAUTH_GOOGLE_CLIENTID", "client")
	t.Setenv("PSINA_OAUTH_GOOGLE_CLIENTSECRET", "secret")
	t.Setenv("PSINA_OAUTH_GOOGLE_REDIRECTURIS", " , ")

	_, err := loadConfig(nil)
	assert.ErrorContains(t, err, "oauth.google")
}

// Every PSINA_* name in the docs and deploy files must reach a Config field;
// koanf drops an unknown one silently and the server runs on its default.
func TestDocumentedEnvNamesMapToConfig(t *testing.T) {
	keys := map[string]bool{}
	collectKoanfKeys(reflect.TypeOf(Config{}), "", keys)

	// Compose interpolation variables, not read by psina.
	notConfig := map[string]bool{"PSINA_DOMAIN": true}

	name := regexp.MustCompile(`PSINA_[A-Z_]+`)
	for _, file := range []string{"../../README.md", "../../deploy/compose.yaml", "../../deploy/secrets.env.example"} {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		for _, env := range name.FindAllString(string(data), -1) {
			if notConfig[env] {
				continue
			}
			key := strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(env, "PSINA_")), "_", ".")
			assert.True(t, keys[key], "%s: %s maps to %q, which is not a config key", file, env, key)
		}
	}
}

func collectKoanfKeys(t reflect.Type, prefix string, out map[string]bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("koanf")
		if tag == "" {
			continue
		}
		if f.Type.Kind() == reflect.Struct {
			collectKoanfKeys(f.Type, prefix+tag+".", out)
			continue
		}
		out[prefix+tag] = true
	}
}

func TestLoadConfig_Wallet(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		config, err := loadConfig(nil)
		require.NoError(t, err)
		d, err := createWalletDispatcher(config)
		require.NoError(t, err)
		assert.Nil(t, d)
	})

	t.Run("enabled from env with the default chain", func(t *testing.T) {
		t.Setenv("PSINA_WALLET_DOMAIN", "app.example.com")
		t.Setenv("PSINA_WALLET_URI", "https://app.example.com")

		config, err := loadConfig(nil)
		require.NoError(t, err)
		assert.Equal(t, auth.DefaultWalletChallengeTTL, config.Wallet.ChallengeTTL)
		d, err := createWalletDispatcher(config)
		require.NoError(t, err)
		assert.Equal(t, []string{"ethereum"}, d.Chains())
	})

	t.Run("chains from env", func(t *testing.T) {
		t.Setenv("PSINA_WALLET_DOMAIN", "app.example.com")
		t.Setenv("PSINA_WALLET_URI", "https://app.example.com")
		t.Setenv("PSINA_WALLET_EVMCHAINS", "ethereum=1, polygon=137,")

		config, err := loadConfig(nil)
		require.NoError(t, err)
		d, err := createWalletDispatcher(config)
		require.NoError(t, err)
		chains := d.Chains()
		sort.Strings(chains)
		assert.Equal(t, []string{"ethereum", "polygon"}, chains)

		p, err := d.Provider("polygon")
		require.NoError(t, err)
		assert.Contains(t, p.BuildMessage("0x0", "n0nce123", wallet.MessageOpts{}), "Chain ID: 137")
	})
}

func TestValidateWallet(t *testing.T) {
	valid := func() *Config {
		c := &Config{}
		c.Wallet.Domain = "app.example.com"
		c.Wallet.URI = "https://app.example.com"
		c.Wallet.EVMChains = []string{"ethereum=1"}
		return c
	}

	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"valid", func(*Config) {}, ""},
		{"disabled skips the rest", func(c *Config) { c.Wallet.Domain, c.Wallet.URI, c.Wallet.Statement = "", "", "a\nb" }, ""},
		{"disabled still checks chains", func(c *Config) { c.Wallet.Domain, c.Wallet.URI, c.Wallet.EVMChains = "", "", []string{"ethereum"} }, "not name=chainID"},
		{"domain without uri", func(c *Config) { c.Wallet.URI = "" }, "domain and uri together"},
		{"uri without domain", func(c *Config) { c.Wallet.Domain = "" }, "domain and uri together"},
		{"line break in statement", func(c *Config) { c.Wallet.Statement = "hi\nURI: https://evil.example" }, "single-line"},
		{"carriage return in uri", func(c *Config) { c.Wallet.URI += "\r" }, "single-line"},
		{"negative ttl", func(c *Config) { c.Wallet.ChallengeTTL = -time.Second }, "must not be negative"},
		{"no chains", func(c *Config) { c.Wallet.EVMChains = nil }, "evmchains is empty"},
		{"chain without id", func(c *Config) { c.Wallet.EVMChains = []string{"ethereum"} }, "not name=chainID"},
		{"chain id not a number", func(c *Config) { c.Wallet.EVMChains = []string{"ethereum=one"} }, "not name=chainID"},
		{"chain id zero", func(c *Config) { c.Wallet.EVMChains = []string{"ethereum=0"} }, "not name=chainID"},
		{"empty name", func(c *Config) { c.Wallet.EVMChains = []string{"=1"} }, "not name=chainID"},
		{"duplicate chain", func(c *Config) { c.Wallet.EVMChains = []string{"ethereum=1", "ethereum=5"} }, "duplicate chain"},
		{"duplicate chain id", func(c *Config) { c.Wallet.EVMChains = []string{"ethereum=1", "mainnet=1"} }, "duplicate chain id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mutate(c)
			err := validateWallet(c)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoadConfig_TrustedProxies(t *testing.T) {
	t.Run("none by default", func(t *testing.T) {
		config, err := loadConfig(nil)
		require.NoError(t, err)
		assert.Empty(t, config.Server.TrustedProxies)
	})

	t.Run("from env", func(t *testing.T) {
		t.Setenv("PSINA_SERVER_TRUSTEDPROXIES", "172.16.0.0/12, 10.0.0.7,fd00::/8")

		config, err := loadConfig(nil)
		require.NoError(t, err)
		prefixes, err := parseTrustedProxies(config.Server.TrustedProxies)
		require.NoError(t, err)
		assert.Equal(t, []netip.Prefix{
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("10.0.0.7/32"),
			netip.MustParsePrefix("fd00::/8"),
		}, prefixes)
	})

	t.Run("invalid entry", func(t *testing.T) {
		t.Setenv("PSINA_SERVER_TRUSTEDPROXIES", "traefik")

		_, err := loadConfig(nil)
		require.ErrorContains(t, err, "server.trustedproxies")
	})
}
