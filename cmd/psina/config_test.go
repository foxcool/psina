package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
