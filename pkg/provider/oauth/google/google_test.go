package google

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/foxcool/psina/pkg/provider/oauth"
)

const (
	testClientID = "client-123.apps.googleusercontent.com"
	testRedirect = "https://app.example.com/callback"
)

func testConfig() Config {
	return Config{
		ClientID:     testClientID,
		ClientSecret: "secret",
		RedirectURIs: []string{testRedirect},
	}
}

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"valid", func(c *Config) {}, ""},
		{"missing client id", func(c *Config) { c.ClientID = "" }, "client id"},
		{"missing client secret", func(c *Config) { c.ClientSecret = "" }, "client secret"},
		{"no redirect uris", func(c *Config) { c.RedirectURIs = nil }, "redirect uri"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			tt.mutate(&cfg)
			_, err := New(cfg)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestProvider_AuthCodeURL(t *testing.T) {
	p, err := New(testConfig())
	require.NoError(t, err)

	got, err := p.AuthCodeURL("state-xyz", testRedirect)
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, testClientID, q.Get("client_id"))
	assert.Equal(t, testRedirect, q.Get("redirect_uri"))
	assert.Equal(t, "state-xyz", q.Get("state"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Contains(t, q.Get("scope"), "openid")
	assert.Contains(t, q.Get("scope"), "email")

	// Whitelist is exact-match
	_, err = p.AuthCodeURL("state-xyz", "https://evil.example.com/callback")
	assert.True(t, errors.Is(err, oauth.ErrRedirectURINotAllowed), "expected ErrRedirectURINotAllowed, got: %v", err)
}

// signIDToken produces a well-formed RS256-signed ID token with the given claims.
func signIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func validClaims() map[string]any {
	return map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            testClientID,
		"sub":            "google-sub-42",
		"email":          "user@gmail.com",
		"email_verified": true,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
	}
}

// fakeTokenEndpoint returns a provider wired to an httptest token endpoint
// that responds with the given ID token.
func fakeTokenEndpoint(t *testing.T, idToken string) *Provider {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"access_token": "ya29.access",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if idToken != "" {
			resp["id_token"] = idToken
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	t.Cleanup(srv.Close)

	p, err := newWithEndpoint(testConfig(), oauth2.Endpoint{
		AuthURL:  srv.URL + "/auth",
		TokenURL: srv.URL + "/token",
	})
	require.NoError(t, err)
	return p
}

func TestProvider_ExchangeCode(t *testing.T) {
	p := fakeTokenEndpoint(t, signIDToken(t, validClaims()))

	info, err := p.ExchangeCode(context.Background(), "auth-code", testRedirect)
	require.NoError(t, err)
	assert.Equal(t, "google-sub-42", info.ExternalID)
	assert.Equal(t, "user@gmail.com", info.Email)
	assert.True(t, info.EmailVerified)
}

func TestProvider_ExchangeCode_Rejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong audience", func(c map[string]any) { c["aud"] = "another-client" }},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example.com" }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{"missing sub", func(c map[string]any) { delete(c, "sub") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := validClaims()
			tt.mutate(claims)
			p := fakeTokenEndpoint(t, signIDToken(t, claims))

			_, err := p.ExchangeCode(context.Background(), "auth-code", testRedirect)
			assert.True(t, errors.Is(err, oauth.ErrInvalidToken), "expected ErrInvalidToken, got: %v", err)
		})
	}
}

func TestProvider_ExchangeCode_NoIDToken(t *testing.T) {
	p := fakeTokenEndpoint(t, "")

	_, err := p.ExchangeCode(context.Background(), "auth-code", testRedirect)
	assert.True(t, errors.Is(err, oauth.ErrInvalidToken), "expected ErrInvalidToken, got: %v", err)
}

func TestProvider_ExchangeCode_MalformedIDToken(t *testing.T) {
	p := fakeTokenEndpoint(t, "not-a-jwt")

	_, err := p.ExchangeCode(context.Background(), "auth-code", testRedirect)
	assert.True(t, errors.Is(err, oauth.ErrInvalidToken), "expected ErrInvalidToken, got: %v", err)
}

func TestProvider_ExchangeCode_RedirectWhitelist(t *testing.T) {
	p := fakeTokenEndpoint(t, signIDToken(t, validClaims()))

	_, err := p.ExchangeCode(context.Background(), "auth-code", "https://evil.example.com/callback")
	assert.True(t, errors.Is(err, oauth.ErrRedirectURINotAllowed), "expected ErrRedirectURINotAllowed, got: %v", err)
}

func TestProvider_AlternateIssuerForm(t *testing.T) {
	claims := validClaims()
	claims["iss"] = "accounts.google.com" // Google may omit the scheme
	p := fakeTokenEndpoint(t, signIDToken(t, claims))

	info, err := p.ExchangeCode(context.Background(), "auth-code", testRedirect)
	require.NoError(t, err)
	assert.Equal(t, "google-sub-42", info.ExternalID)
}
