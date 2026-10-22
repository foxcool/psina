package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/foxcool/psina/provider/oauth"
)

const (
	testClientID = "Iv1.client123"
	testRedirect = "https://app.example.com/callback"
	testToken    = "gho_access"
)

// testVerifier is one PKCE verifier shared by the URL and exchange sides.
var testVerifier = oauth2.GenerateVerifier()

func testParams() oauth.AuthParams {
	return oauth.AuthParams{
		State:        "state-xyz",
		RedirectURI:  testRedirect,
		CodeVerifier: testVerifier,
	}
}

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

	got, err := p.AuthCodeURL(testParams())
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)
	assert.Equal(t, "github.com", u.Host)
	q := u.Query()
	assert.Equal(t, testClientID, q.Get("client_id"))
	assert.Equal(t, testRedirect, q.Get("redirect_uri"))
	assert.Equal(t, "state-xyz", q.Get("state"))
	assert.Equal(t, "user:email", q.Get("scope"))
	assert.Equal(t, oauth2.S256ChallengeFromVerifier(testVerifier), q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Empty(t, q.Get("code_verifier"), "verifier must never leave the server")

	// Whitelist is exact-match
	params := testParams()
	params.RedirectURI = "https://evil.example.com/callback"
	_, err = p.AuthCodeURL(params)
	assert.True(t, errors.Is(err, oauth.ErrRedirectURINotAllowed), "expected ErrRedirectURINotAllowed, got: %v", err)
}

func TestProvider_NonceNotRequired(t *testing.T) {
	p, err := New(testConfig())
	require.NoError(t, err)

	got, err := p.AuthCodeURL(testParams())
	require.NoError(t, err)
	u, err := url.Parse(got)
	require.NoError(t, err)
	assert.False(t, u.Query().Has("nonce"))
}

func TestProvider_MissingCodeVerifier(t *testing.T) {
	p := fakeGitHub(t, fakeResponses{})
	params := testParams()
	params.CodeVerifier = ""

	_, err := p.AuthCodeURL(params)
	assert.True(t, errors.Is(err, oauth.ErrMissingAuthParams), "AuthCodeURL: expected ErrMissingAuthParams, got: %v", err)
	_, err = p.ExchangeCode(context.Background(), "auth-code", params)
	assert.True(t, errors.Is(err, oauth.ErrMissingAuthParams), "ExchangeCode: expected ErrMissingAuthParams, got: %v", err)
}

// fakeResponses scripts the fake GitHub; zero fields fall back to a valid answer.
type fakeResponses struct {
	tokenBody    string // form-encoded, as GitHub answers without Accept: application/json
	userStatus   int
	userBody     string
	emailsStatus int
	emailsBody   string
}

const (
	validUser   = `{"id": 583231, "login": "octocat", "email": "public@example.com"}`
	validEmails = `[
		{"email": "secondary@example.com", "primary": false, "verified": true},
		{"email": "octocat@example.com", "primary": true, "verified": true}
	]`
)

// fakeGitHub returns a provider wired to an httptest server playing both the
// OAuth token endpoint and the REST API.
func fakeGitHub(t *testing.T, r fakeResponses) *Provider {
	t.Helper()
	if r.tokenBody == "" {
		r.tokenBody = "access_token=" + testToken + "&scope=user%3Aemail&token_type=bearer"
	}
	if r.userBody == "" {
		r.userBody = validUser
	}
	if r.emailsBody == "" {
		r.emailsBody = validEmails
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, req *http.Request) {
		assert.NoError(t, req.ParseForm())
		assert.Equal(t, "authorization_code", req.Form.Get("grant_type"))
		assert.Equal(t, testVerifier, req.Form.Get("code_verifier"))
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte(r.tokenBody))
	})
	api := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, "Bearer "+testToken, req.Header.Get("Authorization"))
			if status != 0 {
				w.WriteHeader(status)
			}
			_, _ = w.Write([]byte(body))
		}
	}
	mux.HandleFunc("GET /api/user", api(r.userStatus, r.userBody))
	mux.HandleFunc("GET /api/user/emails", api(r.emailsStatus, r.emailsBody))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p, err := newWithEndpoint(testConfig(), oauth2.Endpoint{
		AuthURL:  srv.URL + "/authorize",
		TokenURL: srv.URL + "/token",
	}, srv.URL+"/api")
	require.NoError(t, err)
	return p
}

func TestProvider_ExchangeCode(t *testing.T) {
	tests := []struct {
		name         string
		emails       string
		wantEmail    string
		wantVerified bool
	}{
		{"primary verified", validEmails, "octocat@example.com", true},
		{
			name:      "primary unverified is reported, not replaced by a verified secondary",
			emails:    `[{"email": "a@example.com", "primary": true, "verified": false}, {"email": "b@example.com", "primary": false, "verified": true}]`,
			wantEmail: "a@example.com",
		},
		{"no primary", `[{"email": "b@example.com", "primary": false, "verified": true}]`, "", false},
		{"no emails", `[]`, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := fakeGitHub(t, fakeResponses{emailsBody: tt.emails})

			info, err := p.ExchangeCode(context.Background(), "auth-code", testParams())
			require.NoError(t, err)
			assert.Equal(t, "583231", info.ExternalID)
			assert.Equal(t, tt.wantEmail, info.Email)
			assert.Equal(t, tt.wantVerified, info.EmailVerified)
		})
	}
}

func TestProvider_ExchangeCode_Failures(t *testing.T) {
	tests := []struct {
		name        string
		resp        fakeResponses
		wantInvalid bool // oauth.ErrInvalidToken expected
	}{
		{name: "token endpoint error", resp: fakeResponses{tokenBody: "error=bad_verification_code&error_description=expired"}},
		{name: "user api unauthorized", resp: fakeResponses{userStatus: http.StatusUnauthorized, userBody: `{"message":"Bad credentials"}`}},
		{name: "emails api forbidden", resp: fakeResponses{emailsStatus: http.StatusForbidden, emailsBody: `{"message":"scope"}`}},
		{name: "user without id", resp: fakeResponses{userBody: `{"login":"octocat"}`}, wantInvalid: true},
		{name: "malformed user", resp: fakeResponses{userBody: `not json`}, wantInvalid: true},
		{name: "malformed emails", resp: fakeResponses{emailsBody: `{"email":"x"}`}, wantInvalid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := fakeGitHub(t, tt.resp)

			_, err := p.ExchangeCode(context.Background(), "auth-code", testParams())
			require.Error(t, err)
			assert.Equal(t, tt.wantInvalid, errors.Is(err, oauth.ErrInvalidToken), "got: %v", err)
		})
	}
}

func TestProvider_ExchangeCode_RedirectWhitelist(t *testing.T) {
	p := fakeGitHub(t, fakeResponses{})

	params := testParams()
	params.RedirectURI = "https://evil.example.com/callback"
	_, err := p.ExchangeCode(context.Background(), "auth-code", params)
	assert.True(t, errors.Is(err, oauth.ErrRedirectURINotAllowed), "expected ErrRedirectURINotAllowed, got: %v", err)
}
