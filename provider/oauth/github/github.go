// Package github implements Sign in with GitHub via OAuth 2.0. GitHub has no
// OpenID Connect, so the identity comes from the REST API: the numeric account
// id from GET /user and the email from GET /user/emails.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/oauth"
)

const (
	apiURL = "https://api.github.com"
	// maxAPIResponse caps how much of a REST response is read; /user and
	// /user/emails are a few KB.
	maxAPIResponse = 1 << 20
)

// Config configures the GitHub provider.
type Config struct {
	ClientID     string
	ClientSecret string
	// RedirectURIs is the exact-match whitelist of allowed redirect URIs.
	RedirectURIs []string
}

// Provider implements oauth.Provider for GitHub.
type Provider struct {
	cfg      Config
	endpoint oauth2.Endpoint
	apiURL   string
}

var _ oauth.Provider = (*Provider)(nil)

// New creates a GitHub provider.
func New(cfg Config) (*Provider, error) {
	return newWithEndpoint(cfg, endpoints.GitHub, apiURL)
}

// newWithEndpoint allows tests to point the provider at fake OAuth and API servers.
func newWithEndpoint(cfg Config, endpoint oauth2.Endpoint, apiURL string) (*Provider, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("github: client id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("github: client secret is required")
	}
	if len(cfg.RedirectURIs) == 0 {
		return nil, fmt.Errorf("github: at least one redirect uri is required")
	}
	return &Provider{cfg: cfg, endpoint: endpoint, apiURL: apiURL}, nil
}

// ProviderName returns the provider type identifier.
func (p *Provider) ProviderName() string {
	return entity.ProviderTypeGitHub
}

// oauthConfig builds the per-request oauth2 config. redirect_uri varies per
// call (validated against the whitelist), everything else is static.
func (p *Provider) oauthConfig(redirectURI string) (*oauth2.Config, error) {
	if !slices.Contains(p.cfg.RedirectURIs, redirectURI) {
		return nil, fmt.Errorf("%w: %s", oauth.ErrRedirectURINotAllowed, redirectURI)
	}
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     p.endpoint,
		// user:email unlocks /user/emails, which carries the verified flag.
		Scopes: []string{"user:email"},
	}, nil
}

// requireParams rejects a flow without PKCE verifier. The nonce is ignored:
// GitHub issues no ID token to bind it to.
func requireParams(params oauth.AuthParams) error {
	if params.CodeVerifier == "" {
		return fmt.Errorf("%w: code verifier is required", oauth.ErrMissingAuthParams)
	}
	return nil
}

// AuthCodeURL builds GitHub's authorization URL with state and PKCE S256 challenge.
func (p *Provider) AuthCodeURL(params oauth.AuthParams) (string, error) {
	if err := requireParams(params); err != nil {
		return "", err
	}
	conf, err := p.oauthConfig(params.RedirectURI)
	if err != nil {
		return "", err
	}
	return conf.AuthCodeURL(params.State, oauth2.S256ChallengeOption(params.CodeVerifier)), nil
}

type apiUser struct {
	ID int64 `json:"id"`
}

type apiEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// ExchangeCode swaps the authorization code for an access token and reads the
// user identity from the REST API.
//
// The email is always the primary one from /user/emails, never the profile
// email on /user: that is the user's public choice and carries no verified
// flag. An unverified primary is reported as such, so the service refuses it
// rather than psina falling back to some other address.
func (p *Provider) ExchangeCode(ctx context.Context, code string, params oauth.AuthParams) (*oauth.UserInfo, error) {
	if err := requireParams(params); err != nil {
		return nil, err
	}
	conf, err := p.oauthConfig(params.RedirectURI)
	if err != nil {
		return nil, err
	}

	token, err := conf.Exchange(ctx, code, oauth2.VerifierOption(params.CodeVerifier))
	if err != nil {
		return nil, fmt.Errorf("github: exchange code: %w", err)
	}
	client := conf.Client(ctx, token)

	var user apiUser
	if err := p.getJSON(ctx, client, "/user", &user); err != nil {
		return nil, err
	}
	if user.ID <= 0 {
		return nil, fmt.Errorf("%w: /user has no id", oauth.ErrInvalidToken)
	}

	var emails []apiEmail
	if err := p.getJSON(ctx, client, "/user/emails", &emails); err != nil {
		return nil, err
	}

	info := &oauth.UserInfo{ExternalID: strconv.FormatInt(user.ID, 10)}
	if i := slices.IndexFunc(emails, func(e apiEmail) bool { return e.Primary }); i >= 0 {
		info.Email = emails[i].Email
		info.EmailVerified = emails[i].Verified
	}
	return info, nil
}

// getJSON GETs a REST API path with the user's token and decodes the body into dst.
func (p *Provider) getJSON(ctx context.Context, client *http.Client, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiURL+path, nil)
	if err != nil {
		return fmt.Errorf("github: build %s request: %w", path, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("github: get %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body := io.LimitReader(resp.Body, maxAPIResponse)
	if resp.StatusCode != http.StatusOK {
		// Drain so the connection is reused; the body is not echoed into the error.
		_, _ = io.Copy(io.Discard, body)
		return fmt.Errorf("github: get %s: unexpected status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		return fmt.Errorf("%w: decode %s: %v", oauth.ErrInvalidToken, path, err)
	}
	return nil
}
