// Package google implements Sign in with Google via OAuth 2.0 with OpenID
// Connect. The user's stable id and email come from the ID token returned by
// the token endpoint, so no userinfo API call is needed.
package google

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/provider/oauth"
)

// endpoint is Google's OAuth 2.0 endpoint. Inlined instead of importing
// golang.org/x/oauth2/google, which drags in cloud.google.com/go/compute/metadata
// for two URL constants.
// #nosec G101 -- public endpoint URLs, not credentials
var endpoint = oauth2.Endpoint{
	AuthURL:  "https://accounts.google.com/o/oauth2/auth",
	TokenURL: "https://oauth2.googleapis.com/token",
}

// Config configures the Google provider.
type Config struct {
	ClientID     string
	ClientSecret string
	// RedirectURIs is the exact-match whitelist of allowed redirect URIs.
	RedirectURIs []string
}

// Provider implements oauth.Provider for Google.
type Provider struct {
	cfg      Config
	endpoint oauth2.Endpoint
}

var _ oauth.Provider = (*Provider)(nil)

// New creates a Google provider.
func New(cfg Config) (*Provider, error) {
	return newWithEndpoint(cfg, endpoint)
}

// newWithEndpoint allows tests to point the provider at a fake token endpoint.
func newWithEndpoint(cfg Config, endpoint oauth2.Endpoint) (*Provider, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("google: client id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("google: client secret is required")
	}
	if len(cfg.RedirectURIs) == 0 {
		return nil, fmt.Errorf("google: at least one redirect uri is required")
	}
	return &Provider{cfg: cfg, endpoint: endpoint}, nil
}

// ProviderName returns the provider type identifier.
func (p *Provider) ProviderName() string {
	return entity.ProviderTypeGoogle
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
		// openid+email is all psina needs: sub and email land in the ID token.
		Scopes: []string{"openid", "email"},
	}, nil
}

// AuthCodeURL builds Google's authorization URL for the given CSRF state.
func (p *Provider) AuthCodeURL(state, redirectURI string) (string, error) {
	conf, err := p.oauthConfig(redirectURI)
	if err != nil {
		return "", err
	}
	return conf.AuthCodeURL(state), nil
}

// idTokenClaims is the subset of Google ID token claims psina consumes.
type idTokenClaims struct {
	jwt.Claims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// ExchangeCode swaps the authorization code for tokens and extracts the user
// identity from the ID token.
//
// The ID token signature is deliberately not verified against Google's JWKS:
// the token arrives straight from Google's token endpoint over TLS on a
// client-secret-authenticated request, so per OIDC Core §3.1.3.7 the TLS
// server validation may be used to validate the issuer in place of checking
// the token signature. Issuer, audience, and expiry are still checked.
func (p *Provider) ExchangeCode(ctx context.Context, code, redirectURI string) (*oauth.UserInfo, error) {
	conf, err := p.oauthConfig(redirectURI)
	if err != nil {
		return nil, err
	}

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google: exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("%w: token response has no id_token", oauth.ErrInvalidToken)
	}

	parsed, err := jwt.ParseSigned(rawIDToken, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("%w: parse id_token: %v", oauth.ErrInvalidToken, err)
	}

	var claims idTokenClaims
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("%w: decode id_token claims: %v", oauth.ErrInvalidToken, err)
	}

	if err := claims.Validate(jwt.Expected{
		// Google may issue either issuer form.
		AnyAudience: jwt.Audience{p.cfg.ClientID},
		Time:        time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("%w: validate id_token claims: %v", oauth.ErrInvalidToken, err)
	}
	if claims.Issuer != "https://accounts.google.com" && claims.Issuer != "accounts.google.com" {
		return nil, fmt.Errorf("%w: unexpected issuer %q", oauth.ErrInvalidToken, claims.Issuer)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: id_token has no sub", oauth.ErrInvalidToken)
	}

	return &oauth.UserInfo{
		ExternalID:    claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
	}, nil
}
