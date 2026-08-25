// Package oauth defines the contract for OAuth 2.0 / OpenID Connect identity
// providers. Concrete providers (Google, GitHub) live in subpackages and are
// wired into the auth service by the host application.
package oauth

import (
	"context"
	"errors"
)

// ErrRedirectURINotAllowed indicates the redirect URI is not on the
// provider's configured whitelist.
var ErrRedirectURINotAllowed = errors.New("redirect uri not allowed")

// ErrInvalidToken indicates the provider returned a token response that
// could not be validated (malformed, wrong audience/issuer, expired).
var ErrInvalidToken = errors.New("invalid provider token")

// UserInfo is the identity a provider reports after a code exchange.
type UserInfo struct {
	ExternalID    string // provider's stable account id (OIDC "sub")
	Email         string
	EmailVerified bool
}

// Provider abstracts one OAuth 2.0 / OIDC identity provider.
type Provider interface {
	// ProviderName returns the provider type identifier, one of the
	// entity.ProviderType* constants (registry key).
	ProviderName() string

	// AuthCodeURL builds the provider's authorization URL for the given CSRF
	// state. redirectURI must be on the provider's whitelist.
	AuthCodeURL(state, redirectURI string) (string, error)

	// ExchangeCode swaps an authorization code for the provider's tokens and
	// returns the authenticated user's identity. redirectURI must equal the
	// value used in AuthCodeURL.
	ExchangeCode(ctx context.Context, code, redirectURI string) (*UserInfo, error)
}
