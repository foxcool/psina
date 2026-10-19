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

// ErrMissingAuthParams indicates a required AuthParams field (PKCE verifier,
// OIDC nonce) is empty — a caller bug, never a user error.
var ErrMissingAuthParams = errors.New("missing oauth auth params")

// ErrInvalidToken indicates the provider returned a token response that
// could not be validated (malformed, wrong audience/issuer/nonce, expired).
var ErrInvalidToken = errors.New("invalid provider token")

// UserInfo is the identity a provider reports after a code exchange.
type UserInfo struct {
	ExternalID    string // provider's stable account id (OIDC "sub")
	Email         string
	EmailVerified bool
}

// AuthParams carries the per-flow values that must match between AuthCodeURL
// and ExchangeCode. The caller generates them, keeps them server-side (the
// auth challenge), and passes the same values to both calls.
type AuthParams struct {
	State       string
	RedirectURI string // must be on the provider's whitelist
	// CodeVerifier is the PKCE (RFC 7636) verifier, from oauth2.GenerateVerifier.
	// Required: PKCE guards against authorization code injection even for
	// confidential clients (RFC 9700 §2.1.1).
	CodeVerifier string
	// Nonce is the OIDC nonce binding the ID token to this flow. Required by
	// OIDC providers; providers without OIDC ignore it.
	Nonce string
}

// Provider abstracts one OAuth 2.0 / OIDC identity provider.
type Provider interface {
	// ProviderName returns the provider type identifier, one of the
	// entity.ProviderType* constants (registry key).
	ProviderName() string

	// AuthCodeURL builds the provider's authorization URL carrying the state,
	// the PKCE S256 challenge derived from p.CodeVerifier and, for OIDC
	// providers, p.Nonce.
	AuthCodeURL(p AuthParams) (string, error)

	// ExchangeCode swaps an authorization code for the provider's tokens and
	// returns the authenticated user's identity. p must carry the same
	// RedirectURI, CodeVerifier and Nonce that were passed to AuthCodeURL.
	ExchangeCode(ctx context.Context, code string, p AuthParams) (*UserInfo, error)
}
