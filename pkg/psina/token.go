package psina

import (
	"context"

	"github.com/go-jose/go-jose/v4"
)

// TokenIssuer handles JWT token lifecycle.
type TokenIssuer interface {
	// Issue generates a new token pair for an authenticated identity.
	Issue(ctx context.Context, identity *Identity) (*TokenPair, error)

	// Validate verifies an access token and returns its claims.
	Validate(ctx context.Context, accessToken string) (*Claims, error)

	// Refresh generates a new token pair using a refresh token.
	Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)

	// JWKS returns the JSON Web Key Set for public key verification.
	JWKS() *jose.JSONWebKeySet
}
