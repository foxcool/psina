package auth

import (
	"context"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/go-jose/go-jose/v4"
)

// Provider authenticates users via a specific method (local, passkey, wallet, etc.).
type Provider interface {
	// Type returns the provider type identifier.
	Type() string

	// Authenticate verifies credentials and returns an authenticated identity.
	Authenticate(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error)

	// Register creates a new user account and returns the identity.
	Register(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error)
}

// UserStore handles user persistence.
type UserStore interface {
	// Create persists a new user.
	Create(ctx context.Context, user *entity.User) error

	// GetByID retrieves a user by ID.
	GetByID(ctx context.Context, id string) (*entity.User, error)

	// GetByEmail retrieves a user by email address.
	GetByEmail(ctx context.Context, email string) (*entity.User, error)

	// Delete removes a user by ID.
	Delete(ctx context.Context, id string) error
}

// TokenStore handles refresh token persistence.
type TokenStore interface {
	// SaveRefreshToken persists a refresh token.
	SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error

	// GetRefreshToken retrieves a refresh token by its hash.
	GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error)

	// RevokeTokens revokes a token and all tokens in its family.
	// Works for both single token revocation and family revocation.
	// Query: WHERE hash = $1 OR parent = $1
	RevokeTokens(ctx context.Context, hash string) error
}

// CredentialStore handles password hash persistence for local auth.
// This is separated from UserStore to maintain clean architecture.
type CredentialStore interface {
	// SavePasswordHash stores a password hash for a user.
	SavePasswordHash(ctx context.Context, userID, hash string) error

	// GetPasswordHash retrieves a password hash for a user.
	GetPasswordHash(ctx context.Context, userID string) (string, error)
}

// TokenIssuer handles JWT token operations.
type TokenIssuer interface {
	// GenerateTokens creates access and refresh tokens.
	// Returns: TokenPair, refresh token hash (for storage), error.
	GenerateTokens(userID, email string) (*entity.TokenPair, string, error)

	// ParseToken validates an access token and returns claims.
	ParseToken(accessToken string) (*entity.Claims, error)

	// JWKS returns the JSON Web Key Set for public key verification.
	JWKS() *jose.JSONWebKeySet
}
