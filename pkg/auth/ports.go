package auth

import (
	"context"
	"time"

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

// PATStore handles personal access token persistence.
type PATStore interface {
	// SavePAT persists a personal access token.
	SavePAT(ctx context.Context, pat *entity.PersonalAccessToken) error

	// GetPAT retrieves a personal access token by its hash.
	GetPAT(ctx context.Context, hash string) (*entity.PersonalAccessToken, error)

	// ListPATs returns all personal access tokens for a user.
	ListPATs(ctx context.Context, userID string) ([]*entity.PersonalAccessToken, error)

	// DeletePAT removes a token by its UUID, scoped to its owner to prevent
	// cross-user deletion.
	DeletePAT(ctx context.Context, userID, id string) error

	// TouchPAT records last-used time. Best-effort; callers may ignore the error.
	TouchPAT(ctx context.Context, hash string, t time.Time) error
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
	// GenerateTokens creates access and refresh tokens. Roles are embedded in
	// the access JWT as an opaque claim.
	// Returns: TokenPair, refresh token hash (for storage), error.
	GenerateTokens(userID, email string, roles []string) (*entity.TokenPair, string, error)

	// ParseToken validates an access token and returns claims.
	ParseToken(accessToken string) (*entity.Claims, error)

	// JWKS returns the JSON Web Key Set for public key verification.
	JWKS() *jose.JSONWebKeySet
}
