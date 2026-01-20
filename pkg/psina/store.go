package psina

import "context"

// UserStore handles user persistence.
type UserStore interface {
	// Create persists a new user.
	Create(ctx context.Context, user *User) error

	// GetByID retrieves a user by ID.
	GetByID(ctx context.Context, id string) (*User, error)

	// GetByEmail retrieves a user by email address.
	GetByEmail(ctx context.Context, email string) (*User, error)
}

// TokenStore handles refresh token persistence.
type TokenStore interface {
	// SaveRefreshToken persists a refresh token.
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error

	// GetRefreshToken retrieves a refresh token by its hash.
	GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error)

	// RevokeRefreshToken marks a refresh token as revoked.
	RevokeRefreshToken(ctx context.Context, hash string) error
}

// CredentialStore handles password hash persistence for local auth.
// This is separated from UserStore to maintain clean architecture.
type CredentialStore interface {
	// SavePasswordHash stores a password hash for a user.
	SavePasswordHash(ctx context.Context, userID, hash string) error

	// GetPasswordHash retrieves a password hash for a user.
	GetPasswordHash(ctx context.Context, userID string) (string, error)
}
