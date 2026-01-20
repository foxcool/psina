package psina

import "time"

// User represents an authenticated user in the system.
type User struct {
	ID        string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Identity represents an authenticated identity from a provider.
type Identity struct {
	UserID   string
	Email    string
	Provider string            // "local", "passkey", "wallet"
	Metadata map[string]string // Provider-specific metadata
}

// TokenPair represents an access token and refresh token pair.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // Access token TTL in seconds
}

// Claims represents JWT claims.
type Claims struct {
	UserID string
	Email  string
	Issuer string
	Exp    int64 // Expiration timestamp
	Iat    int64 // Issued at timestamp
}

// RefreshToken represents a persisted refresh token.
type RefreshToken struct {
	Hash      string    // SHA256 hash of the token
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	Revoked   bool
}

// AuthRequest represents a request to authenticate a user.
type AuthRequest struct {
	Email    string
	Password string // For local provider
	// Future: challenge, signature for passkey/wallet
}

// RegisterRequest represents a request to register a new user.
type RegisterRequest struct {
	Email    string
	Password string // For local provider
	// Future: additional fields for other providers
}
