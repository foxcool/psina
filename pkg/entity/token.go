package entity

import "time"

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
	Hash      string // SHA256 hash of the token
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	Revoked   bool
}
