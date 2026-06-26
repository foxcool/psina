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
	Parent    string // Hash of the root token in this family (empty for root tokens)
	ExpiresAt time.Time
	CreatedAt time.Time
	Revoked   bool
}

// PersonalAccessToken represents a long-lived, opaque API token. Only the SHA256
// hash of the secret is persisted; the plaintext is shown to the user once at
// creation. Revocation is a row delete.
type PersonalAccessToken struct {
	ID         string // UUID, public handle for list/revoke
	Hash       string // SHA256 hash of the token (internal storage detail)
	UserID     string
	Name       string   // human-readable label
	Scopes     []string // stored for forward-compat; not enforced yet
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}
