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
	// Roles are opaque strings copied from the user; psina never interprets them.
	Roles  []string
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
	// RotatedAt is when Refresh exchanged this token; nil if it never was.
	RotatedAt *time.Time
	// EndedAt is when logout or reuse detection revoked this token; nil if not.
	EndedAt *time.Time
}

// RefreshFamily summarises a refresh token family for reuse decisions.
type RefreshFamily struct {
	// SessionEnded is true if any member was revoked by logout or reuse
	// detection (RevokeTokens), as opposed to rotation.
	SessionEnded bool
	// LastRotatedAt is the latest rotation in the family; nil if none.
	LastRotatedAt *time.Time
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
