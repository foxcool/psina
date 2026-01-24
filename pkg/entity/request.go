package entity

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
