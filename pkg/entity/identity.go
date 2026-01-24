package entity

// Identity represents an authenticated identity from a provider.
type Identity struct {
	UserID   string
	Email    string
	Provider string            // "local", "passkey", "wallet"
	Metadata map[string]string // Provider-specific metadata
}
