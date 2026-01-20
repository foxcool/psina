package psina

import "context"

// Provider authenticates users via a specific method (local, passkey, wallet, etc.).
type Provider interface {
	// Type returns the provider type identifier.
	Type() string

	// Authenticate verifies credentials and returns an authenticated identity.
	Authenticate(ctx context.Context, req *AuthRequest) (*Identity, error)

	// Register creates a new user account and returns the identity.
	Register(ctx context.Context, req *RegisterRequest) (*Identity, error)
}
