package entity

import "time"

// Provider type identifiers. Stored in Identity.Provider and returned by each
// provider's Type() method; the auth.Service registry is keyed by these.
const (
	ProviderTypeLocal  = "local"
	ProviderTypeGoogle = "google"
	ProviderTypeGitHub = "github"
	ProviderTypeWallet = "wallet"
)

// Identity represents an authenticated identity from a provider.
type Identity struct {
	UserID   string
	Email    string
	Provider string            // one of ProviderType* constants
	Metadata map[string]string // Provider-specific metadata
}

// OAuthIdentity links a user to an external OAuth provider account. A user may
// hold several (one per provider). Uniqueness is (Provider, ExternalID).
type OAuthIdentity struct {
	ID         string // UUID, internal handle
	UserID     string
	Provider   string // ProviderTypeGoogle, ProviderTypeGitHub, ...
	ExternalID string // provider's stable account id (e.g. OIDC "sub")
	Email      string // email reported by the provider (may differ from User.Email)
	CreatedAt  time.Time
}

// WalletIdentity links a user to a blockchain wallet address. Uniqueness is
// (Chain, Address); Address is stored normalized (EIP-55 checksum for EVM).
type WalletIdentity struct {
	ID        string // UUID, internal handle
	UserID    string
	Chain     string // chain identifier from the WalletProvider (e.g. "ethereum")
	Address   string // normalized wallet address
	CreatedAt time.Time
}

// Challenge is a single-use, expiring nonce. It backs wallet sign-in (the
// message the wallet signs, bound to Chain+Address) and OAuth CSRF state (Nonce
// as the state value, with Chain/Address empty). Consumed via delete-before-use.
type Challenge struct {
	Nonce     string // random, primary key
	Message   string // full text the client signs, or OAuth state payload
	Chain     string // wallet chain binding; empty for OAuth state
	Address   string // wallet address binding; empty for OAuth state
	ExpiresAt time.Time
	CreatedAt time.Time
}
