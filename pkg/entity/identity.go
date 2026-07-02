package entity

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
