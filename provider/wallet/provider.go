// Package wallet defines the chain-agnostic contract for wallet signature
// authentication and a dispatcher that routes to per-chain implementations.
// Concrete providers (EVM/SIWE, Solana, Polkadot) live in subpackages and are
// registered with a Dispatcher at wiring time.
package wallet

import (
	"errors"
	"fmt"
	"time"
)

// ErrUnsupportedChain indicates no provider is registered for a chain.
var ErrUnsupportedChain = errors.New("unsupported wallet chain")

// MessageOpts parameterizes the message a wallet is asked to sign. Fields map
// onto the SIWE (EIP-4361) message for EVM chains; other chains use the subset
// that applies.
type MessageOpts struct {
	Domain    string    // requesting domain, e.g. "app.example.com"
	Statement string    // human-readable statement shown to the signer
	ChainID   int       // chain id (EVM); 0 when not applicable
	IssuedAt  time.Time // message issuance time
	ExpiresAt time.Time // message expiry
}

// WalletProvider verifies wallet signatures for one chain family.
type WalletProvider interface {
	// Chain returns the chain identifier this provider serves (dispatcher key).
	Chain() string

	// NormalizeAddress canonicalizes an address (e.g. EIP-55 checksum for EVM)
	// or returns an error if it is malformed for this chain.
	NormalizeAddress(addr string) (string, error)

	// BuildMessage returns the exact text the wallet must sign for the given
	// address and nonce.
	BuildMessage(addr, nonce string, opts MessageOpts) string

	// VerifySignature checks that sig is a valid signature of message by addr.
	// Returns nil on success, an error otherwise.
	VerifySignature(addr, message, sig string) error
}

// Dispatcher routes wallet operations to the WalletProvider for a chain. It is
// read-only after construction and safe for concurrent use.
type Dispatcher struct {
	providers map[string]WalletProvider
}

// NewDispatcher builds a dispatcher from the given providers, keyed by Chain().
// A duplicate chain is a wiring bug and panics.
func NewDispatcher(providers ...WalletProvider) *Dispatcher {
	m := make(map[string]WalletProvider, len(providers))
	for _, p := range providers {
		if _, dup := m[p.Chain()]; dup {
			panic(fmt.Sprintf("wallet: duplicate provider for chain %q", p.Chain()))
		}
		m[p.Chain()] = p
	}
	return &Dispatcher{providers: m}
}

// Provider returns the WalletProvider for a chain, or ErrUnsupportedChain.
func (d *Dispatcher) Provider(chain string) (WalletProvider, error) {
	p, ok := d.providers[chain]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedChain, chain)
	}
	return p, nil
}

// Chains returns the supported chain identifiers, in no particular order.
func (d *Dispatcher) Chains() []string {
	chains := make([]string, 0, len(d.providers))
	for c := range d.providers {
		chains = append(chains, c)
	}
	return chains
}
