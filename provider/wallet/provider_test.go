package wallet

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProvider is a minimal WalletProvider for dispatcher tests.
type fakeProvider struct {
	chain string
}

func (f fakeProvider) Chain() string                                { return f.chain }
func (f fakeProvider) NormalizeAddress(addr string) (string, error) { return addr, nil }
func (f fakeProvider) BuildMessage(addr, nonce string, _ MessageOpts) string {
	return addr + ":" + nonce
}
func (f fakeProvider) VerifySignature(_, _, _ string) error { return nil }

func TestDispatcher_Provider(t *testing.T) {
	eth := fakeProvider{chain: "ethereum"}
	sol := fakeProvider{chain: "solana"}
	d := NewDispatcher(eth, sol)

	got, err := d.Provider("ethereum")
	require.NoError(t, err)
	assert.Equal(t, "ethereum", got.Chain())

	got, err = d.Provider("solana")
	require.NoError(t, err)
	assert.Equal(t, "solana", got.Chain())

	_, err = d.Provider("polkadot")
	assert.ErrorIs(t, err, ErrUnsupportedChain)
}

func TestDispatcher_Chains(t *testing.T) {
	d := NewDispatcher(fakeProvider{chain: "ethereum"}, fakeProvider{chain: "solana"})
	assert.ElementsMatch(t, []string{"ethereum", "solana"}, d.Chains())
}

func TestDispatcher_EmptyIsUnsupported(t *testing.T) {
	d := NewDispatcher()
	_, err := d.Provider("ethereum")
	assert.True(t, errors.Is(err, ErrUnsupportedChain))
	assert.Empty(t, d.Chains())
}

func TestNewDispatcher_DuplicateChainPanics(t *testing.T) {
	assert.Panics(t, func() {
		NewDispatcher(fakeProvider{chain: "ethereum"}, fakeProvider{chain: "ethereum"})
	})
}
