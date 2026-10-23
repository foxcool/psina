package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WalletStore is what the wallet contract needs: identities reference users,
// and deleting a user must drop them.
type WalletStore interface {
	auth.UserStore
	auth.WalletIdentityStore
}

// WalletIdentities checks the WalletIdentityStore rules: a (chain, address)
// pair links to exactly one user, addresses match exactly (normalization is
// the wallet provider's job, not the store's), lists are per user and newest
// first, and deleting a user drops its identities.
func WalletIdentities(t *testing.T, newStore func(t *testing.T) WalletStore) {
	ctx := context.Background()

	const ethAddress = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

	newUser := func(t *testing.T, s WalletStore) string {
		t.Helper()
		user := &entity.User{ID: uuid.New().String()}
		require.NoError(t, s.Create(ctx, user))
		return user.ID
	}
	newIdentity := func(userID, chain, addr string) *entity.WalletIdentity {
		return &entity.WalletIdentity{ID: uuid.New().String(), UserID: userID, Chain: chain, Address: addr}
	}
	chainsOf := func(list []*entity.WalletIdentity) []string {
		var chains []string
		for _, identity := range list {
			chains = append(chains, identity.Chain)
		}
		return chains
	}

	t.Run("round trip", func(t *testing.T) {
		s := newStore(t)
		userID := newUser(t, s)
		want := newIdentity(userID, "ethereum", ethAddress)
		want.CreatedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		require.NoError(t, s.SaveWalletIdentity(ctx, want))

		got, err := s.GetWalletIdentity(ctx, "ethereum", ethAddress)
		require.NoError(t, err)
		assert.Equal(t, want.ID, got.ID)
		assert.Equal(t, userID, got.UserID)
		assert.Equal(t, "ethereum", got.Chain)
		assert.Equal(t, ethAddress, got.Address)
		assert.True(t, want.CreatedAt.Equal(got.CreatedAt), "supplied CreatedAt kept, got %v", got.CreatedAt)
	})

	t.Run("CreatedAt set on save", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.SaveWalletIdentity(ctx, newIdentity(newUser(t, s), "ethereum", ethAddress)))

		got, err := s.GetWalletIdentity(ctx, "ethereum", ethAddress)
		require.NoError(t, err)
		assert.False(t, got.CreatedAt.IsZero())
	})

	t.Run("pair taken by one user cannot be claimed by another", func(t *testing.T) {
		s := newStore(t)
		owner, other := newUser(t, s), newUser(t, s)
		require.NoError(t, s.SaveWalletIdentity(ctx, newIdentity(owner, "ethereum", ethAddress)))

		err := s.SaveWalletIdentity(ctx, newIdentity(other, "ethereum", ethAddress))
		assert.True(t, errors.Is(err, store.ErrWalletIdentityExists), "got %v", err)

		got, err := s.GetWalletIdentity(ctx, "ethereum", ethAddress)
		require.NoError(t, err)
		assert.Equal(t, owner, got.UserID, "the original link survives")
	})

	t.Run("lookup is exact", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.SaveWalletIdentity(ctx, newIdentity(newUser(t, s), "ethereum", ethAddress)))

		tests := []struct {
			name, chain, address string
		}{
			{"unknown address", "ethereum", "0x0000000000000000000000000000000000000000"},
			{"other chain", "solana", ethAddress},
			{"different spelling", "ethereum", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"},
		}
		for _, tt := range tests {
			_, err := s.GetWalletIdentity(ctx, tt.chain, tt.address)
			assert.True(t, errors.Is(err, store.ErrWalletIdentityNotFound), "%s: got %v", tt.name, err)
		}
	})

	t.Run("list is per user, newest first", func(t *testing.T) {
		s := newStore(t)
		userID, other := newUser(t, s), newUser(t, s)
		base := time.Now().Add(-time.Hour).Truncate(time.Second)
		for i, chain := range []string{"ethereum", "polygon", "base"} {
			identity := newIdentity(userID, chain, ethAddress)
			identity.CreatedAt = base.Add(time.Duration(i) * time.Minute)
			require.NoError(t, s.SaveWalletIdentity(ctx, identity))
		}
		require.NoError(t, s.SaveWalletIdentity(ctx, newIdentity(other, "ethereum", "0x0000000000000000000000000000000000000001")))

		list, err := s.ListWalletIdentities(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, []string{"base", "polygon", "ethereum"}, chainsOf(list))

		list, err = s.ListWalletIdentities(ctx, other)
		require.NoError(t, err)
		assert.Equal(t, []string{"ethereum"}, chainsOf(list))
	})

	t.Run("deleting the user frees its wallets", func(t *testing.T) {
		s := newStore(t)
		userID := newUser(t, s)
		require.NoError(t, s.SaveWalletIdentity(ctx, newIdentity(userID, "ethereum", ethAddress)))

		require.NoError(t, s.Delete(ctx, userID))
		_, err := s.GetWalletIdentity(ctx, "ethereum", ethAddress)
		assert.True(t, errors.Is(err, store.ErrWalletIdentityNotFound), "got %v", err)
		require.NoError(t, s.SaveWalletIdentity(ctx, newIdentity(newUser(t, s), "ethereum", ethAddress)),
			"the address can sign in again as a new user")
	})
}
