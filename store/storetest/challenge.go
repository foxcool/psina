package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Challenges checks the ChallengeStore round trip and single-use deletion.
// Expiry is backend-specific (memory deletes on read, postgres on the next
// save) and stays in each backend's own tests.
func Challenges(t *testing.T, newStore func(t *testing.T) auth.ChallengeStore) {
	ctx := context.Background()

	roundTrip := func(t *testing.T, s auth.ChallengeStore, want *entity.Challenge) {
		t.Helper()
		want.ExpiresAt = time.Now().Add(time.Minute)
		require.NoError(t, s.SaveChallenge(ctx, want))

		got, err := s.GetChallenge(ctx, want.Nonce)
		require.NoError(t, err)
		assert.Equal(t, want.Message, got.Message)
		assert.Equal(t, want.Chain, got.Chain)
		assert.Equal(t, want.Address, got.Address)
		assert.Equal(t, want.CodeVerifier, got.CodeVerifier)
		assert.Equal(t, want.OAuthNonce, got.OAuthNonce)
		assert.Equal(t, want.BindingHash, got.BindingHash)
		assert.False(t, got.CreatedAt.IsZero(), "CreatedAt should be set on save")
	}

	t.Run("wallet challenge round trip", func(t *testing.T) {
		roundTrip(t, newStore(t), &entity.Challenge{
			Nonce:   "wallet-nonce",
			Message: "sign me",
			Chain:   "ethereum",
			Address: "0xAbC",
		})
	})

	t.Run("oauth challenge round trip", func(t *testing.T) {
		roundTrip(t, newStore(t), &entity.Challenge{
			Nonce:        "oauth-state",
			CodeVerifier: "verifier-123",
			OAuthNonce:   "oidc-nonce-456",
			BindingHash:  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		})
	})

	t.Run("single use", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.SaveChallenge(ctx, &entity.Challenge{
			Nonce:     "single-use",
			ExpiresAt: time.Now().Add(time.Minute),
		}))

		require.NoError(t, s.DeleteChallenge(ctx, "single-use"))
		_, err := s.GetChallenge(ctx, "single-use")
		assert.True(t, errors.Is(err, store.ErrChallengeNotFound), "expected ErrChallengeNotFound, got: %v", err)

		err = s.DeleteChallenge(ctx, "single-use")
		assert.True(t, errors.Is(err, store.ErrChallengeNotFound), "deleting twice: expected ErrChallengeNotFound, got: %v", err)
	})
}
