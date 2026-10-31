package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Backend is every user-owned port a full store backend implements; the
// contracts below need several at once because the rows reference users.
type Backend interface {
	auth.UserStore
	auth.TokenStore
	auth.CredentialStore
	auth.PATStore
	auth.OAuthIdentityStore
	auth.WalletIdentityStore
}

// NewBackend returns an empty store.
type NewBackend func(t *testing.T) Backend

// createUser stores a fresh email-less user and returns its ID.
func createUser(t *testing.T, s auth.UserStore) string {
	t.Helper()
	user := &entity.User{ID: uuid.New().String()}
	require.NoError(t, s.Create(context.Background(), user))
	return user.ID
}

// UserOwnership checks that rows belong to an existing user: deleting a user
// removes everything it owns, and a write for a missing user is refused with
// store.ErrUserNotFound. Postgres enforces both with ON DELETE CASCADE foreign
// keys; the memory store must do the same by hand.
func UserOwnership(t *testing.T, newStore NewBackend) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// seed gives the user one row of every kind and returns its PAT hash.
	seed := func(t *testing.T, s Backend, userID string) string {
		t.Helper()
		patHash := "pat-" + userID
		require.NoError(t, s.SavePasswordHash(ctx, userID, "hash"))
		require.NoError(t, s.SaveRefreshToken(ctx, &entity.RefreshToken{
			Hash: "rt-" + userID, UserID: userID, ExpiresAt: now.Add(time.Hour),
		}))
		require.NoError(t, s.SavePAT(ctx, &entity.PersonalAccessToken{
			ID: uuid.New().String(), Hash: patHash, UserID: userID, Name: "ci",
		}))
		require.NoError(t, s.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
			ID: uuid.New().String(), UserID: userID, Provider: entity.ProviderTypeGoogle, ExternalID: "sub-" + userID,
		}))
		return patHash
	}

	t.Run("deleting a user removes what it owns", func(t *testing.T) {
		s := newStore(t)
		userID, other := createUser(t, s), createUser(t, s)
		patHash := seed(t, s, userID)
		otherPATHash := seed(t, s, other)

		require.NoError(t, s.Delete(ctx, userID))

		_, err := s.GetPasswordHash(ctx, userID)
		assert.ErrorIs(t, err, store.ErrCredentialNotFound)
		_, err = s.GetRefreshToken(ctx, "rt-"+userID)
		assert.ErrorIs(t, err, store.ErrTokenNotFound)
		_, err = s.GetPAT(ctx, patHash)
		assert.ErrorIs(t, err, store.ErrTokenNotFound)
		pats, err := s.ListPATs(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, pats)
		_, err = s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-"+userID)
		assert.ErrorIs(t, err, store.ErrOAuthIdentityNotFound)
		identities, err := s.ListOAuthIdentities(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, identities)

		// Another user's rows are untouched.
		_, err = s.GetPasswordHash(ctx, other)
		require.NoError(t, err)
		_, err = s.GetRefreshToken(ctx, "rt-"+other)
		require.NoError(t, err)
		_, err = s.GetPAT(ctx, otherPATHash)
		require.NoError(t, err)
		identities, err = s.ListOAuthIdentities(ctx, other)
		require.NoError(t, err)
		assert.Len(t, identities, 1)
	})

	t.Run("the provider account can sign in again after deletion", func(t *testing.T) {
		s := newStore(t)
		userID := createUser(t, s)
		seed(t, s, userID)
		require.NoError(t, s.Delete(ctx, userID))

		require.NoError(t, s.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
			ID: uuid.New().String(), UserID: createUser(t, s), Provider: entity.ProviderTypeGoogle, ExternalID: "sub-" + userID,
		}))
	})

	writes := []struct {
		name  string
		write func(s Backend, userID string) error
	}{
		{"password hash", func(s Backend, userID string) error {
			return s.SavePasswordHash(ctx, userID, "hash")
		}},
		{"refresh token", func(s Backend, userID string) error {
			return s.SaveRefreshToken(ctx, &entity.RefreshToken{Hash: "rt", UserID: userID, ExpiresAt: now.Add(time.Hour)})
		}},
		{"personal access token", func(s Backend, userID string) error {
			return s.SavePAT(ctx, &entity.PersonalAccessToken{ID: uuid.New().String(), Hash: "pat", UserID: userID, Name: "ci"})
		}},
		{"oauth identity", func(s Backend, userID string) error {
			return s.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
				ID: uuid.New().String(), UserID: userID, Provider: entity.ProviderTypeGitHub, ExternalID: "42",
			})
		}},
		{"wallet identity", func(s Backend, userID string) error {
			return s.SaveWalletIdentity(ctx, &entity.WalletIdentity{
				ID: uuid.New().String(), UserID: userID, Chain: "ethereum", Address: "0x0000000000000000000000000000000000000001",
			})
		}},
	}

	for _, w := range writes {
		t.Run(w.name+" for a missing user", func(t *testing.T) {
			s := newStore(t)
			assert.ErrorIs(t, w.write(s, uuid.New().String()), store.ErrUserNotFound)
		})
		t.Run(w.name+" for a deleted user", func(t *testing.T) {
			s := newStore(t)
			userID := createUser(t, s)
			require.NoError(t, s.Delete(ctx, userID))
			assert.ErrorIs(t, w.write(s, userID), store.ErrUserNotFound)
		})
	}
}
