package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OAuthIdentities checks the OAuthIdentityStore rules: a (provider, external
// id) pair links to exactly one user, a user created with its first link is
// stored with it or not at all, and lists are per user and newest first.
func OAuthIdentities(t *testing.T, newStore NewBackend) {
	ctx := context.Background()

	newIdentity := func(userID, provider, externalID string) *entity.OAuthIdentity {
		return &entity.OAuthIdentity{ID: uuid.New().String(), UserID: userID, Provider: provider, ExternalID: externalID}
	}
	externalIDsOf := func(list []*entity.OAuthIdentity) []string {
		ids := make([]string, 0, len(list))
		for _, identity := range list {
			ids = append(ids, identity.ExternalID)
		}
		return ids
	}

	t.Run("round trip", func(t *testing.T) {
		s := newStore(t)
		userID := createUser(t, s)
		want := newIdentity(userID, entity.ProviderTypeGoogle, "sub-42")
		want.Email = "user@gmail.com"
		want.CreatedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		require.NoError(t, s.SaveOAuthIdentity(ctx, want))

		got, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-42")
		require.NoError(t, err)
		assert.Equal(t, want.ID, got.ID)
		assert.Equal(t, userID, got.UserID)
		assert.Equal(t, entity.ProviderTypeGoogle, got.Provider)
		assert.Equal(t, "sub-42", got.ExternalID)
		assert.Equal(t, "user@gmail.com", got.Email)
		assert.True(t, want.CreatedAt.Equal(got.CreatedAt), "supplied CreatedAt kept, got %v", got.CreatedAt)
	})

	t.Run("CreatedAt set on save", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.SaveOAuthIdentity(ctx, newIdentity(createUser(t, s), entity.ProviderTypeGoogle, "sub-42")))

		got, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-42")
		require.NoError(t, err)
		assert.False(t, got.CreatedAt.IsZero())
	})

	t.Run("pair taken by one user cannot be claimed by another", func(t *testing.T) {
		s := newStore(t)
		owner, other := createUser(t, s), createUser(t, s)
		require.NoError(t, s.SaveOAuthIdentity(ctx, newIdentity(owner, entity.ProviderTypeGoogle, "sub-42")))

		err := s.SaveOAuthIdentity(ctx, newIdentity(other, entity.ProviderTypeGoogle, "sub-42"))
		assert.ErrorIs(t, err, store.ErrOAuthIdentityExists)

		got, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-42")
		require.NoError(t, err)
		assert.Equal(t, owner, got.UserID, "the original link survives")
	})

	t.Run("lookup is per provider", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.SaveOAuthIdentity(ctx, newIdentity(createUser(t, s), entity.ProviderTypeGoogle, "42")))

		_, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGitHub, "42")
		assert.ErrorIs(t, err, store.ErrOAuthIdentityNotFound)
		_, err = s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "unknown")
		assert.ErrorIs(t, err, store.ErrOAuthIdentityNotFound)
	})

	t.Run("create with identity stores both", func(t *testing.T) {
		s := newStore(t)
		user := &entity.User{ID: uuid.New().String(), Email: "new@example.com"}
		require.NoError(t, s.CreateUserWithOAuthIdentity(ctx, user, newIdentity(user.ID, entity.ProviderTypeGoogle, "sub-42")))

		got, err := s.GetByEmail(ctx, "new@example.com")
		require.NoError(t, err)
		assert.Equal(t, user.ID, got.ID)
		identity, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-42")
		require.NoError(t, err)
		assert.Equal(t, user.ID, identity.UserID)
	})

	t.Run("create with duplicate identity leaves no user", func(t *testing.T) {
		s := newStore(t)
		owner := createUser(t, s)
		require.NoError(t, s.SaveOAuthIdentity(ctx, newIdentity(owner, entity.ProviderTypeGoogle, "sub-42")))

		user := &entity.User{ID: uuid.New().String(), Email: "new@example.com"}
		err := s.CreateUserWithOAuthIdentity(ctx, user, newIdentity(user.ID, entity.ProviderTypeGoogle, "sub-42"))
		assert.ErrorIs(t, err, store.ErrOAuthIdentityExists)

		_, err = s.GetByEmail(ctx, "new@example.com")
		assert.ErrorIs(t, err, store.ErrUserNotFound, "no user row without its link")
		_, err = s.GetByID(ctx, user.ID)
		assert.ErrorIs(t, err, store.ErrUserNotFound)
		got, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-42")
		require.NoError(t, err)
		assert.Equal(t, owner, got.UserID, "the original link survives")
	})

	t.Run("create with duplicate email leaves no identity", func(t *testing.T) {
		s := newStore(t)
		existing := &entity.User{ID: uuid.New().String(), Email: "taken@example.com"}
		require.NoError(t, s.Create(ctx, existing))

		user := &entity.User{ID: uuid.New().String(), Email: "taken@example.com"}
		err := s.CreateUserWithOAuthIdentity(ctx, user, newIdentity(user.ID, entity.ProviderTypeGoogle, "sub-42"))
		assert.ErrorIs(t, err, store.ErrUserExists)

		_, err = s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-42")
		assert.ErrorIs(t, err, store.ErrOAuthIdentityNotFound)
		got, err := s.GetByEmail(ctx, "taken@example.com")
		require.NoError(t, err)
		assert.Equal(t, existing.ID, got.ID)
	})

	t.Run("list is per user, newest first", func(t *testing.T) {
		s := newStore(t)
		userID, other := createUser(t, s), createUser(t, s)
		base := time.Now().Add(-time.Hour).Truncate(time.Second)
		for i, externalID := range []string{"first", "second", "third"} {
			identity := newIdentity(userID, entity.ProviderTypeGitHub, externalID)
			identity.CreatedAt = base.Add(time.Duration(i) * time.Minute)
			require.NoError(t, s.SaveOAuthIdentity(ctx, identity))
		}
		require.NoError(t, s.SaveOAuthIdentity(ctx, newIdentity(other, entity.ProviderTypeGoogle, "other")))

		list, err := s.ListOAuthIdentities(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, []string{"third", "second", "first"}, externalIDsOf(list))

		list, err = s.ListOAuthIdentities(ctx, other)
		require.NoError(t, err)
		assert.Equal(t, []string{"other"}, externalIDsOf(list))

		list, err = s.ListOAuthIdentities(ctx, uuid.New().String())
		require.NoError(t, err)
		assert.Empty(t, list)
	})
}
