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

// PATs checks the PATStore rules: a hash maps to exactly one token, lists are
// per user and newest first, deletion is scoped to the owner.
func PATs(t *testing.T, newStore NewBackend) {
	ctx := context.Background()
	// Postgres keeps microseconds; whole seconds compare equal after a round trip.
	now := time.Now().UTC().Truncate(time.Second)

	newPAT := func(userID, hash string) *entity.PersonalAccessToken {
		return &entity.PersonalAccessToken{ID: uuid.New().String(), Hash: hash, UserID: userID, Name: "ci"}
	}
	namesOf := func(list []*entity.PersonalAccessToken) []string {
		names := make([]string, 0, len(list))
		for _, pat := range list {
			names = append(names, pat.Name)
		}
		return names
	}

	t.Run("round trip", func(t *testing.T) {
		s := newStore(t)
		userID := createUser(t, s)
		expires := now.Add(time.Hour)
		want := newPAT(userID, "h1")
		want.Scopes = []string{"eye:read", "eye:write"}
		want.ExpiresAt = &expires
		want.CreatedAt = now
		require.NoError(t, s.SavePAT(ctx, want))

		got, err := s.GetPAT(ctx, "h1")
		require.NoError(t, err)
		assert.Equal(t, want.ID, got.ID)
		assert.Equal(t, userID, got.UserID)
		assert.Equal(t, "ci", got.Name)
		assert.Equal(t, []string{"eye:read", "eye:write"}, got.Scopes)
		require.NotNil(t, got.ExpiresAt)
		assert.True(t, expires.Equal(*got.ExpiresAt))
		assert.Nil(t, got.LastUsedAt)
		assert.True(t, now.Equal(got.CreatedAt), "supplied CreatedAt kept, got %v", got.CreatedAt)
	})

	t.Run("without scopes or expiry", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.SavePAT(ctx, newPAT(createUser(t, s), "h1")))

		got, err := s.GetPAT(ctx, "h1")
		require.NoError(t, err)
		assert.Empty(t, got.Scopes)
		assert.Nil(t, got.ExpiresAt)
		assert.False(t, got.CreatedAt.IsZero(), "CreatedAt should be set on save")
	})

	t.Run("touch records last use", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.SavePAT(ctx, newPAT(createUser(t, s), "h1")))

		require.NoError(t, s.TouchPAT(ctx, "h1", now))
		got, err := s.GetPAT(ctx, "h1")
		require.NoError(t, err)
		require.NotNil(t, got.LastUsedAt)
		assert.True(t, now.Equal(*got.LastUsedAt))
	})

	t.Run("duplicate hash rejected", func(t *testing.T) {
		s := newStore(t)
		owner, other := createUser(t, s), createUser(t, s)
		original := newPAT(owner, "h1")
		require.NoError(t, s.SavePAT(ctx, original))

		assert.ErrorIs(t, s.SavePAT(ctx, newPAT(other, "h1")), store.ErrPATExists)

		got, err := s.GetPAT(ctx, "h1")
		require.NoError(t, err)
		assert.Equal(t, original.ID, got.ID, "the original token survives")
		list, err := s.ListPATs(ctx, other)
		require.NoError(t, err)
		assert.Empty(t, list)
	})

	t.Run("not found", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetPAT(ctx, "missing")
		assert.ErrorIs(t, err, store.ErrTokenNotFound)
		assert.ErrorIs(t, s.DeletePAT(ctx, createUser(t, s), uuid.New().String()), store.ErrTokenNotFound)
	})

	t.Run("list is per user, newest first", func(t *testing.T) {
		s := newStore(t)
		userID, other := createUser(t, s), createUser(t, s)
		for i, name := range []string{"first", "second", "third"} {
			pat := newPAT(userID, name)
			pat.Name = name
			pat.CreatedAt = now.Add(time.Duration(i-3) * time.Minute)
			require.NoError(t, s.SavePAT(ctx, pat))
		}
		require.NoError(t, s.SavePAT(ctx, newPAT(other, "other")))

		list, err := s.ListPATs(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, []string{"third", "second", "first"}, namesOf(list))

		list, err = s.ListPATs(ctx, other)
		require.NoError(t, err)
		assert.Equal(t, []string{"ci"}, namesOf(list))

		list, err = s.ListPATs(ctx, uuid.New().String())
		require.NoError(t, err)
		assert.Empty(t, list)
	})

	t.Run("delete is owner-scoped", func(t *testing.T) {
		s := newStore(t)
		owner, other := createUser(t, s), createUser(t, s)
		pat := newPAT(owner, "h1")
		require.NoError(t, s.SavePAT(ctx, pat))

		assert.ErrorIs(t, s.DeletePAT(ctx, other, pat.ID), store.ErrTokenNotFound)
		_, err := s.GetPAT(ctx, "h1")
		require.NoError(t, err, "another user cannot delete it")

		require.NoError(t, s.DeletePAT(ctx, owner, pat.ID))
		_, err = s.GetPAT(ctx, "h1")
		assert.ErrorIs(t, err, store.ErrTokenNotFound)
	})

	t.Run("limited save counts only unexpired tokens", func(t *testing.T) {
		s := newStore(t)
		userID, other := createUser(t, s), createUser(t, s)
		past, future := now.Add(-time.Hour), now.Add(time.Hour)
		saved := func(hash string, expires *time.Time) error {
			pat := newPAT(userID, hash)
			pat.ExpiresAt = expires
			return s.SavePATLimited(ctx, pat, 2, now)
		}

		require.NoError(t, s.SavePAT(ctx, &entity.PersonalAccessToken{
			ID: uuid.New().String(), Hash: "expired", UserID: userID, ExpiresAt: &past,
		}))
		require.NoError(t, saved("forever", nil))
		require.NoError(t, saved("later", &future))
		assert.ErrorIs(t, saved("third", nil), store.ErrPATLimitReached)

		// The user's expired tokens are pruned; the live ones stay.
		_, getErr := s.GetPAT(ctx, "expired")
		assert.ErrorIs(t, getErr, store.ErrTokenNotFound)
		list, listErr := s.ListPATs(ctx, userID)
		require.NoError(t, listErr)
		assert.Len(t, list, 2)

		// The refused token is not stored, and another user has its own budget.
		_, err := s.GetPAT(ctx, "third")
		assert.ErrorIs(t, err, store.ErrTokenNotFound)
		require.NoError(t, s.SavePATLimited(ctx, newPAT(other, "o1"), 2, now))
	})

	// Verification rejects a PAT only once now is after its expiry, so the
	// prune must keep one expiring at exactly now.
	t.Run("limited save prunes strictly after expiry", func(t *testing.T) {
		s := newStore(t)
		userID := createUser(t, s)
		at, before := now, now.Add(-time.Microsecond)
		for hash, expires := range map[string]*time.Time{"at": &at, "before": &before} {
			require.NoError(t, s.SavePAT(ctx, &entity.PersonalAccessToken{
				ID: uuid.New().String(), Hash: hash, UserID: userID, ExpiresAt: expires,
			}))
		}

		// "at" still holds a slot, so a cap of one refuses the newcomer.
		assert.ErrorIs(t, s.SavePATLimited(ctx, newPAT(userID, "new"), 1, now), store.ErrPATLimitReached)

		_, err := s.GetPAT(ctx, "at")
		require.NoError(t, err, "expiring exactly at now is not expired")
		_, err = s.GetPAT(ctx, "before")
		assert.ErrorIs(t, err, store.ErrTokenNotFound, "expired before now is pruned")
	})

	t.Run("limited save keeps the save rules", func(t *testing.T) {
		s := newStore(t)
		userID := createUser(t, s)
		require.NoError(t, s.SavePATLimited(ctx, newPAT(userID, "h1"), 5, now))

		assert.ErrorIs(t, s.SavePATLimited(ctx, newPAT(userID, "h1"), 5, now), store.ErrPATExists)
		assert.ErrorIs(t, s.SavePATLimited(ctx, newPAT(uuid.New().String(), "h2"), 5, now), store.ErrUserNotFound)
	})
}
