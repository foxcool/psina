// Package storetest holds behavioural contract tests shared by every store
// backend, so memory (the reference in service unit tests) and postgres cannot
// drift apart semantically.
package storetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NewTokenStore returns an empty store and the ID of an existing user that
// refresh tokens may reference.
type NewTokenStore func(t *testing.T) (s auth.TokenStore, userID string)

// RefreshRotation checks RotateRefreshToken and GetRefreshFamily.
func RefreshRotation(t *testing.T, newStore NewTokenStore) {
	ctx := context.Background()
	// Postgres keeps microseconds; truncate so round-tripped times compare equal.
	now := time.Now().UTC().Truncate(time.Microsecond)

	save := func(t *testing.T, s auth.TokenStore, rt *entity.RefreshToken) {
		t.Helper()
		if rt.ExpiresAt.IsZero() {
			rt.ExpiresAt = now.Add(time.Hour)
		}
		require.NoError(t, s.SaveRefreshToken(ctx, rt))
	}

	t.Run("rotates a live token once", func(t *testing.T) {
		s, userID := newStore(t)
		save(t, s, &entity.RefreshToken{Hash: "r1", UserID: userID})

		rt, err := s.RotateRefreshToken(ctx, "r1", now)
		require.NoError(t, err)
		assert.True(t, rt.Revoked)
		require.NotNil(t, rt.RotatedAt)
		assert.True(t, now.Equal(*rt.RotatedAt))

		rt, err = s.RotateRefreshToken(ctx, "r1", now.Add(time.Second))
		require.ErrorIs(t, err, store.ErrTokenRevoked)
		require.NotNil(t, rt, "loser must get the token to decide on reuse")
		require.NotNil(t, rt.RotatedAt)
		assert.True(t, now.Equal(*rt.RotatedAt), "a failed rotation must not restamp")
	})

	t.Run("not found", func(t *testing.T) {
		s, _ := newStore(t)
		_, err := s.RotateRefreshToken(ctx, "missing", now)
		assert.ErrorIs(t, err, store.ErrTokenNotFound)
	})

	t.Run("expired", func(t *testing.T) {
		s, userID := newStore(t)
		save(t, s, &entity.RefreshToken{Hash: "old", UserID: userID, ExpiresAt: now})

		rt, err := s.RotateRefreshToken(ctx, "old", now)
		require.ErrorIs(t, err, store.ErrTokenExpired)
		assert.False(t, rt.Revoked)
		assert.Nil(t, rt.RotatedAt)
	})

	t.Run("revoked by logout has no rotation stamp", func(t *testing.T) {
		s, userID := newStore(t)
		save(t, s, &entity.RefreshToken{Hash: "r1", UserID: userID})
		require.NoError(t, s.RevokeTokens(ctx, "r1"))

		rt, err := s.RotateRefreshToken(ctx, "r1", now)
		require.ErrorIs(t, err, store.ErrTokenRevoked)
		assert.Nil(t, rt.RotatedAt)
		assert.NotNil(t, rt.EndedAt)
	})

	t.Run("revoking a family with no live member still ends it", func(t *testing.T) {
		// The successor of a rotated root may not be saved yet when a logout lands.
		s, userID := newStore(t)
		save(t, s, &entity.RefreshToken{Hash: "root", UserID: userID})
		_, err := s.RotateRefreshToken(ctx, "root", now)
		require.NoError(t, err)

		require.NoError(t, s.RevokeTokens(ctx, "root"))
		family, err := s.GetRefreshFamily(ctx, "root")
		require.NoError(t, err)
		assert.True(t, family.SessionEnded)
		require.NotNil(t, family.LastRotatedAt, "ending the session keeps rotation history")

		err = s.SaveRefreshToken(ctx, &entity.RefreshToken{
			Hash: "late", UserID: userID, Parent: "root", ExpiresAt: now.Add(time.Hour),
		})
		require.ErrorIs(t, err, store.ErrTokenRevoked, "a successor must not join an ended session")
		_, err = s.GetRefreshToken(ctx, "late")
		assert.ErrorIs(t, err, store.ErrTokenNotFound)
	})

	t.Run("concurrent rotation has one winner", func(t *testing.T) {
		s, userID := newStore(t)
		save(t, s, &entity.RefreshToken{Hash: "r1", UserID: userID})

		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				_, errs[i] = s.RotateRefreshToken(ctx, "r1", now)
			})
		}
		wg.Wait()

		won := 0
		for _, err := range errs {
			if err == nil {
				won++
				continue
			}
			assert.ErrorIs(t, err, store.ErrTokenRevoked)
		}
		assert.Equal(t, 1, won)
	})

	t.Run("family summary", func(t *testing.T) {
		s, userID := newStore(t)
		save(t, s, &entity.RefreshToken{Hash: "root", UserID: userID})
		save(t, s, &entity.RefreshToken{Hash: "c1", UserID: userID, Parent: "root"})
		save(t, s, &entity.RefreshToken{Hash: "other", UserID: userID})

		family, err := s.GetRefreshFamily(ctx, "root")
		require.NoError(t, err)
		assert.False(t, family.SessionEnded)
		assert.Nil(t, family.LastRotatedAt)

		_, err = s.RotateRefreshToken(ctx, "root", now)
		require.NoError(t, err)
		later := now.Add(time.Second)
		_, err = s.RotateRefreshToken(ctx, "c1", later)
		require.NoError(t, err)
		_, err = s.RotateRefreshToken(ctx, "other", later.Add(time.Second))
		require.NoError(t, err)

		family, err = s.GetRefreshFamily(ctx, "root")
		require.NoError(t, err)
		assert.False(t, family.SessionEnded, "rotation alone does not end the session")
		require.NotNil(t, family.LastRotatedAt)
		assert.True(t, later.Equal(*family.LastRotatedAt), "other families must not count")

		save(t, s, &entity.RefreshToken{Hash: "c2", UserID: userID, Parent: "root"})
		require.NoError(t, s.RevokeTokens(ctx, "c2"))
		family, err = s.GetRefreshFamily(ctx, "root")
		require.NoError(t, err)
		assert.True(t, family.SessionEnded)
	})

	t.Run("unknown family is empty", func(t *testing.T) {
		s, _ := newStore(t)
		family, err := s.GetRefreshFamily(ctx, "missing")
		require.NoError(t, err)
		assert.False(t, family.SessionEnded)
		assert.Nil(t, family.LastRotatedAt)
	})
}
