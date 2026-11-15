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

// RefreshRotation checks RotateRefreshToken, GetRefreshFamily and the sweep
// of expired families.
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

	t.Run("revoking a family with no live member ends it and refuses successors", func(t *testing.T) {
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

	t.Run("successor without a root row is refused", func(t *testing.T) {
		// The root anchors the session lock; with it gone a revoke could not
		// serialise against this save.
		s, userID := newStore(t)
		err := s.SaveRefreshToken(ctx, &entity.RefreshToken{
			Hash: "orphan", UserID: userID, Parent: "gone", ExpiresAt: now.Add(time.Hour),
		})
		require.ErrorIs(t, err, store.ErrTokenRevoked)
		_, err = s.GetRefreshToken(ctx, "orphan")
		assert.ErrorIs(t, err, store.ErrTokenNotFound)
	})

	t.Run("starting a session sweeps families whose every member expired", func(t *testing.T) {
		s, userID := newStore(t)
		past := time.Now().Add(-time.Hour)
		// Rotated, then expired.
		save(t, s, &entity.RefreshToken{Hash: "dead", UserID: userID, ExpiresAt: past})
		save(t, s, &entity.RefreshToken{Hash: "dead-c1", UserID: userID, Parent: "dead", ExpiresAt: past})
		// Ended by logout, then expired.
		save(t, s, &entity.RefreshToken{Hash: "ended", UserID: userID, ExpiresAt: past})
		require.NoError(t, s.RevokeTokens(ctx, "ended"))

		save(t, s, &entity.RefreshToken{Hash: "fresh", UserID: userID})

		for _, hash := range []string{"dead", "dead-c1", "ended"} {
			_, err := s.GetRefreshToken(ctx, hash)
			assert.ErrorIs(t, err, store.ErrTokenNotFound, hash)
		}
		_, err := s.GetRefreshToken(ctx, "fresh")
		assert.NoError(t, err)
	})

	t.Run("sweep keeps a live family's root and every member that could still be replayed", func(t *testing.T) {
		// The root expires before its successors; deleting it would end the
		// session (successors need the root row), and deleting a rotated or
		// ended member before it expires would turn a replay into an unknown
		// token instead of detected reuse.
		s, userID := newStore(t)
		wall := time.Now()
		past, future := wall.Add(-time.Hour), wall.Add(time.Hour)
		save(t, s, &entity.RefreshToken{Hash: "root", UserID: userID, ExpiresAt: past})
		save(t, s, &entity.RefreshToken{Hash: "c1", UserID: userID, Parent: "root", ExpiresAt: past})
		save(t, s, &entity.RefreshToken{Hash: "c2", UserID: userID, Parent: "root", ExpiresAt: future})
		_, err := s.RotateRefreshToken(ctx, "c2", wall)
		require.NoError(t, err)
		save(t, s, &entity.RefreshToken{Hash: "c3", UserID: userID, Parent: "root", ExpiresAt: future})
		// A logged-out session whose tokens have not expired yet.
		save(t, s, &entity.RefreshToken{Hash: "out", UserID: userID, ExpiresAt: future})
		require.NoError(t, s.RevokeTokens(ctx, "out"))

		save(t, s, &entity.RefreshToken{Hash: "fresh", UserID: userID})

		for _, hash := range []string{"root", "c1", "c2", "c3", "out"} {
			_, err := s.GetRefreshToken(ctx, hash)
			assert.NoError(t, err, hash)
		}
		_, err = s.RotateRefreshToken(ctx, "c2", wall)
		require.ErrorIs(t, err, store.ErrTokenRevoked, "a replayed rotated token is still recognised")
		_, err = s.RotateRefreshToken(ctx, "out", wall)
		require.ErrorIs(t, err, store.ErrTokenRevoked, "a replayed logged-out token is still recognised")
		require.NoError(t, s.SaveRefreshToken(ctx, &entity.RefreshToken{
			Hash: "c4", UserID: userID, Parent: "root", ExpiresAt: future,
		}), "the live session continues")
	})

	t.Run("unknown family is empty", func(t *testing.T) {
		s, _ := newStore(t)
		family, err := s.GetRefreshFamily(ctx, "missing")
		require.NoError(t, err)
		assert.False(t, family.SessionEnded)
		assert.Nil(t, family.LastRotatedAt)
	})
}
