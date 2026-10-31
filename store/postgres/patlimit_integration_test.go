//go:build integration

package postgres

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

// The cap is only race-free because creates for one user queue on its user
// row. Racing goroutines rarely overlap on a small pool, so this holds the
// row lock from outside and checks that a limited save waits for it.
func TestSavePATLimited_WaitsForUserLock(t *testing.T) {
	ctx := context.Background()
	s := getTestStore(t)
	user := &entity.User{ID: uuid.New().String()}
	require.NoError(t, s.Create(ctx, user))

	tx, err := s.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT 1 FROM `+s.tableUsers+` WHERE id = $1 FOR NO KEY UPDATE`, user.ID)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- s.SavePATLimited(ctx,
			&entity.PersonalAccessToken{ID: uuid.New().String(), Hash: "h1", UserID: user.ID, Name: "ci"}, 1, time.Now())
	}()

	select {
	case err := <-done:
		t.Fatalf("saved while another transaction held the user row: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	require.NoError(t, tx.Rollback(ctx))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("save did not resume after the lock was released")
	}
	_, err = s.GetPAT(ctx, "h1")
	assert.NotErrorIs(t, err, store.ErrTokenNotFound)
}
