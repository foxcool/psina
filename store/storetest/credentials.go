package storetest

import (
	"context"
	"testing"

	"github.com/foxcool/psina/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Credentials checks the CredentialStore round trip: saving again replaces
// the hash (password change), and a user without one is reported as such.
func Credentials(t *testing.T, newStore NewBackend) {
	ctx := context.Background()

	t.Run("save, get, replace", func(t *testing.T) {
		s := newStore(t)
		userID := createUser(t, s)

		require.NoError(t, s.SavePasswordHash(ctx, userID, "first"))
		got, err := s.GetPasswordHash(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, "first", got)

		require.NoError(t, s.SavePasswordHash(ctx, userID, "second"))
		got, err = s.GetPasswordHash(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, "second", got)
	})

	t.Run("not found", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetPasswordHash(ctx, createUser(t, s))
		assert.ErrorIs(t, err, store.ErrCredentialNotFound)
		_, err = s.GetPasswordHash(ctx, uuid.New().String())
		assert.ErrorIs(t, err, store.ErrCredentialNotFound)
	})
}
