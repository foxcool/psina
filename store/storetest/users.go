package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Users checks the UserStore email rules: emails are unique, while users
// without an email (wallet sign-in) coexist and are never found by email.
func Users(t *testing.T, newStore func(t *testing.T) auth.UserStore) {
	ctx := context.Background()

	newUser := func(email string) *entity.User {
		return &entity.User{ID: uuid.New().String(), Email: email}
	}

	t.Run("duplicate email rejected", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.Create(ctx, newUser("dup@example.com")))

		err := s.Create(ctx, newUser("dup@example.com"))
		assert.True(t, errors.Is(err, store.ErrUserExists), "got %v", err)
	})

	t.Run("email-less users coexist", func(t *testing.T) {
		s := newStore(t)
		first, second := newUser(""), newUser("")
		require.NoError(t, s.Create(ctx, first))
		require.NoError(t, s.Create(ctx, second))

		got, err := s.GetByID(ctx, second.ID)
		require.NoError(t, err)
		assert.Empty(t, got.Email)
	})

	t.Run("empty email is never found", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.Create(ctx, newUser("")))

		_, err := s.GetByEmail(ctx, "")
		assert.True(t, errors.Is(err, store.ErrUserNotFound), "got %v", err)
	})
}
