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

// Users checks the UserStore rules: IDs and emails are unique, users without
// an email (wallet sign-in) coexist and are never found by email, and the
// store never shares a *entity.User with its caller.
func Users(t *testing.T, newStore func(t *testing.T) auth.UserStore) {
	ctx := context.Background()

	newUser := func(email string) *entity.User {
		return &entity.User{ID: uuid.New().String(), Email: email}
	}

	t.Run("round trip", func(t *testing.T) {
		s := newStore(t)
		want := newUser("user@example.com")
		want.Roles = []string{"admin", "support"}
		require.NoError(t, s.Create(ctx, want))

		for name, get := range map[string]func() (*entity.User, error){
			"by id":    func() (*entity.User, error) { return s.GetByID(ctx, want.ID) },
			"by email": func() (*entity.User, error) { return s.GetByEmail(ctx, "user@example.com") },
		} {
			got, err := get()
			require.NoError(t, err, name)
			assert.Equal(t, want.ID, got.ID, name)
			assert.Equal(t, "user@example.com", got.Email, name)
			assert.Equal(t, []string{"admin", "support"}, got.Roles, name)
			assert.False(t, got.CreatedAt.IsZero(), name)
		}
	})

	t.Run("without roles", func(t *testing.T) {
		s := newStore(t)
		user := newUser("user@example.com")
		require.NoError(t, s.Create(ctx, user))

		got, err := s.GetByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Empty(t, got.Roles)
	})

	t.Run("not found", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetByID(ctx, uuid.New().String())
		assert.ErrorIs(t, err, store.ErrUserNotFound)
		_, err = s.GetByEmail(ctx, "nobody@example.com")
		assert.ErrorIs(t, err, store.ErrUserNotFound)
		assert.ErrorIs(t, s.Delete(ctx, uuid.New().String()), store.ErrUserNotFound)
	})

	t.Run("delete", func(t *testing.T) {
		s := newStore(t)
		user := newUser("user@example.com")
		require.NoError(t, s.Create(ctx, user))

		require.NoError(t, s.Delete(ctx, user.ID))
		_, err := s.GetByID(ctx, user.ID)
		assert.ErrorIs(t, err, store.ErrUserNotFound)
		_, err = s.GetByEmail(ctx, "user@example.com")
		assert.ErrorIs(t, err, store.ErrUserNotFound)
		require.NoError(t, s.Create(ctx, newUser("user@example.com")), "the email is free again")
	})

	t.Run("duplicate id rejected", func(t *testing.T) {
		s := newStore(t)
		user := newUser("first@example.com")
		require.NoError(t, s.Create(ctx, user))

		err := s.Create(ctx, &entity.User{ID: user.ID, Email: "second@example.com"})
		assert.ErrorIs(t, err, store.ErrUserExists)
	})

	t.Run("caller mutations do not reach the store", func(t *testing.T) {
		s := newStore(t)
		user := newUser("user@example.com")
		user.Roles = []string{"admin"}
		require.NoError(t, s.Create(ctx, user))

		user.Email = "changed@example.com"
		user.Roles[0] = "changed"
		got, err := s.GetByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", got.Email, "the created user is copied")
		assert.Equal(t, []string{"admin"}, got.Roles, "the created roles are copied")

		got.Email = "changed@example.com"
		got.Roles[0] = "changed"
		byEmail, err := s.GetByEmail(ctx, "user@example.com")
		require.NoError(t, err)
		byEmail.Roles[0] = "changed"

		got, err = s.GetByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", got.Email, "a returned user is a copy")
		assert.Equal(t, []string{"admin"}, got.Roles, "returned roles are a copy")
	})

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
