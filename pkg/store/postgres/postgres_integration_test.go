//go:build integration

package postgres

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/store"
	"github.com/foxcool/psina/pkg/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testDB *testutil.TestDB

func TestMain(m *testing.M) {
	ctx := context.Background()

	var err error
	testDB, err = testutil.NewTestDB(ctx)
	if err != nil {
		slog.Error("failed to create test database", "error", err)
		os.Exit(1)
	}

	code := m.Run()

	testDB.Close(ctx)
	os.Exit(code)
}

func getTestStore(t *testing.T) *Store {
	t.Helper()
	testDB.MustTruncate(t)
	return New(testDB.Pool)
}

func TestStore_UserCRUD(t *testing.T) {
	s := getTestStore(t)
	ctx := context.Background()

	// Create user
	user := &entity.User{
		ID:    uuid.New().String(),
		Email: "test@example.com",
		Roles: []string{"admin", "support"},
	}
	err := s.Create(ctx, user)
	require.NoError(t, err)

	// Get by ID
	found, err := s.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)
	assert.Equal(t, user.Email, found.Email)
	assert.Equal(t, []string{"admin", "support"}, found.Roles)

	// Get by email
	found, err = s.GetByEmail(ctx, user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)
	assert.Equal(t, []string{"admin", "support"}, found.Roles)

	// User with nil roles persists and round-trips empty (not NULL)
	noRoles := &entity.User{
		ID:    uuid.New().String(),
		Email: "noroles@example.com",
	}
	err = s.Create(ctx, noRoles)
	require.NoError(t, err)
	found, err = s.GetByID(ctx, noRoles.ID)
	require.NoError(t, err)
	assert.Empty(t, found.Roles)

	// Duplicate email should fail
	duplicate := &entity.User{
		ID:    uuid.New().String(),
		Email: "test@example.com",
	}
	err = s.Create(ctx, duplicate)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrUserExists), "expected ErrUserExists, got: %v", err)
}

func TestStore_RefreshTokens(t *testing.T) {
	s := getTestStore(t)
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    uuid.New().String(),
		Email: "test@example.com",
	}
	require.NoError(t, s.Create(ctx, user))

	// Save refresh token
	token := &entity.RefreshToken{
		Hash:   "token-hash-123",
		UserID: user.ID,
	}
	err := s.SaveRefreshToken(ctx, token)
	require.NoError(t, err)

	// Get refresh token
	found, err := s.GetRefreshToken(ctx, token.Hash)
	require.NoError(t, err)
	assert.Equal(t, token.Hash, found.Hash)
	assert.Equal(t, token.UserID, found.UserID)
	assert.False(t, found.Revoked)

	// Revoke token
	err = s.RevokeTokens(ctx, token.Hash)
	require.NoError(t, err)

	// Verify revoked
	found, err = s.GetRefreshToken(ctx, token.Hash)
	require.NoError(t, err)
	assert.True(t, found.Revoked)
}

func TestStore_Credentials(t *testing.T) {
	s := getTestStore(t)
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    uuid.New().String(),
		Email: "test@example.com",
	}
	require.NoError(t, s.Create(ctx, user))

	// Save password hash
	hash := "$argon2id$v=19$m=65536,t=3,p=2$salt$hash"
	err := s.SavePasswordHash(ctx, user.ID, hash)
	require.NoError(t, err)

	// Get password hash
	found, err := s.GetPasswordHash(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, hash, found)

	// Update password hash
	newHash := "$argon2id$v=19$m=65536,t=3,p=2$salt2$hash2"
	err = s.SavePasswordHash(ctx, user.ID, newHash)
	require.NoError(t, err)

	found, err = s.GetPasswordHash(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, newHash, found)
}

func TestStore_TokenFamilyRevocation(t *testing.T) {
	s := getTestStore(t)
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    uuid.New().String(),
		Email: "test@example.com",
	}
	require.NoError(t, s.Create(ctx, user))

	// Create root token (parent="")
	rootToken := &entity.RefreshToken{
		Hash:   "root-token-hash",
		UserID: user.ID,
		Parent: "",
	}
	require.NoError(t, s.SaveRefreshToken(ctx, rootToken))

	// Create child token (parent=root.Hash)
	childToken := &entity.RefreshToken{
		Hash:   "child-token-hash",
		UserID: user.ID,
		Parent: rootToken.Hash,
	}
	require.NoError(t, s.SaveRefreshToken(ctx, childToken))

	// Verify both tokens are not revoked initially
	foundRoot, err := s.GetRefreshToken(ctx, rootToken.Hash)
	require.NoError(t, err)
	assert.False(t, foundRoot.Revoked, "root token should not be revoked initially")

	foundChild, err := s.GetRefreshToken(ctx, childToken.Hash)
	require.NoError(t, err)
	assert.False(t, foundChild.Revoked, "child token should not be revoked initially")

	// Revoke using root hash — should revoke both root and child
	err = s.RevokeTokens(ctx, rootToken.Hash)
	require.NoError(t, err)

	// Verify root token is revoked
	foundRoot, err = s.GetRefreshToken(ctx, rootToken.Hash)
	require.NoError(t, err)
	assert.True(t, foundRoot.Revoked, "root token should be revoked")

	// Verify child token is also revoked
	foundChild, err = s.GetRefreshToken(ctx, childToken.Hash)
	require.NoError(t, err)
	assert.True(t, foundChild.Revoked, "child token should be revoked when parent is revoked")
}

func TestStore_NotFound(t *testing.T) {
	s := getTestStore(t)
	ctx := context.Background()

	nonexistentID := uuid.New().String()

	// User not found by ID
	_, err := s.GetByID(ctx, nonexistentID)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrUserNotFound), "expected ErrUserNotFound, got: %v", err)

	// User not found by email
	_, err = s.GetByEmail(ctx, "nonexistent@example.com")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrUserNotFound), "expected ErrUserNotFound, got: %v", err)

	// Token not found
	_, err = s.GetRefreshToken(ctx, "nonexistent-hash")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrTokenNotFound), "expected ErrTokenNotFound, got: %v", err)

	// Credential not found
	_, err = s.GetPasswordHash(ctx, nonexistentID)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrCredentialNotFound), "expected ErrCredentialNotFound, got: %v", err)
}

func TestStore_PATCRUD(t *testing.T) {
	s := getTestStore(t)
	ctx := context.Background()

	user := &entity.User{ID: uuid.New().String(), Email: "pat@example.com"}
	require.NoError(t, s.Create(ctx, user))

	exp := timePtr(t)
	pat := &entity.PersonalAccessToken{
		ID:        uuid.New().String(),
		Hash:      "pat-hash-1",
		UserID:    user.ID,
		Name:      "ci",
		Scopes:    []string{"eye:read", "eye:write"},
		ExpiresAt: exp,
	}
	require.NoError(t, s.SavePAT(ctx, pat))

	got, err := s.GetPAT(ctx, "pat-hash-1")
	require.NoError(t, err)
	assert.Equal(t, pat.ID, got.ID)
	assert.Equal(t, user.ID, got.UserID)
	assert.Equal(t, "ci", got.Name)
	assert.Equal(t, []string{"eye:read", "eye:write"}, got.Scopes)
	require.NotNil(t, got.ExpiresAt)
	assert.Nil(t, got.LastUsedAt)

	// Touch updates last_used_at.
	require.NoError(t, s.TouchPAT(ctx, "pat-hash-1", exp.Add(time.Minute)))
	got, err = s.GetPAT(ctx, "pat-hash-1")
	require.NoError(t, err)
	require.NotNil(t, got.LastUsedAt)

	// List returns it.
	pats, err := s.ListPATs(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, pats, 1)

	// Delete scoped to a different owner is a no-op (not found).
	err = s.DeletePAT(ctx, uuid.New().String(), pat.ID)
	assert.True(t, errors.Is(err, store.ErrTokenNotFound))

	// Delete by the real owner removes it.
	require.NoError(t, s.DeletePAT(ctx, user.ID, pat.ID))
	_, err = s.GetPAT(ctx, "pat-hash-1")
	assert.True(t, errors.Is(err, store.ErrTokenNotFound))
}

func timePtr(t *testing.T) *time.Time {
	t.Helper()
	v := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	return &v
}
