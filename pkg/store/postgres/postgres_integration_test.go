//go:build integration

package postgres

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/testutil"
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
	store := getTestStore(t)
	ctx := context.Background()

	// Create user
	user := &entity.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	err := store.Create(ctx, user)
	require.NoError(t, err)

	// Get by ID
	found, err := store.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)
	assert.Equal(t, user.Email, found.Email)

	// Get by email
	found, err = store.GetByEmail(ctx, user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)

	// Duplicate email should fail
	duplicate := &entity.User{
		ID:    "user-456",
		Email: "test@example.com",
	}
	err = store.Create(ctx, duplicate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestStore_RefreshTokens(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	require.NoError(t, store.Create(ctx, user))

	// Save refresh token
	token := &entity.RefreshToken{
		Hash:   "token-hash-123",
		UserID: user.ID,
	}
	err := store.SaveRefreshToken(ctx, token)
	require.NoError(t, err)

	// Get refresh token
	found, err := store.GetRefreshToken(ctx, token.Hash)
	require.NoError(t, err)
	assert.Equal(t, token.Hash, found.Hash)
	assert.Equal(t, token.UserID, found.UserID)
	assert.False(t, found.Revoked)

	// Revoke token
	err = store.RevokeTokens(ctx, token.Hash)
	require.NoError(t, err)

	// Verify revoked
	found, err = store.GetRefreshToken(ctx, token.Hash)
	require.NoError(t, err)
	assert.True(t, found.Revoked)
}

func TestStore_Credentials(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	require.NoError(t, store.Create(ctx, user))

	// Save password hash
	hash := "$argon2id$v=19$m=65536,t=3,p=2$salt$hash"
	err := store.SavePasswordHash(ctx, user.ID, hash)
	require.NoError(t, err)

	// Get password hash
	found, err := store.GetPasswordHash(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, hash, found)

	// Update password hash
	newHash := "$argon2id$v=19$m=65536,t=3,p=2$salt2$hash2"
	err = store.SavePasswordHash(ctx, user.ID, newHash)
	require.NoError(t, err)

	found, err = store.GetPasswordHash(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, newHash, found)
}

func TestStore_TokenFamilyRevocation(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	require.NoError(t, store.Create(ctx, user))

	// Create root token (parent="")
	rootToken := &entity.RefreshToken{
		Hash:   "root-token-hash",
		UserID: user.ID,
		Parent: "",
	}
	require.NoError(t, store.SaveRefreshToken(ctx, rootToken))

	// Create child token (parent=root.Hash)
	childToken := &entity.RefreshToken{
		Hash:   "child-token-hash",
		UserID: user.ID,
		Parent: rootToken.Hash,
	}
	require.NoError(t, store.SaveRefreshToken(ctx, childToken))

	// Verify both tokens are not revoked initially
	foundRoot, err := store.GetRefreshToken(ctx, rootToken.Hash)
	require.NoError(t, err)
	assert.False(t, foundRoot.Revoked, "root token should not be revoked initially")

	foundChild, err := store.GetRefreshToken(ctx, childToken.Hash)
	require.NoError(t, err)
	assert.False(t, foundChild.Revoked, "child token should not be revoked initially")

	// Revoke using root hash — should revoke both root and child
	err = store.RevokeTokens(ctx, rootToken.Hash)
	require.NoError(t, err)

	// Verify root token is revoked
	foundRoot, err = store.GetRefreshToken(ctx, rootToken.Hash)
	require.NoError(t, err)
	assert.True(t, foundRoot.Revoked, "root token should be revoked")

	// Verify child token is also revoked
	foundChild, err = store.GetRefreshToken(ctx, childToken.Hash)
	require.NoError(t, err)
	assert.True(t, foundChild.Revoked, "child token should be revoked when parent is revoked")
}

func TestStore_NotFound(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	// User not found
	_, err := store.GetByID(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Email not found
	_, err = store.GetByEmail(ctx, "nonexistent@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Token not found
	_, err = store.GetRefreshToken(ctx, "nonexistent-hash")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Credential not found
	_, err = store.GetPasswordHash(ctx, "nonexistent-user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
