package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_UserCRUD(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Create user
	user := &entity.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	err := s.Create(ctx, user)
	require.NoError(t, err)

	// Get by ID
	found, err := s.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)
	assert.Equal(t, user.Email, found.Email)

	// Get by email
	found, err = s.GetByEmail(ctx, user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)

	// Duplicate email should fail
	duplicate := &entity.User{
		ID:    "user-456",
		Email: "test@example.com",
	}
	err = s.Create(ctx, duplicate)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrUserExists), "expected ErrUserExists, got: %v", err)

	// Duplicate ID should fail
	duplicateID := &entity.User{
		ID:    "user-123",
		Email: "other@example.com",
	}
	err = s.Create(ctx, duplicateID)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrUserExists), "expected ErrUserExists, got: %v", err)
}

func TestStore_RefreshTokens(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    "user-123",
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
	s := New()
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    "user-123",
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
	s := New()
	ctx := context.Background()

	// Create user first
	user := &entity.User{
		ID:    "user-123",
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
	assert.False(t, foundRoot.Revoked)

	foundChild, err := s.GetRefreshToken(ctx, childToken.Hash)
	require.NoError(t, err)
	assert.False(t, foundChild.Revoked)

	// Revoke using root hash — should revoke both root and child
	err = s.RevokeTokens(ctx, rootToken.Hash)
	require.NoError(t, err)

	// Verify root token is revoked
	foundRoot, err = s.GetRefreshToken(ctx, rootToken.Hash)
	require.NoError(t, err)
	assert.True(t, foundRoot.Revoked)

	// Verify child token is also revoked
	foundChild, err = s.GetRefreshToken(ctx, childToken.Hash)
	require.NoError(t, err)
	assert.True(t, foundChild.Revoked)
}

func TestStore_Delete(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Create user with credentials
	user := &entity.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	require.NoError(t, s.Create(ctx, user))
	require.NoError(t, s.SavePasswordHash(ctx, user.ID, "hash"))

	// Verify user exists
	_, err := s.GetByID(ctx, user.ID)
	require.NoError(t, err)

	// Delete user
	err = s.Delete(ctx, user.ID)
	require.NoError(t, err)

	// Verify user is gone
	_, err = s.GetByID(ctx, user.ID)
	assert.True(t, errors.Is(err, store.ErrUserNotFound))

	// Verify credentials are also gone
	_, err = s.GetPasswordHash(ctx, user.ID)
	assert.True(t, errors.Is(err, store.ErrCredentialNotFound))

	// Delete nonexistent user should fail
	err = s.Delete(ctx, "nonexistent")
	assert.True(t, errors.Is(err, store.ErrUserNotFound))
}

func TestStore_NotFound(t *testing.T) {
	s := New()
	ctx := context.Background()

	// User not found by ID
	_, err := s.GetByID(ctx, "nonexistent")
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
	_, err = s.GetPasswordHash(ctx, "nonexistent-user")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrCredentialNotFound), "expected ErrCredentialNotFound, got: %v", err)

	// SavePasswordHash for nonexistent user
	err = s.SavePasswordHash(ctx, "nonexistent-user", "hash")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrUserNotFound), "expected ErrUserNotFound, got: %v", err)
}
