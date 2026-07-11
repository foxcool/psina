package memory

import (
	"context"
	"errors"
	"testing"
	"time"

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

	// User without roles round-trips empty
	noRoles := &entity.User{
		ID:    "user-789",
		Email: "noroles@example.com",
	}
	err = s.Create(ctx, noRoles)
	require.NoError(t, err)
	found, err = s.GetByID(ctx, noRoles.ID)
	require.NoError(t, err)
	assert.Empty(t, found.Roles)

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

func TestStore_OAuthIdentities(t *testing.T) {
	s := New()
	ctx := context.Background()

	identity := &entity.OAuthIdentity{
		ID:         "oauth-1",
		UserID:     "user-123",
		Provider:   entity.ProviderTypeGoogle,
		ExternalID: "sub-42",
		Email:      "test@gmail.com",
	}
	require.NoError(t, s.SaveOAuthIdentity(ctx, identity))

	// Get by natural key
	found, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-42")
	require.NoError(t, err)
	assert.Equal(t, identity.ID, found.ID)
	assert.Equal(t, identity.UserID, found.UserID)
	assert.Equal(t, identity.Email, found.Email)
	assert.False(t, found.CreatedAt.IsZero(), "CreatedAt should be set on save")

	// Returned value is a copy — mutating it must not affect the store
	found.Email = "mutated@example.com"
	again, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-42")
	require.NoError(t, err)
	assert.Equal(t, "test@gmail.com", again.Email)

	// Same user, second provider
	require.NoError(t, s.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
		ID:         "oauth-2",
		UserID:     "user-123",
		Provider:   entity.ProviderTypeGitHub,
		ExternalID: "99",
	}))

	list, err := s.ListOAuthIdentities(ctx, "user-123")
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// Unknown lookups
	_, err = s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "unknown")
	assert.True(t, errors.Is(err, store.ErrOAuthIdentityNotFound), "expected ErrOAuthIdentityNotFound, got: %v", err)

	list, err = s.ListOAuthIdentities(ctx, "nobody")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestStore_Challenges(t *testing.T) {
	s := New()
	ctx := context.Background()

	challenge := &entity.Challenge{
		Nonce:     "nonce-1",
		Message:   "sign me",
		Chain:     "ethereum",
		Address:   "0xAbC",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	require.NoError(t, s.SaveChallenge(ctx, challenge))

	found, err := s.GetChallenge(ctx, "nonce-1")
	require.NoError(t, err)
	assert.Equal(t, "sign me", found.Message)
	assert.Equal(t, "ethereum", found.Chain)
	assert.Equal(t, "0xAbC", found.Address)
	assert.False(t, found.CreatedAt.IsZero(), "CreatedAt should be set on save")

	// Single-use: delete, then gone
	require.NoError(t, s.DeleteChallenge(ctx, "nonce-1"))
	_, err = s.GetChallenge(ctx, "nonce-1")
	assert.True(t, errors.Is(err, store.ErrChallengeNotFound), "expected ErrChallengeNotFound, got: %v", err)

	// Deleting again reports not found
	err = s.DeleteChallenge(ctx, "nonce-1")
	assert.True(t, errors.Is(err, store.ErrChallengeNotFound), "expected ErrChallengeNotFound, got: %v", err)
}

func TestStore_ChallengeExpiry(t *testing.T) {
	s := New()
	ctx := context.Background()

	expired := &entity.Challenge{
		Nonce:     "nonce-expired",
		ExpiresAt: time.Now().Add(-time.Second),
	}
	require.NoError(t, s.SaveChallenge(ctx, expired))

	// Expired challenge is reported as such and removed
	_, err := s.GetChallenge(ctx, "nonce-expired")
	assert.True(t, errors.Is(err, store.ErrChallengeExpired), "expected ErrChallengeExpired, got: %v", err)
	_, err = s.GetChallenge(ctx, "nonce-expired")
	assert.True(t, errors.Is(err, store.ErrChallengeNotFound), "expected ErrChallengeNotFound after expiry cleanup, got: %v", err)

	// Sweep on save evicts other expired challenges
	require.NoError(t, s.SaveChallenge(ctx, &entity.Challenge{
		Nonce:     "nonce-stale",
		ExpiresAt: time.Now().Add(-time.Second),
	}))
	require.NoError(t, s.SaveChallenge(ctx, &entity.Challenge{
		Nonce:     "nonce-live",
		ExpiresAt: time.Now().Add(time.Minute),
	}))
	_, err = s.GetChallenge(ctx, "nonce-stale")
	assert.True(t, errors.Is(err, store.ErrChallengeNotFound), "expected stale challenge swept on save, got: %v", err)
	_, err = s.GetChallenge(ctx, "nonce-live")
	assert.NoError(t, err)
}
