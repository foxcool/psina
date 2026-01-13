package local_test

import (
	"context"
	"testing"

	"github.com/foxcool/psina/pkg/provider/local"
	"github.com/foxcool/psina/pkg/psina"
	"github.com/foxcool/psina/pkg/store/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider_Register(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	req := &psina.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	identity, err := provider.Register(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, identity.UserID)
	assert.Equal(t, "test@example.com", identity.Email)
	assert.Equal(t, "local", identity.Provider)
}

func TestProvider_RegisterDuplicateEmail(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	req := &psina.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	// First registration
	_, err := provider.Register(context.Background(), req)
	require.NoError(t, err)

	// Second registration with same email should fail
	_, err = provider.Register(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestProvider_Authenticate(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	// Register user
	registerReq := &psina.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}
	_, err := provider.Register(context.Background(), registerReq)
	require.NoError(t, err)

	// Authenticate
	authReq := &psina.AuthRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}
	identity, err := provider.Authenticate(context.Background(), authReq)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", identity.Email)
	assert.Equal(t, "local", identity.Provider)
}

func TestProvider_AuthenticateWrongPassword(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	// Register user
	registerReq := &psina.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}
	_, err := provider.Register(context.Background(), registerReq)
	require.NoError(t, err)

	// Authenticate with wrong password
	authReq := &psina.AuthRequest{
		Email:    "test@example.com",
		Password: "WrongPassword",
	}
	_, err = provider.Authenticate(context.Background(), authReq)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials")
}

func TestProvider_AuthenticateNonexistentUser(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	authReq := &psina.AuthRequest{
		Email:    "nonexistent@example.com",
		Password: "password",
	}
	_, err := provider.Authenticate(context.Background(), authReq)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials")
}

func TestProvider_PasswordHashing(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	// Register two users with same password
	req1 := &psina.RegisterRequest{
		Email:    "user1@example.com",
		Password: "SamePassword123!",
	}
	identity1, err := provider.Register(context.Background(), req1)
	require.NoError(t, err)

	req2 := &psina.RegisterRequest{
		Email:    "user2@example.com",
		Password: "SamePassword123!",
	}
	identity2, err := provider.Register(context.Background(), req2)
	require.NoError(t, err)

	// Password hashes should be different (different salts)
	hash1, err := store.GetPasswordHash(context.Background(), identity1.UserID)
	require.NoError(t, err)

	hash2, err := store.GetPasswordHash(context.Background(), identity2.UserID)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "Password hashes should differ due to random salts")
}
