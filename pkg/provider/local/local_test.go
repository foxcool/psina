package local_test

import (
	"context"
	"errors"
	"testing"

	"github.com/foxcool/psina/pkg/auth"
	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/provider/local"
	"github.com/foxcool/psina/pkg/store/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider_Register(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	req := &entity.RegisterRequest{
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

	req := &entity.RegisterRequest{
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
	registerReq := &entity.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}
	_, err := provider.Register(context.Background(), registerReq)
	require.NoError(t, err)

	// Authenticate
	authReq := &entity.AuthRequest{
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
	registerReq := &entity.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}
	_, err := provider.Register(context.Background(), registerReq)
	require.NoError(t, err)

	// Authenticate with wrong password
	authReq := &entity.AuthRequest{
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

	authReq := &entity.AuthRequest{
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
	req1 := &entity.RegisterRequest{
		Email:    "user1@example.com",
		Password: "SamePassword123!",
	}
	identity1, err := provider.Register(context.Background(), req1)
	require.NoError(t, err)

	req2 := &entity.RegisterRequest{
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

// failingCredentialStore always fails on SavePasswordHash
type failingCredentialStore struct {
	auth.CredentialStore
}

func (f *failingCredentialStore) SavePasswordHash(ctx context.Context, userID, hash string) error {
	return errors.New("database connection lost")
}

func (f *failingCredentialStore) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	return "", errors.New("database connection lost")
}

func TestProvider_RegisterCompensatingDelete(t *testing.T) {
	userStore := memory.New()
	credStore := &failingCredentialStore{}
	provider := local.New(userStore, credStore)

	req := &entity.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	// Registration should fail due to credential store error
	_, err := provider.Register(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store password")

	// User should NOT exist (compensating delete worked)
	_, err = userStore.GetByEmail(context.Background(), "test@example.com")
	assert.Error(t, err, "user should be deleted after credential store failure")
}
