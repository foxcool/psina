//go:build integration

package postgres

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/foxcool/psina/migrations"
	"github.com/foxcool/psina/pkg/psina"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	// Check if running in integration test environment
	if os.Getenv("DOCKER_COMPOSE_TEST") != "true" {
		slog.Info("Skipping integration tests (DOCKER_COMPOSE_TEST not set)")
		os.Exit(0)
	}

	dsn := os.Getenv("PSINA_DB_URL")
	if dsn == "" {
		slog.Error("PSINA_DB_URL not set")
		os.Exit(1)
	}

	var err error
	testPool, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		slog.Error("failed to create pool", "error", err)
		os.Exit(1)
	}
	defer testPool.Close()

	// Run migrations
	if err := migrations.Apply(context.Background(), testPool); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	code := m.Run()
	os.Exit(code)
}

// getTestStore returns a store with transaction for test isolation.
// Rollback is called automatically after test.
func getTestStore(t *testing.T) *Store {
	t.Helper()

	ctx := context.Background()

	// Start transaction for test isolation
	tx, err := testPool.Begin(ctx)
	require.NoError(t, err)

	// Cleanup after test
	t.Cleanup(func() {
		_ = tx.Rollback(ctx)
	})

	// Create a pool-like wrapper that uses the transaction
	// For simplicity, we'll clean tables instead of using transaction
	_, err = testPool.Exec(ctx, `
		TRUNCATE TABLE refresh_tokens, local_credentials, users CASCADE
	`)
	require.NoError(t, err)

	return New(testPool)
}

func TestStore_UserCRUD(t *testing.T) {
	store := getTestStore(t)
	ctx := context.Background()

	// Create user
	user := &psina.User{
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
	duplicate := &psina.User{
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
	user := &psina.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	require.NoError(t, store.Create(ctx, user))

	// Save refresh token
	token := &psina.RefreshToken{
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
	err = store.RevokeRefreshToken(ctx, token.Hash)
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
	user := &psina.User{
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
