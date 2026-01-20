//go:build integration

package psina_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/foxcool/psina/migrations"
	"github.com/foxcool/psina/pkg/provider/local"
	"github.com/foxcool/psina/pkg/psina"
	"github.com/foxcool/psina/pkg/store/postgres"
	"github.com/foxcool/psina/pkg/token"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	if os.Getenv("DOCKER_COMPOSE_TEST") != "true" {
		slog.Info("Skipping integration tests")
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

func cleanupTables(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(context.Background(), `
		TRUNCATE TABLE refresh_tokens, local_credentials, users CASCADE
	`)
	require.NoError(t, err)
}

func getTestService(t *testing.T) *psina.Service {
	t.Helper()
	cleanupTables(t)

	store := postgres.New(testPool)
	provider := local.New(store, store)
	tokenIssuer, err := token.New(store, store)
	require.NoError(t, err)

	return psina.NewService(provider, store, tokenIssuer)
}

func TestE2E_FullAuthFlow(t *testing.T) {
	service := getTestService(t)
	ctx := context.Background()

	// 1. Register
	regResult, err := service.Register(ctx, "user@example.com", "securepassword123")
	require.NoError(t, err)
	assert.NotEmpty(t, regResult.UserID)
	assert.Equal(t, "user@example.com", regResult.Email)
	assert.NotEmpty(t, regResult.TokenPair.AccessToken)
	assert.NotEmpty(t, regResult.TokenPair.RefreshToken)

	// 2. Verify access token
	claims, err := service.Verify(ctx, regResult.TokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, regResult.UserID, claims.UserID)
	assert.Equal(t, regResult.Email, claims.Email)

	// 3. Login with same credentials
	loginResult, err := service.Login(ctx, "user@example.com", "securepassword123")
	require.NoError(t, err)
	assert.Equal(t, regResult.UserID, loginResult.UserID)
	assert.NotEmpty(t, loginResult.TokenPair.AccessToken)

	// 4. Refresh tokens
	newTokens, err := service.Refresh(ctx, loginResult.TokenPair.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newTokens.AccessToken)
	assert.NotEmpty(t, newTokens.RefreshToken)
	assert.NotEqual(t, loginResult.TokenPair.AccessToken, newTokens.AccessToken)

	// 5. Old refresh token should be revoked
	_, err = service.Refresh(ctx, loginResult.TokenPair.RefreshToken)
	assert.Error(t, err)

	// 6. Logout (revoke new refresh token)
	err = service.Logout(ctx, newTokens.RefreshToken)
	require.NoError(t, err)

	// 7. Refresh with revoked token should fail
	_, err = service.Refresh(ctx, newTokens.RefreshToken)
	assert.Error(t, err)
}

func TestE2E_DuplicateRegistration(t *testing.T) {
	service := getTestService(t)
	ctx := context.Background()

	// First registration
	_, err := service.Register(ctx, "duplicate@example.com", "password123")
	require.NoError(t, err)

	// Second registration with same email should fail
	_, err = service.Register(ctx, "duplicate@example.com", "differentpassword")
	assert.Error(t, err)
}

func TestE2E_InvalidLogin(t *testing.T) {
	service := getTestService(t)
	ctx := context.Background()

	// Register
	_, err := service.Register(ctx, "login@example.com", "correctpassword")
	require.NoError(t, err)

	// Wrong password
	_, err = service.Login(ctx, "login@example.com", "wrongpassword")
	assert.Error(t, err)

	// Non-existent user
	_, err = service.Login(ctx, "nonexistent@example.com", "anypassword")
	assert.Error(t, err)
}

func TestE2E_EmailNormalization(t *testing.T) {
	service := getTestService(t)
	ctx := context.Background()

	// Register with uppercase
	_, err := service.Register(ctx, "UPPER@EXAMPLE.COM", "password123")
	require.NoError(t, err)

	// Login with lowercase should work
	_, err = service.Login(ctx, "upper@example.com", "password123")
	require.NoError(t, err)

	// Login with mixed case should work
	_, err = service.Login(ctx, "Upper@Example.Com", "password123")
	require.NoError(t, err)
}

func TestE2E_PasswordValidation(t *testing.T) {
	service := getTestService(t)
	ctx := context.Background()

	// Too short
	_, err := service.Register(ctx, "short@example.com", "short")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password")
}

func TestE2E_EmailValidation(t *testing.T) {
	service := getTestService(t)
	ctx := context.Background()

	// Invalid email
	_, err := service.Register(ctx, "notanemail", "password123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email")
}
