//go:build integration

package auth_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/foxcool/psina/pkg/auth"
	"github.com/foxcool/psina/pkg/provider/local"
	"github.com/foxcool/psina/pkg/store/postgres"
	"github.com/foxcool/psina/pkg/testutil"
	"github.com/foxcool/psina/pkg/token"
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

func getTestService(t *testing.T) *auth.Service {
	t.Helper()
	testDB.MustTruncate(t)

	store := postgres.New(testDB.Pool)
	provider := local.New(store, store)
	issuer, err := token.New()
	require.NoError(t, err)

	return auth.NewService(provider, store, store, issuer)
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

func TestE2E_TokenReuseDetection(t *testing.T) {
	service := getTestService(t)
	ctx := context.Background()

	// 1. Register → tokenA (root of the family)
	regResult, err := service.Register(ctx, "reuse@example.com", "password123")
	require.NoError(t, err)
	tokenA := regResult.TokenPair.RefreshToken

	// 2. Refresh tokenA → tokenB (tokenA now revoked)
	tokenPairB, err := service.Refresh(ctx, tokenA)
	require.NoError(t, err)
	tokenB := tokenPairB.RefreshToken

	// 3. Refresh tokenB → tokenC (tokenB now revoked)
	tokenPairC, err := service.Refresh(ctx, tokenB)
	require.NoError(t, err)
	tokenC := tokenPairC.RefreshToken

	// 4. Attacker reuses stolen tokenA (already revoked)
	// This should trigger family revocation
	_, err = service.Refresh(ctx, tokenA)
	assert.ErrorIs(t, err, auth.ErrTokenReuse)

	// 5. Now tokenC should also be invalid (entire family was revoked)
	_, err = service.Refresh(ctx, tokenC)
	assert.Error(t, err, "tokenC should be revoked after tokenA reuse detected")
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
