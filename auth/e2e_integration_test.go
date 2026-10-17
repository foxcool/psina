//go:build integration

package auth_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/local"
	"github.com/foxcool/psina/store/postgres"
	"github.com/foxcool/psina/testutil"
	"github.com/foxcool/psina/token"
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

func getTestService(t *testing.T, opts ...auth.ServiceOption) *auth.Service {
	t.Helper()
	testDB.MustTruncate(t)

	store := postgres.New(testDB.Pool)
	provider := local.New(store, store)
	issuer, err := token.New()
	require.NoError(t, err)

	opts = append([]auth.ServiceOption{auth.WithPAT(store, auth.PATConfig{})}, opts...)
	return auth.NewService(store, store, issuer, []auth.Provider{provider}, opts...)
}

// concurrentRefresh presents the same refresh token n times in parallel.
func concurrentRefresh(t *testing.T, service *auth.Service, refreshToken string, n int) (pairs []string, reuse int) {
	t.Helper()
	ctx := context.Background()
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			pair, err := service.Refresh(ctx, refreshToken)
			errs[i] = err
			if err == nil {
				results[i] = pair.RefreshToken
			}
		})
	}
	wg.Wait()
	for i, err := range errs {
		switch {
		case err == nil:
			pairs = append(pairs, results[i])
		case errors.Is(err, auth.ErrTokenReuse):
			reuse++
		default:
			t.Errorf("unexpected refresh error: %v", err)
		}
	}
	return pairs, reuse
}

func TestE2E_ConcurrentRefresh(t *testing.T) {
	const n = 10
	ctx := context.Background()

	t.Run("leeway: every duplicate succeeds and the family stays alive", func(t *testing.T) {
		service := getTestService(t)
		reg, err := service.Register(ctx, "concurrent@example.com", "password123")
		require.NoError(t, err)

		pairs, _ := concurrentRefresh(t, service, reg.TokenPair.RefreshToken, n)
		require.Len(t, pairs, n)
		for _, rt := range pairs {
			_, err := service.Refresh(ctx, rt)
			assert.NoError(t, err, "every successor must be a live family member")
		}
	})

	t.Run("strict: concurrent replays end the session", func(t *testing.T) {
		service := getTestService(t, auth.WithRefreshReuseLeeway(0))
		reg, err := service.Register(ctx, "strict@example.com", "password123")
		require.NoError(t, err)

		pairs, reuse := concurrentRefresh(t, service, reg.TokenPair.RefreshToken, n)
		assert.LessOrEqual(t, len(pairs), 1)
		assert.Equal(t, n, len(pairs)+reuse)
		for _, rt := range pairs {
			_, err := service.Refresh(ctx, rt)
			assert.ErrorIs(t, err, auth.ErrTokenReuse, "nothing issued may outlive the ended session")
		}
	})

	t.Run("logout racing a refresh leaves nothing usable", func(t *testing.T) {
		// Probabilistic: the interleaving that matters (logout's UPDATE
		// overlapping the successor INSERT) is hit only on some iterations.
		service := getTestService(t)
		for i := range 10 {
			reg, err := service.Register(ctx, fmt.Sprintf("race%d@example.com", i), "password123")
			require.NoError(t, err)
			rt := reg.TokenPair.RefreshToken

			var pair *entity.TokenPair
			var refreshErr error
			var wg sync.WaitGroup
			wg.Go(func() { pair, refreshErr = service.Refresh(ctx, rt) })
			wg.Go(func() { assert.NoError(t, service.Logout(ctx, rt)) })
			wg.Wait()

			// Logout first: the refresh is refused as reuse. Refresh first: its
			// successor must not outlive the logout that follows.
			if refreshErr != nil {
				assert.ErrorIs(t, refreshErr, auth.ErrTokenReuse, "iteration %d", i)
				continue
			}
			if pair != nil {
				_, err := service.Refresh(ctx, pair.RefreshToken)
				assert.ErrorIs(t, err, auth.ErrTokenReuse, "iteration %d: successor outlived logout", i)
			}
		}
	})

	t.Run("replay after the leeway revokes the family", func(t *testing.T) {
		// Refresh calls below are sequential, so a plain variable is enough.
		now := time.Now()
		service := getTestService(t, auth.WithClock(func() time.Time { return now }))
		reg, err := service.Register(ctx, "late@example.com", "password123")
		require.NoError(t, err)

		next, err := service.Refresh(ctx, reg.TokenPair.RefreshToken)
		require.NoError(t, err)

		now = now.Add(auth.DefaultRefreshReuseLeeway + time.Second)
		_, err = service.Refresh(ctx, reg.TokenPair.RefreshToken)
		require.ErrorIs(t, err, auth.ErrTokenReuse)
		_, err = service.Refresh(ctx, next.RefreshToken)
		assert.ErrorIs(t, err, auth.ErrTokenReuse, "successor must be revoked with the family")
	})
}

func TestE2E_FullAuthFlow(t *testing.T) {
	// Strict reuse detection: step 5 replays a token right after rotating it.
	service := getTestService(t, auth.WithRefreshReuseLeeway(0))
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
	assert.ErrorIs(t, err, auth.ErrUserExists)
}

func TestE2E_InvalidLogin(t *testing.T) {
	service := getTestService(t)
	ctx := context.Background()

	// Register
	_, err := service.Register(ctx, "login@example.com", "correctpassword")
	require.NoError(t, err)

	// Wrong password
	_, err = service.Login(ctx, "login@example.com", "wrongpassword")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)

	// Non-existent user
	_, err = service.Login(ctx, "nonexistent@example.com", "anypassword")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
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
