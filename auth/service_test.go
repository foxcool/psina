package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider implements Provider for testing.
type mockProvider struct {
	registerFn     func(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error)
	authenticateFn func(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error)
}

func (m *mockProvider) Type() string { return entity.ProviderTypeLocal }

func (m *mockProvider) Register(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error) {
	if m.registerFn != nil {
		return m.registerFn(ctx, req)
	}
	return &entity.Identity{
		UserID:   "user-123",
		Email:    req.Email,
		Provider: "mock",
	}, nil
}

func (m *mockProvider) Authenticate(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, req)
	}
	return &entity.Identity{
		UserID:   "user-123",
		Email:    req.Email,
		Provider: "mock",
	}, nil
}

func setupTestService(t *testing.T, opts ...ServiceOption) (*Service, *memory.Store) {
	t.Helper()
	memStore := memory.New()
	issuer, err := token.New()
	require.NoError(t, err)

	provider := &mockProvider{}
	opts = append([]ServiceOption{WithPAT(memStore, PATConfig{})}, opts...)
	service := NewService(memStore, memStore, issuer, []Provider{provider}, opts...)
	return service, memStore
}

// fakeClock is a manually advanced clock for WithClock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestService_Register(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	result, err := service.Register(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)

	assert.NotEmpty(t, result.UserID)
	assert.Equal(t, "test@example.com", result.Email)
	assert.NotEmpty(t, result.TokenPair.AccessToken)
	assert.NotEmpty(t, result.TokenPair.RefreshToken)
	assert.Greater(t, result.TokenPair.ExpiresIn, int64(0))
}

func TestService_Register_InvalidEmail(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	_, err := service.Register(ctx, "invalid-email", "SecurePassword123!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validate email")
}

func TestService_Register_ShortPassword(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	_, err := service.Register(ctx, "test@example.com", "short")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validate password")
}

func TestService_Login(t *testing.T) {
	service, memStore := setupTestService(t)
	ctx := context.Background()

	// Mock provider authenticates as user-123; Login loads the user for roles
	user := &entity.User{ID: "user-123", Email: "test@example.com"}
	require.NoError(t, memStore.Create(ctx, user))

	result, err := service.Login(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)

	assert.NotEmpty(t, result.UserID)
	assert.Equal(t, "test@example.com", result.Email)
	assert.NotEmpty(t, result.TokenPair.AccessToken)
	assert.NotEmpty(t, result.TokenPair.RefreshToken)
}

// secondProvider is a distinct Provider type for registry tests.
type secondProvider struct{ mockProvider }

func (secondProvider) Type() string { return entity.ProviderTypeWallet }

func TestService_ProviderRegistry(t *testing.T) {
	memStore := memory.New()
	issuer, err := token.New()
	require.NoError(t, err)

	local := &mockProvider{}
	wallet := &secondProvider{}
	service := NewService(memStore, memStore, issuer, []Provider{local, wallet})

	got, ok := service.provider(entity.ProviderTypeLocal)
	require.True(t, ok)
	assert.Same(t, local, got)

	got, ok = service.provider(entity.ProviderTypeWallet)
	require.True(t, ok)
	assert.Same(t, wallet, got)

	_, ok = service.provider(entity.ProviderTypeGoogle)
	assert.False(t, ok)
}

func TestService_DuplicateProviderPanics(t *testing.T) {
	memStore := memory.New()
	issuer, err := token.New()
	require.NoError(t, err)

	assert.Panics(t, func() {
		NewService(memStore, memStore, issuer, []Provider{&mockProvider{}, &mockProvider{}})
	})
}

func TestService_NoLocalProvider(t *testing.T) {
	memStore := memory.New()
	issuer, err := token.New()
	require.NoError(t, err)

	// Only a wallet provider registered — password paths are unconfigured.
	service := NewService(memStore, memStore, issuer, []Provider{&secondProvider{}})
	ctx := context.Background()

	_, err = service.Register(ctx, "test@example.com", "SecurePassword123!")
	assert.ErrorIs(t, err, ErrProviderNotConfigured)

	_, err = service.Login(ctx, "test@example.com", "SecurePassword123!")
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestService_RolesInTokens(t *testing.T) {
	service, memStore := setupTestService(t)
	ctx := context.Background()

	user := &entity.User{ID: "user-123", Email: "test@example.com", Roles: []string{"admin"}}
	require.NoError(t, memStore.Create(ctx, user))

	// Login embeds user roles into the access JWT
	result, err := service.Login(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)

	claims, err := service.Verify(ctx, result.TokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, claims.Roles)

	// Refresh preserves roles in the new access token
	refreshed, err := service.Refresh(ctx, result.TokenPair.RefreshToken)
	require.NoError(t, err)
	claims, err = service.Verify(ctx, refreshed.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, claims.Roles)

	// PAT verification returns the user's current roles
	pat, err := service.CreatePAT(ctx, user.ID, "ci", nil, nil)
	require.NoError(t, err)
	claims, err = service.Verify(ctx, pat.Plaintext)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, claims.Roles)
}

func TestService_Login_InvalidCredentials(t *testing.T) {
	memStore := memory.New()
	issuer, _ := token.New()

	provider := &mockProvider{
		authenticateFn: func(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error) {
			return nil, ErrInvalidCredentials
		},
	}

	service := NewService(memStore, memStore, issuer, []Provider{provider}, WithPAT(memStore, PATConfig{}))
	ctx := context.Background()

	_, err := service.Login(ctx, "test@example.com", "WrongPassword")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidCredentials))
}

func TestService_Refresh(t *testing.T) {
	service, memStore := setupTestService(t)
	ctx := context.Background()

	// Create user
	user := &entity.User{ID: "user-123", Email: "test@example.com"}
	require.NoError(t, memStore.Create(ctx, user))

	// Register to get tokens
	result, err := service.Register(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)

	// Refresh tokens
	newPair, err := service.Refresh(ctx, result.TokenPair.RefreshToken)
	require.NoError(t, err)

	assert.NotEmpty(t, newPair.AccessToken)
	assert.NotEmpty(t, newPair.RefreshToken)
	assert.NotEqual(t, result.TokenPair.RefreshToken, newPair.RefreshToken)
}

func TestService_Refresh_TokenReuse(t *testing.T) {
	clock := newFakeClock()
	service, memStore := setupTestService(t, WithClock(clock.Now))
	ctx := context.Background()

	// Create user
	user := &entity.User{ID: "user-123", Email: "test@example.com"}
	require.NoError(t, memStore.Create(ctx, user))

	// Register to get tokens
	result, err := service.Register(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)

	// First refresh - should succeed
	second, err := service.Refresh(ctx, result.TokenPair.RefreshToken)
	require.NoError(t, err)

	// Same token again once the leeway is over - should detect reuse
	clock.Advance(DefaultRefreshReuseLeeway + time.Second)
	_, err = service.Refresh(ctx, result.TokenPair.RefreshToken)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenReuse))

	// Verify error contains user_id
	var reuseErr *TokenReuseError
	require.True(t, errors.As(err, &reuseErr))
	assert.Equal(t, "user-123", reuseErr.UserID)

	// The whole family is revoked, including the legitimate successor
	_, err = service.Refresh(ctx, second.RefreshToken)
	assert.ErrorIs(t, err, ErrTokenReuse)
}

// registerForRefresh creates the mock provider's user and returns its first refresh token.
func registerForRefresh(t *testing.T, service *Service, memStore *memory.Store) string {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, memStore.Create(ctx, &entity.User{ID: "user-123", Email: "test@example.com"}))
	result, err := service.Register(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)
	return result.TokenPair.RefreshToken
}

func TestService_Refresh_ReuseLeeway(t *testing.T) {
	ctx := context.Background()

	t.Run("duplicate within leeway gets a pair and keeps the family", func(t *testing.T) {
		clock := newFakeClock()
		service, memStore := setupTestService(t, WithClock(clock.Now))
		r1 := registerForRefresh(t, service, memStore)

		first, err := service.Refresh(ctx, r1)
		require.NoError(t, err)
		clock.Advance(DefaultRefreshReuseLeeway)
		dup, err := service.Refresh(ctx, r1)
		require.NoError(t, err)
		assert.NotEqual(t, first.RefreshToken, dup.RefreshToken)

		// Both successors are live members of the same family
		_, err = service.Refresh(ctx, dup.RefreshToken)
		require.NoError(t, err)
		_, err = service.Refresh(ctx, first.RefreshToken)
		require.NoError(t, err)
	})

	t.Run("strict mode treats an immediate duplicate as reuse", func(t *testing.T) {
		service, memStore := setupTestService(t, WithRefreshReuseLeeway(0))
		r1 := registerForRefresh(t, service, memStore)

		_, err := service.Refresh(ctx, r1)
		require.NoError(t, err)
		_, err = service.Refresh(ctx, r1)
		assert.ErrorIs(t, err, ErrTokenReuse)
	})

	t.Run("older generation is reuse even within leeway", func(t *testing.T) {
		clock := newFakeClock()
		service, memStore := setupTestService(t, WithClock(clock.Now))
		r1 := registerForRefresh(t, service, memStore)

		r2, err := service.Refresh(ctx, r1)
		require.NoError(t, err)
		// Distinct stamps: equal ones count r1 as the latest rotation too.
		clock.Advance(time.Second)
		r3, err := service.Refresh(ctx, r2.RefreshToken)
		require.NoError(t, err)

		// The client has moved on to r3, so r1 cannot be a duplicate
		_, err = service.Refresh(ctx, r1)
		require.ErrorIs(t, err, ErrTokenReuse)
		_, err = service.Refresh(ctx, r3.RefreshToken)
		assert.ErrorIs(t, err, ErrTokenReuse, "family must be revoked")
	})

	t.Run("no grace after logout", func(t *testing.T) {
		service, memStore := setupTestService(t)
		r1 := registerForRefresh(t, service, memStore)

		r2, err := service.Refresh(ctx, r1)
		require.NoError(t, err)
		require.NoError(t, service.Logout(ctx, r2.RefreshToken))

		_, err = service.Refresh(ctx, r1)
		assert.ErrorIs(t, err, ErrTokenReuse)
	})

	t.Run("logout ends siblings minted within leeway", func(t *testing.T) {
		service, memStore := setupTestService(t)
		r1 := registerForRefresh(t, service, memStore)

		tabA, err := service.Refresh(ctx, r1)
		require.NoError(t, err)
		tabB, err := service.Refresh(ctx, r1)
		require.NoError(t, err)

		require.NoError(t, service.Logout(ctx, tabA.RefreshToken))
		_, err = service.Refresh(ctx, tabB.RefreshToken)
		assert.ErrorIs(t, err, ErrTokenReuse)
	})

	t.Run("replay from a lagging clock beyond leeway is reuse", func(t *testing.T) {
		clock := newFakeClock()
		service, memStore := setupTestService(t, WithClock(clock.Now))
		r1 := registerForRefresh(t, service, memStore)

		// The rotating replica was ahead by more than the leeway.
		clock.Advance(DefaultRefreshReuseLeeway + time.Second)
		_, err := service.Refresh(ctx, r1)
		require.NoError(t, err)
		clock.Advance(-(DefaultRefreshReuseLeeway + time.Second) * 2)

		_, err = service.Refresh(ctx, r1)
		assert.ErrorIs(t, err, ErrTokenReuse)
	})

	t.Run("logged out token is reuse without grace", func(t *testing.T) {
		service, memStore := setupTestService(t)
		r1 := registerForRefresh(t, service, memStore)

		require.NoError(t, service.Logout(ctx, r1))
		_, err := service.Refresh(ctx, r1)
		assert.ErrorIs(t, err, ErrTokenReuse)
	})

	t.Run("expired token", func(t *testing.T) {
		clock := newFakeClock()
		service, memStore := setupTestService(t, WithClock(clock.Now))
		r1 := registerForRefresh(t, service, memStore)

		clock.Advance(token.RefreshTokenTTL)
		_, err := service.Refresh(ctx, r1)
		assert.ErrorIs(t, err, ErrTokenExpired)
	})
}

// logoutBeforeSave ends the session right before the successor token is
// saved: the interleaving the SaveRefreshToken root check exists for.
type logoutBeforeSave struct {
	*memory.Store
	root      string
	successor string // hash of the token offered for saving after the logout
}

func (s *logoutBeforeSave) SaveRefreshToken(ctx context.Context, rt *entity.RefreshToken) error {
	if s.root != "" && rt.Parent == s.root {
		if err := s.RevokeTokens(ctx, s.root); err != nil {
			return err
		}
		s.successor = rt.Hash
	}
	return s.Store.SaveRefreshToken(ctx, rt)
}

func TestService_Refresh_SessionEndsBeforeSave(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	issuer, err := token.New()
	require.NoError(t, err)
	racy := &logoutBeforeSave{Store: memStore}
	service := NewService(racy, memStore, issuer, []Provider{&mockProvider{}})

	r1 := registerForRefresh(t, service, memStore)
	racy.root = token.HashToken(r1)

	_, err = service.Refresh(ctx, r1)
	require.ErrorIs(t, err, ErrTokenReuse)

	// The successor offered after the logout must not join the ended session.
	require.NotEmpty(t, racy.successor)
	_, err = memStore.GetRefreshToken(ctx, racy.successor)
	assert.ErrorIs(t, err, store.ErrTokenNotFound)
}

func TestService_Refresh_Concurrent(t *testing.T) {
	const n = 10
	ctx := context.Background()

	run := func(t *testing.T, service *Service, r1 string) (winners []string, reuse int) {
		t.Helper()
		errs := make([]error, n)
		pairs := make([]*entity.TokenPair, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				pairs[i], errs[i] = service.Refresh(ctx, r1)
			})
		}
		wg.Wait()
		for i, err := range errs {
			switch {
			case err == nil:
				winners = append(winners, pairs[i].RefreshToken)
			case errors.Is(err, ErrTokenReuse):
				reuse++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		return winners, reuse
	}

	t.Run("leeway absorbs duplicates", func(t *testing.T) {
		service, memStore := setupTestService(t)
		winners, _ := run(t, service, registerForRefresh(t, service, memStore))
		assert.Len(t, winners, n)
	})

	t.Run("strict: concurrent replays end the session", func(t *testing.T) {
		service, memStore := setupTestService(t, WithRefreshReuseLeeway(0))
		r1 := registerForRefresh(t, service, memStore)
		winners, reuse := run(t, service, r1)

		// One rotation wins; its pair is handed out only if its successor is
		// saved before a loser ends the session (otherwise SaveRefreshToken
		// refuses it). Either way the session ends and nothing issued stays usable.
		assert.LessOrEqual(t, len(winners), 1)
		assert.Equal(t, n, len(winners)+reuse)
		family, err := memStore.GetRefreshFamily(ctx, token.HashToken(r1))
		require.NoError(t, err)
		assert.True(t, family.SessionEnded)
		for _, rt := range winners {
			_, err := service.Refresh(ctx, rt)
			assert.ErrorIs(t, err, ErrTokenReuse)
		}
	})
}

func TestService_Refresh_NotFound(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	_, err := service.Refresh(ctx, "nonexistent-token")
	assert.ErrorIs(t, err, store.ErrTokenNotFound)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestService_Logout(t *testing.T) {
	service, memStore := setupTestService(t)
	ctx := context.Background()

	// Create user
	user := &entity.User{ID: "user-123", Email: "test@example.com"}
	require.NoError(t, memStore.Create(ctx, user))

	// Register to get tokens
	result, err := service.Register(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)

	// Logout
	err = service.Logout(ctx, result.TokenPair.RefreshToken)
	require.NoError(t, err)

	// Try to refresh - should fail (token revoked triggers reuse detection)
	_, err = service.Refresh(ctx, result.TokenPair.RefreshToken)
	assert.Error(t, err)
}

func TestService_Verify(t *testing.T) {
	service, memStore := setupTestService(t)
	ctx := context.Background()

	// Create user
	user := &entity.User{ID: "user-123", Email: "test@example.com"}
	require.NoError(t, memStore.Create(ctx, user))

	// Register to get tokens
	result, err := service.Register(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)

	// Verify access token
	claims, err := service.Verify(ctx, result.TokenPair.AccessToken)
	require.NoError(t, err)

	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
}

func TestService_Verify_InvalidToken(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	_, err := service.Verify(ctx, "invalid-token")
	assert.Error(t, err)
}

func TestService_JWKS(t *testing.T) {
	service, _ := setupTestService(t)

	jwks := service.JWKS()
	assert.NotNil(t, jwks)
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "psina-key-1", jwks.Keys[0].KeyID)
}
