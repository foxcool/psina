package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/store"
	"github.com/foxcool/psina/pkg/store/memory"
	"github.com/foxcool/psina/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider implements Provider for testing.
type mockProvider struct {
	registerFn     func(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error)
	authenticateFn func(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error)
}

func (m *mockProvider) Type() string { return "mock" }

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

func setupTestService(t *testing.T) (*Service, *memory.Store) {
	t.Helper()
	memStore := memory.New()
	issuer, err := token.New()
	require.NoError(t, err)

	provider := &mockProvider{}
	service := NewService(provider, memStore, memStore, issuer, WithPAT(memStore, PATConfig{}))
	return service, memStore
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
			return nil, errors.New("invalid credentials")
		},
	}

	service := NewService(provider, memStore, memStore, issuer, WithPAT(memStore, PATConfig{}))
	ctx := context.Background()

	_, err := service.Login(ctx, "test@example.com", "WrongPassword")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidCredentials))
}

func TestService_AdminEmails(t *testing.T) {
	newAdminService := func(t *testing.T, entries []string) (*Service, *memory.Store) {
		t.Helper()
		memStore := memory.New()
		issuer, err := token.New()
		require.NoError(t, err)
		service := NewService(&mockProvider{}, memStore, memStore, issuer,
			WithPAT(memStore, PATConfig{}), WithAdminEmails(entries))
		return service, memStore
	}

	login := func(t *testing.T, service *Service, memStore *memory.Store, email string, roles []string) *entity.Claims {
		t.Helper()
		ctx := context.Background()
		user := &entity.User{ID: "user-123", Email: email, Roles: roles}
		require.NoError(t, memStore.Create(ctx, user))
		result, err := service.Login(ctx, email, "SecurePassword123!")
		require.NoError(t, err)
		claims, err := service.Verify(ctx, result.TokenPair.AccessToken)
		require.NoError(t, err)
		return claims
	}

	t.Run("exact email match", func(t *testing.T) {
		service, memStore := newAdminService(t, []string{"boss@example.com"})
		claims := login(t, service, memStore, "boss@example.com", nil)
		assert.Equal(t, []string{AdminRole}, claims.Roles)
	})

	t.Run("domain match", func(t *testing.T) {
		service, memStore := newAdminService(t, []string{"@example.com"})
		claims := login(t, service, memStore, "anyone@example.com", []string{"support"})
		assert.Equal(t, []string{"support", AdminRole}, claims.Roles)
	})

	t.Run("domain match is anchored at @", func(t *testing.T) {
		service, memStore := newAdminService(t, []string{"@example.com"})
		claims := login(t, service, memStore, "user@sub.example.com", nil)
		assert.Empty(t, claims.Roles)
	})

	t.Run("case-insensitive", func(t *testing.T) {
		service, memStore := newAdminService(t, []string{"Boss@Example.COM"})
		claims := login(t, service, memStore, "boss@example.com", nil)
		assert.Equal(t, []string{AdminRole}, claims.Roles)
	})

	t.Run("no duplicate when role already present", func(t *testing.T) {
		service, memStore := newAdminService(t, []string{"boss@example.com"})
		claims := login(t, service, memStore, "boss@example.com", []string{AdminRole})
		assert.Equal(t, []string{AdminRole}, claims.Roles)
	})

	t.Run("non-matching email gets nothing", func(t *testing.T) {
		service, memStore := newAdminService(t, []string{"boss@example.com", "@corp.example"})
		claims := login(t, service, memStore, "user@example.com", nil)
		assert.Empty(t, claims.Roles)
	})

	t.Run("PAT verification merges admin", func(t *testing.T) {
		service, memStore := newAdminService(t, []string{"@example.com"})
		ctx := context.Background()
		user := &entity.User{ID: "user-123", Email: "boss@example.com"}
		require.NoError(t, memStore.Create(ctx, user))

		pat, err := service.CreatePAT(ctx, user.ID, "ci", nil, nil)
		require.NoError(t, err)
		claims, err := service.Verify(ctx, pat.Plaintext)
		require.NoError(t, err)
		assert.Equal(t, []string{AdminRole}, claims.Roles)
	})

	t.Run("refresh keeps admin role", func(t *testing.T) {
		service, memStore := newAdminService(t, []string{"boss@example.com"})
		ctx := context.Background()
		user := &entity.User{ID: "user-123", Email: "boss@example.com"}
		require.NoError(t, memStore.Create(ctx, user))
		result, err := service.Login(ctx, "boss@example.com", "SecurePassword123!")
		require.NoError(t, err)

		refreshed, err := service.Refresh(ctx, result.TokenPair.RefreshToken)
		require.NoError(t, err)
		claims, err := service.Verify(ctx, refreshed.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, []string{AdminRole}, claims.Roles)
	})
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
	service, memStore := setupTestService(t)
	ctx := context.Background()

	// Create user
	user := &entity.User{ID: "user-123", Email: "test@example.com"}
	require.NoError(t, memStore.Create(ctx, user))

	// Register to get tokens
	result, err := service.Register(ctx, "test@example.com", "SecurePassword123!")
	require.NoError(t, err)

	// First refresh - should succeed
	_, err = service.Refresh(ctx, result.TokenPair.RefreshToken)
	require.NoError(t, err)

	// Second refresh with same token - should detect reuse
	_, err = service.Refresh(ctx, result.TokenPair.RefreshToken)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenReuse))

	// Verify error contains user_id
	var reuseErr *TokenReuseError
	assert.True(t, errors.As(err, &reuseErr))
	assert.Equal(t, "user-123", reuseErr.UserID)
}

func TestService_Refresh_NotFound(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	_, err := service.Refresh(ctx, "nonexistent-token")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrTokenNotFound))
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
