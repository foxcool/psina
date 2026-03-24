package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/pkg/api/auth/v1"
	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/store/memory"
	"github.com/foxcool/psina/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMemStore creates a new in-memory store for testing.
func newMemStore(t *testing.T) *memory.Store {
	t.Helper()
	return memory.New()
}

// newServiceWithProvider creates a service with a custom provider and store.
func newServiceWithProvider(t *testing.T, provider Provider, store *memory.Store) *Service {
	t.Helper()
	issuer, err := token.New()
	require.NoError(t, err)
	return NewService(provider, store, store, issuer)
}

// registerUser registers a user via the handler and pre-creates the user in the store.
// The mock provider always returns "user-123" as UserID, so this pre-creates that user.
func registerUser(t *testing.T, store *memory.Store, email, password string, svc *Service) *RegisterResult {
	t.Helper()
	ctx := context.Background()
	// Pre-create user so Refresh (which does GetByID) can find them
	_ = store.Create(ctx, &entity.User{ID: "user-123", Email: email})
	result, err := svc.Register(ctx, email, password)
	require.NoError(t, err)
	return result
}

func setupTestHandler(t *testing.T) (*Handler, *Service, *memory.Store) {
	t.Helper()
	service, store := setupTestService(t)
	handler := NewHandler(service)
	return handler, service, store
}

func setupCookieHandler(t *testing.T) (*Handler, *Service, *memory.Store) {
	t.Helper()
	service, store := setupTestService(t)
	handler := NewHandler(service, WithCookieConfig(&CookieConfig{
		Enabled:  true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}))
	return handler, service, store
}

// hasCookie checks if a Set-Cookie header contains a cookie with the given name.
func hasCookie(header http.Header, name string) bool {
	for _, v := range header.Values("Set-Cookie") {
		req := http.Request{Header: http.Header{"Cookie": []string{v}}}
		cookies := req.Cookies()
		for _, c := range cookies {
			if c.Name == name {
				return true
			}
		}
		// Parse the Set-Cookie header directly
		if c := parseCookieName(v); c == name {
			return true
		}
	}
	return false
}

// parseCookieName extracts the cookie name from a Set-Cookie header value.
func parseCookieName(setCookie string) string {
	resp := http.Response{Header: http.Header{"Set-Cookie": []string{setCookie}}}
	cookies := resp.Cookies()
	if len(cookies) > 0 {
		return cookies[0].Name
	}
	return ""
}

// cookieMaxAge extracts MaxAge from a Set-Cookie header for a given cookie name.
func cookieMaxAge(header http.Header, name string) (int, bool) {
	for _, v := range header.Values("Set-Cookie") {
		resp := http.Response{Header: http.Header{"Set-Cookie": []string{v}}}
		cookies := resp.Cookies()
		for _, c := range cookies {
			if c.Name == name {
				return c.MaxAge, true
			}
		}
	}
	return 0, false
}

// TestHandler_Register tests the Register RPC handler.
func TestHandler_Register(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		req := connect.NewRequest(&authv1.RegisterRequest{
			Email:    "test@example.com",
			Password: "SecurePassword123!",
		})
		resp, err := handler.Register(context.Background(), req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Msg.UserId)
		assert.Equal(t, "test@example.com", resp.Msg.Email)
		assert.NotEmpty(t, resp.Msg.AccessToken)
		assert.NotEmpty(t, resp.Msg.RefreshToken)
		assert.Greater(t, resp.Msg.ExpiresIn, int64(0))
		assert.Empty(t, resp.Header().Values("Set-Cookie"))
	})

	t.Run("success with cookie", func(t *testing.T) {
		handler, _, _ := setupCookieHandler(t)
		req := connect.NewRequest(&authv1.RegisterRequest{
			Email:    "cookie@example.com",
			Password: "SecurePassword123!",
		})
		resp, err := handler.Register(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, hasCookie(resp.Header(), AccessTokenCookie))
		assert.True(t, hasCookie(resp.Header(), RefreshTokenCookie))
	})

	t.Run("duplicate email", func(t *testing.T) {
		callCount := 0
		dupMock := &mockProvider{
			registerFn: func(_ context.Context, req *entity.RegisterRequest) (*entity.Identity, error) {
				callCount++
				if callCount > 1 {
					return nil, ErrUserExists
				}
				return &entity.Identity{UserID: "user-123", Email: req.Email, Provider: "mock"}, nil
			},
		}
		store := newMemStore(t)
		svc := newServiceWithProvider(t, dupMock, store)
		handler := NewHandler(svc)
		ctx := context.Background()

		req := connect.NewRequest(&authv1.RegisterRequest{
			Email:    "dup@example.com",
			Password: "SecurePassword123!",
		})
		_, err := handler.Register(ctx, req)
		require.NoError(t, err)

		_, err = handler.Register(ctx, req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeAlreadyExists, connectErr.Code())
	})

	t.Run("invalid email", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		req := connect.NewRequest(&authv1.RegisterRequest{
			Email:    "not-an-email",
			Password: "SecurePassword123!",
		})
		_, err := handler.Register(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
	})

	t.Run("short password", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		req := connect.NewRequest(&authv1.RegisterRequest{
			Email:    "test@example.com",
			Password: "short",
		})
		_, err := handler.Register(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
	})

	t.Run("long password", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		longPass := ""
		for range 129 {
			longPass += "a"
		}
		req := connect.NewRequest(&authv1.RegisterRequest{
			Email:    "test@example.com",
			Password: longPass,
		})
		_, err := handler.Register(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
	})
}

// TestHandler_Login tests the Login RPC handler.
func TestHandler_Login(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler, service, _ := setupTestHandler(t)
		ctx := context.Background()

		_, err := service.Register(ctx, "login@example.com", "SecurePassword123!")
		require.NoError(t, err)

		req := connect.NewRequest(&authv1.LoginRequest{
			Email:    "login@example.com",
			Password: "SecurePassword123!",
		})
		resp, err := handler.Login(ctx, req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Msg.AccessToken)
		assert.NotEmpty(t, resp.Msg.RefreshToken)
		assert.Empty(t, resp.Header().Values("Set-Cookie"))
	})

	t.Run("success with cookie", func(t *testing.T) {
		handler, service, _ := setupCookieHandler(t)
		ctx := context.Background()

		_, err := service.Register(ctx, "cookielogin@example.com", "SecurePassword123!")
		require.NoError(t, err)

		req := connect.NewRequest(&authv1.LoginRequest{
			Email:    "cookielogin@example.com",
			Password: "SecurePassword123!",
		})
		resp, err := handler.Login(ctx, req)
		require.NoError(t, err)
		assert.True(t, hasCookie(resp.Header(), AccessTokenCookie))
		assert.True(t, hasCookie(resp.Header(), RefreshTokenCookie))
	})

	t.Run("invalid credentials", func(t *testing.T) {
		memStore := newMemStore(t)
		failingMock := &mockProvider{
			authenticateFn: func(_ context.Context, _ *entity.AuthRequest) (*entity.Identity, error) {
				return nil, ErrInvalidCredentials
			},
		}
		svc := newServiceWithProvider(t, failingMock, memStore)
		handler := NewHandler(svc)
		req := connect.NewRequest(&authv1.LoginRequest{
			Email:    "user@example.com",
			Password: "WrongPassword!",
		})
		_, err := handler.Login(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
	})
}

// TestHandler_Refresh tests the Refresh RPC handler.
func TestHandler_Refresh(t *testing.T) {
	t.Run("token in body", func(t *testing.T) {
		handler, service, store := setupTestHandler(t)
		result := registerUser(t, store, "refresh@example.com", "SecurePassword123!", service)

		req := connect.NewRequest(&authv1.RefreshRequest{
			RefreshToken: result.TokenPair.RefreshToken,
		})
		resp, err := handler.Refresh(context.Background(), req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Msg.AccessToken)
		assert.NotEmpty(t, resp.Msg.RefreshToken)
	})

	t.Run("token in cookie when enabled", func(t *testing.T) {
		handler, service, store := setupCookieHandler(t)
		result := registerUser(t, store, "refreshcookie@example.com", "SecurePassword123!", service)

		req := connect.NewRequest(&authv1.RefreshRequest{})
		req.Header().Set("Cookie", fmt.Sprintf("%s=%s", RefreshTokenCookie, result.TokenPair.RefreshToken))

		resp, err := handler.Refresh(context.Background(), req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Msg.AccessToken)
	})

	t.Run("no token cookie disabled", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		req := connect.NewRequest(&authv1.RefreshRequest{})
		_, err := handler.Refresh(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
	})

	t.Run("no token cookie enabled", func(t *testing.T) {
		handler, _, _ := setupCookieHandler(t)
		req := connect.NewRequest(&authv1.RefreshRequest{})
		_, err := handler.Refresh(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
	})

	t.Run("token reuse", func(t *testing.T) {
		handler, service, store := setupTestHandler(t)
		result := registerUser(t, store, "reuse@example.com", "SecurePassword123!", service)

		ctx := context.Background()

		// First refresh succeeds
		req := connect.NewRequest(&authv1.RefreshRequest{
			RefreshToken: result.TokenPair.RefreshToken,
		})
		_, err := handler.Refresh(ctx, req)
		require.NoError(t, err)

		// Second refresh with same token fails
		req2 := connect.NewRequest(&authv1.RefreshRequest{
			RefreshToken: result.TokenPair.RefreshToken,
		})
		_, err = handler.Refresh(ctx, req2)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
	})
}

// TestHandler_Logout tests the Logout RPC handler.
func TestHandler_Logout(t *testing.T) {
	t.Run("token in body", func(t *testing.T) {
		handler, service, _ := setupTestHandler(t)
		ctx := context.Background()

		result, err := service.Register(ctx, "logout@example.com", "SecurePassword123!")
		require.NoError(t, err)

		req := connect.NewRequest(&authv1.LogoutRequest{
			RefreshToken: result.TokenPair.RefreshToken,
		})
		resp, err := handler.Logout(ctx, req)
		require.NoError(t, err)
		assert.True(t, resp.Msg.Success)
	})

	t.Run("token in cookie when enabled", func(t *testing.T) {
		handler, service, _ := setupCookieHandler(t)
		ctx := context.Background()

		result, err := service.Register(ctx, "logoutcookie@example.com", "SecurePassword123!")
		require.NoError(t, err)

		req := connect.NewRequest(&authv1.LogoutRequest{})
		req.Header().Set("Cookie", fmt.Sprintf("%s=%s", RefreshTokenCookie, result.TokenPair.RefreshToken))

		resp, err := handler.Logout(ctx, req)
		require.NoError(t, err)
		assert.True(t, resp.Msg.Success)
	})

	t.Run("no token always succeeds", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		req := connect.NewRequest(&authv1.LogoutRequest{})
		resp, err := handler.Logout(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, resp.Msg.Success)
	})

	t.Run("clears cookies when enabled", func(t *testing.T) {
		handler, service, _ := setupCookieHandler(t)
		ctx := context.Background()

		result, err := service.Register(ctx, "logoutclear@example.com", "SecurePassword123!")
		require.NoError(t, err)

		req := connect.NewRequest(&authv1.LogoutRequest{
			RefreshToken: result.TokenPair.RefreshToken,
		})
		resp, err := handler.Logout(ctx, req)
		require.NoError(t, err)

		maxAge, found := cookieMaxAge(resp.Header(), AccessTokenCookie)
		assert.True(t, found)
		assert.Equal(t, -1, maxAge)

		maxAge, found = cookieMaxAge(resp.Header(), RefreshTokenCookie)
		assert.True(t, found)
		assert.Equal(t, -1, maxAge)
	})
}

// TestHandler_Verify tests the Verify RPC handler.
func TestHandler_Verify(t *testing.T) {
	t.Run("valid bearer token", func(t *testing.T) {
		handler, service, _ := setupTestHandler(t)
		ctx := context.Background()

		result, err := service.Register(ctx, "verify@example.com", "SecurePassword123!")
		require.NoError(t, err)

		req := connect.NewRequest(&authv1.VerifyRequest{})
		req.Header().Set("Authorization", "Bearer "+result.TokenPair.AccessToken)

		resp, err := handler.Verify(ctx, req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Msg.UserId)
		assert.Equal(t, "verify@example.com", resp.Msg.Email)
		assert.Equal(t, resp.Msg.UserId, resp.Header().Get("X-User-Id"))
		assert.Equal(t, resp.Msg.Email, resp.Header().Get("X-User-Email"))
	})

	t.Run("token from cookie when enabled", func(t *testing.T) {
		handler, service, _ := setupCookieHandler(t)
		ctx := context.Background()

		result, err := service.Register(ctx, "verifycookie@example.com", "SecurePassword123!")
		require.NoError(t, err)

		req := connect.NewRequest(&authv1.VerifyRequest{})
		req.Header().Set("Cookie", fmt.Sprintf("%s=%s", AccessTokenCookie, result.TokenPair.AccessToken))

		resp, err := handler.Verify(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, "verifycookie@example.com", resp.Msg.Email)
	})

	t.Run("no token", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		req := connect.NewRequest(&authv1.VerifyRequest{})
		_, err := handler.Verify(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
	})

	t.Run("invalid authorization format", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		req := connect.NewRequest(&authv1.VerifyRequest{})
		req.Header().Set("Authorization", "InvalidFormat token123")
		_, err := handler.Verify(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
	})

	t.Run("invalid token", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)
		req := connect.NewRequest(&authv1.VerifyRequest{})
		req.Header().Set("Authorization", "Bearer invalid.token.here")
		_, err := handler.Verify(context.Background(), req)
		require.Error(t, err)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
	})
}

// TestGetClientIP tests IP extraction from headers.
func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected string
	}{
		{
			name:     "X-Forwarded-For single IP",
			headers:  http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
			expected: "1.2.3.4",
		},
		{
			name:     "X-Forwarded-For multiple IPs",
			headers:  http.Header{"X-Forwarded-For": []string{"1.2.3.4, 5.6.7.8"}},
			expected: "1.2.3.4",
		},
		{
			name:     "X-Real-IP",
			headers:  http.Header{"X-Real-Ip": []string{"9.0.0.1"}},
			expected: "9.0.0.1",
		},
		{
			name:     "no headers",
			headers:  http.Header{},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getClientIP(tt.headers)
			assert.Equal(t, tt.expected, result)
		})
	}
}
