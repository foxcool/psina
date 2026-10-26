package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/api/auth/v1"
	"github.com/foxcool/psina/entity"
	psinastore "github.com/foxcool/psina/store"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/token"
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
	return NewService(store, store, issuer, []Provider{provider}, WithPAT(store, PATConfig{}))
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

func setupCookieHandlerWithDomain(t *testing.T, domain string) (*Handler, *Service, *memory.Store) {
	t.Helper()
	service, store := setupTestService(t)
	handler := NewHandler(service, WithCookieConfig(&CookieConfig{
		Enabled:  true,
		Domain:   domain,
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

// setCookiesByName parses every Set-Cookie header and groups the parsed cookies
// by name, preserving order. A single name may map to several entries (e.g. a
// Domain-scoped set plus a host-only eviction).
func setCookiesByName(header http.Header, name string) []*http.Cookie {
	var out []*http.Cookie
	for _, v := range header.Values("Set-Cookie") {
		resp := http.Response{Header: http.Header{"Set-Cookie": []string{v}}}
		for _, c := range resp.Cookies() {
			if c.Name == name {
				out = append(out, c)
			}
		}
	}
	return out
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
					// What the real local provider returns, not the service sentinel.
					return nil, fmt.Errorf("%w: %s", psinastore.ErrUserExists, req.Email)
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
		handler, service, store := setupTestHandler(t)
		ctx := context.Background()

		registerUser(t, store, "login@example.com", "SecurePassword123!", service)

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
		handler, service, store := setupCookieHandler(t)
		ctx := context.Background()

		registerUser(t, store, "cookielogin@example.com", "SecurePassword123!", service)

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
		service, store := setupTestService(t, WithRefreshReuseLeeway(0))
		handler := NewHandler(service)
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
		// No roles — no header
		assert.Empty(t, resp.Msg.Roles)
		assert.Empty(t, resp.Header().Values("X-User-Roles"))
	})

	t.Run("roles in response and header", func(t *testing.T) {
		handler, service, store := setupTestHandler(t)
		ctx := context.Background()

		user := &entity.User{ID: "user-123", Email: "roles@example.com", Roles: []string{"admin", "support"}}
		require.NoError(t, store.Create(ctx, user))

		result, err := service.Login(ctx, "roles@example.com", "SecurePassword123!")
		require.NoError(t, err)

		req := connect.NewRequest(&authv1.VerifyRequest{})
		req.Header().Set("Authorization", "Bearer "+result.TokenPair.AccessToken)

		resp, err := handler.Verify(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, []string{"admin", "support"}, resp.Msg.Roles)
		assert.Equal(t, "admin,support", resp.Header().Get("X-User-Roles"))
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

// errStorage stands in for a driver error whose text must not reach clients.
var errStorage = errors.New("pgx: connection refused")

// brokenStore fails storage calls with errStorage: RotateRefreshToken
// (Refresh), GetRefreshToken (Logout), GetPAT (PAT verify), ListPATs (list and
// create PAT) and DeletePAT (revoke PAT). Everything else is the memory store.
type brokenStore struct{ *memory.Store }

func (brokenStore) GetRefreshToken(context.Context, string) (*entity.RefreshToken, error) {
	return nil, errStorage
}

func (brokenStore) ListPATs(context.Context, string) ([]*entity.PersonalAccessToken, error) {
	return nil, errStorage
}

func (brokenStore) DeletePAT(context.Context, string, string) error {
	return errStorage
}

func (brokenStore) RotateRefreshToken(context.Context, string, time.Time) (*entity.RefreshToken, error) {
	return nil, errStorage
}

func (brokenStore) GetPAT(context.Context, string) (*entity.PersonalAccessToken, error) {
	return nil, errStorage
}

// TestHandler_StorageFailureIsInternal checks that a storage outage is not
// reported as a rejected credential: a 401 would log clients out on a DB blip.
func TestHandler_StorageFailureIsInternal(t *testing.T) {
	broken := brokenStore{Store: memory.New()}
	issuer, err := token.New()
	require.NoError(t, err)
	provider := &mockProvider{
		authenticateFn: func(context.Context, *entity.AuthRequest) (*entity.Identity, error) {
			return nil, fmt.Errorf("get user: %w", errStorage)
		},
		registerFn: func(context.Context, *entity.RegisterRequest) (*entity.Identity, error) {
			return nil, fmt.Errorf("create user: %w", errStorage)
		},
	}
	handler := NewHandler(NewService(broken, broken, issuer, []Provider{provider}, WithPAT(broken, PATConfig{})))
	ctx := context.Background()

	// A session JWT needs no store, so the PAT RPCs get past authentication.
	session, _, err := issuer.GenerateTokens("user-123", "down@example.com", nil)
	require.NoError(t, err)
	withSession := func(header http.Header) { header.Set("Authorization", "Bearer "+session.AccessToken) }

	tests := []struct {
		name string
		call func() error
	}{
		{"login", func() error {
			_, err := handler.Login(ctx, connect.NewRequest(&authv1.LoginRequest{
				Email: "down@example.com", Password: "SecurePassword123!",
			}))
			return err
		}},
		{"refresh", func() error {
			_, err := handler.Refresh(ctx, connect.NewRequest(&authv1.RefreshRequest{RefreshToken: "some-token"}))
			return err
		}},
		{"verify pat", func() error {
			req := connect.NewRequest(&authv1.VerifyRequest{})
			req.Header().Set("Authorization", "Bearer "+token.PATPrefix+"whatever")
			_, err := handler.Verify(ctx, req)
			return err
		}},
		{"register", func() error {
			_, err := handler.Register(ctx, connect.NewRequest(&authv1.RegisterRequest{
				Email: "down@example.com", Password: "SecurePassword123!",
			}))
			return err
		}},
		{"logout", func() error {
			_, err := handler.Logout(ctx, connect.NewRequest(&authv1.LogoutRequest{RefreshToken: "some-token"}))
			return err
		}},
		{"create pat", func() error {
			req := connect.NewRequest(&authv1.CreatePersonalAccessTokenRequest{Name: "ci"})
			withSession(req.Header())
			_, err := handler.CreatePersonalAccessToken(ctx, req)
			return err
		}},
		{"list pats", func() error {
			req := connect.NewRequest(&authv1.ListPersonalAccessTokensRequest{})
			withSession(req.Header())
			_, err := handler.ListPersonalAccessTokens(ctx, req)
			return err
		}},
		{"revoke pat", func() error {
			req := connect.NewRequest(&authv1.RevokePersonalAccessTokenRequest{Id: "0192d3a4-0000-7000-8000-000000000000"})
			withSession(req.Header())
			_, err := handler.RevokePersonalAccessToken(ctx, req)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var connectErr *connect.Error
			require.ErrorAs(t, tc.call(), &connectErr)
			assert.Equal(t, connect.CodeInternal, connectErr.Code())
			assert.NotContains(t, connectErr.Message(), "pgx")
		})
	}
}

// TestHandler_RejectedCredentialIsUnauthenticated pins the 401 side of the
// split: rejected credentials keep reporting Unauthenticated.
func TestHandler_RejectedCredentialIsUnauthenticated(t *testing.T) {
	handler, _, _ := setupTestHandler(t)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"refresh unknown token", func() error {
			_, err := handler.Refresh(ctx, connect.NewRequest(&authv1.RefreshRequest{RefreshToken: "unknown-token"}))
			return err
		}},
		{"verify unknown pat", func() error {
			req := connect.NewRequest(&authv1.VerifyRequest{})
			req.Header().Set("Authorization", "Bearer "+token.PATPrefix+"unknown")
			_, err := handler.Verify(ctx, req)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var connectErr *connect.Error
			require.ErrorAs(t, tc.call(), &connectErr)
			assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
		})
	}
}

// TestHandler_LegacyScopedCookieEviction covers the stale-cookie bug: when a
// Domain is configured, login/logout must also expire any legacy duplicate left
// under a foreign scope — the host-only scope (Domain unset) or a broader parent
// domain — so the browser stops sending a stale token that the Domain-scoped
// Set-Cookie can never overwrite. A parent-domain duplicate is the case that
// host-only-only eviction missed.
func TestHandler_LegacyScopedCookieEviction(t *testing.T) {
	const domain = "app.example.com"
	const parent = "example.com"

	t.Run("login sets domain cookie and evicts host-only + parent duplicates", func(t *testing.T) {
		handler, service, store := setupCookieHandlerWithDomain(t, domain)
		ctx := context.Background()
		registerUser(t, store, "evict-login@example.com", "SecurePassword123!", service)

		req := connect.NewRequest(&authv1.LoginRequest{
			Email:    "evict-login@example.com",
			Password: "SecurePassword123!",
		})
		resp, err := handler.Login(ctx, req)
		require.NoError(t, err)

		for _, name := range []string{AccessTokenCookie, RefreshTokenCookie} {
			cookies := setCookiesByName(resp.Header(), name)
			require.Len(t, cookies, 3, "%s: expected a Domain-scoped set + host-only + parent eviction", name)

			byScope := map[string]*http.Cookie{}
			for _, c := range cookies {
				byScope[c.Domain] = c
			}
			require.Contains(t, byScope, domain, "%s: missing Domain-scoped cookie", name)
			require.Contains(t, byScope, "", "%s: missing host-only eviction", name)
			require.Contains(t, byScope, parent, "%s: missing parent-domain eviction", name)

			assert.NotEmpty(t, byScope[domain].Value, "%s: Domain-scoped cookie must carry the token", name)
			assert.Greater(t, byScope[domain].MaxAge, 0, "%s: Domain-scoped cookie must live", name)

			for _, scope := range []string{"", parent} {
				assert.Empty(t, byScope[scope].Value, "%s: %q eviction must be empty", name, scope)
				assert.Less(t, byScope[scope].MaxAge, 0, "%s: %q eviction must expire", name, scope)
			}
		}
	})

	t.Run("logout clears domain, host-only and parent cookies", func(t *testing.T) {
		handler, service, store := setupCookieHandlerWithDomain(t, domain)
		ctx := context.Background()
		registerUser(t, store, "evict-logout@example.com", "SecurePassword123!", service)

		resp, err := handler.Logout(ctx, connect.NewRequest(&authv1.LogoutRequest{}))
		require.NoError(t, err)

		for _, name := range []string{AccessTokenCookie, RefreshTokenCookie} {
			cookies := setCookiesByName(resp.Header(), name)
			require.Len(t, cookies, 3, "%s: expected domain + host-only + parent clears", name)
			for _, c := range cookies {
				assert.Empty(t, c.Value, "%s: clear must be empty", name)
				assert.Less(t, c.MaxAge, 0, "%s: clear must expire", name)
			}
		}
	})

	t.Run("host-only config emits no extra eviction", func(t *testing.T) {
		handler, service, store := setupCookieHandler(t) // Domain unset
		ctx := context.Background()
		registerUser(t, store, "evict-noop@example.com", "SecurePassword123!", service)

		req := connect.NewRequest(&authv1.LoginRequest{
			Email:    "evict-noop@example.com",
			Password: "SecurePassword123!",
		})
		resp, err := handler.Login(ctx, req)
		require.NoError(t, err)

		for _, name := range []string{AccessTokenCookie, RefreshTokenCookie} {
			cookies := setCookiesByName(resp.Header(), name)
			assert.Len(t, cookies, 1, "%s: host-only config must not duplicate cookies", name)
		}
	})
}

func TestParentDomains(t *testing.T) {
	tests := []struct {
		host string
		want []string
	}{
		{"app.example.com", []string{"example.com"}},
		{".app.example.com", []string{"example.com"}},
		{"a.b.example.com", []string{"b.example.com", "example.com"}},
		{"example.com", nil},
		{"localhost", nil},
		{"", nil},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, parentDomains(tt.host), "parentDomains(%q)", tt.host)
	}
}

// TestGetCookieFromHeader_SkipsEmptyDuplicate ensures a cleared duplicate does
// not shadow the real token while the browser is still evicting it.
func TestGetCookieFromHeader_SkipsEmptyDuplicate(t *testing.T) {
	handler, _, _ := setupCookieHandlerWithDomain(t, "app.example.com")
	header := http.Header{"Cookie": []string{"psina_access=; psina_access=real-token"}}
	assert.Equal(t, "real-token", handler.getCookieFromHeader(header, AccessTokenCookie))
}
