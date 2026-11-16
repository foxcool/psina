package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveForwardAuth runs one request through h.ForwardAuth().
func serveForwardAuth(h *Handler, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ForwardAuth().ServeHTTP(rec, req)
	return rec
}

// TestHandler_ForwardAuth pins the contract reverse proxies depend on: status
// codes, plain-text bodies and the X-User-* headers.
func TestHandler_ForwardAuth(t *testing.T) {
	ctx := context.Background()

	t.Run("bearer token sets identity headers", func(t *testing.T) {
		handler, service, store := setupTestHandler(t)
		result := registerUser(t, store, "fa@example.com", "SecurePassword123!", service)

		rec := serveForwardAuth(handler, http.Header{"Authorization": {"Bearer " + result.TokenPair.AccessToken}})

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, result.UserID, rec.Header().Get("X-User-Id"))
		assert.Equal(t, "fa@example.com", rec.Header().Get("X-User-Email"))
		assert.Empty(t, rec.Header().Values("X-User-Roles"), "no roles, no header")
		assert.Empty(t, rec.Body.String())
	})

	t.Run("roles header", func(t *testing.T) {
		handler, service, store := setupTestHandler(t)
		require.NoError(t, store.Create(ctx, &entity.User{ID: "user-123", Email: "roles@example.com", Roles: []string{"admin", "support"}}))
		result, err := service.Login(ctx, "roles@example.com", "SecurePassword123!")
		require.NoError(t, err)

		rec := serveForwardAuth(handler, http.Header{"Authorization": {"Bearer " + result.TokenPair.AccessToken}})

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "admin,support", rec.Header().Get("X-User-Roles"))
	})

	t.Run("token from cookie when enabled", func(t *testing.T) {
		handler, service, store := setupCookieHandler(t)
		result := registerUser(t, store, "facookie@example.com", "SecurePassword123!", service)

		rec := serveForwardAuth(handler, http.Header{"Cookie": {AccessTokenCookie + "=" + result.TokenPair.AccessToken}})

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "facookie@example.com", rec.Header().Get("X-User-Email"))
	})

	// A browser mid-eviction sends a cleared legacy duplicate first; Verify
	// already skips it, ForwardAuth must too.
	t.Run("empty duplicate cookie does not shadow the token", func(t *testing.T) {
		handler, service, store := setupCookieHandler(t)
		result := registerUser(t, store, "dup@example.com", "SecurePassword123!", service)

		rec := serveForwardAuth(handler, http.Header{"Cookie": {AccessTokenCookie + "=; " + AccessTokenCookie + "=" + result.TokenPair.AccessToken}})

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "dup@example.com", rec.Header().Get("X-User-Email"))
	})

	// HTTP/1.1 clients may split cookies over several Cookie header lines.
	t.Run("token in a second Cookie header line", func(t *testing.T) {
		handler, service, store := setupCookieHandler(t)
		result := registerUser(t, store, "lines@example.com", "SecurePassword123!", service)

		rec := serveForwardAuth(handler, http.Header{"Cookie": {"theme=dark", AccessTokenCookie + "=" + result.TokenPair.AccessToken}})

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "lines@example.com", rec.Header().Get("X-User-Email"))
	})

	t.Run("cookie ignored when disabled", func(t *testing.T) {
		handler, service, store := setupTestHandler(t)
		result := registerUser(t, store, "nocookie@example.com", "SecurePassword123!", service)

		rec := serveForwardAuth(handler, http.Header{"Cookie": {AccessTokenCookie + "=" + result.TokenPair.AccessToken}})

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "missing authorization\n", rec.Body.String())
	})

	t.Run("bad authorization header wins over a valid cookie", func(t *testing.T) {
		handler, service, store := setupCookieHandler(t)
		result := registerUser(t, store, "badformat@example.com", "SecurePassword123!", service)

		rec := serveForwardAuth(handler, http.Header{
			"Authorization": {"Basic dXNlcjpwYXNz"},
			"Cookie":        {AccessTokenCookie + "=" + result.TokenPair.AccessToken},
		})

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "invalid authorization format\n", rec.Body.String())
		assert.Empty(t, rec.Header().Get("X-User-Id"))
	})

	t.Run("missing token", func(t *testing.T) {
		handler, _, _ := setupCookieHandler(t)

		rec := serveForwardAuth(handler, nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "missing authorization\n", rec.Body.String())
		assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
	})

	t.Run("invalid token", func(t *testing.T) {
		handler, _, _ := setupTestHandler(t)

		rec := serveForwardAuth(handler, http.Header{"Authorization": {"Bearer invalid.token.here"}})

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "invalid token\n", rec.Body.String())
		assert.Empty(t, rec.Header().Get("X-User-Id"))
	})

	t.Run("storage failure is 500 without driver detail", func(t *testing.T) {
		broken := brokenStore{Store: memory.New()}
		issuer, err := token.New()
		require.NoError(t, err)
		handler := NewHandler(NewService(broken, broken, issuer, []Provider{&mockProvider{}}, WithPAT(broken, PATConfig{})))

		rec := serveForwardAuth(handler, http.Header{"Authorization": {"Bearer " + token.PATPrefix + "whatever"}})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, "internal error\n", rec.Body.String())
		assert.Empty(t, rec.Header().Get("X-User-Id"))
	})
}
