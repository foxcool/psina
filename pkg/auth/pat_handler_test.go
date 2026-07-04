package auth

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/pkg/api/auth/v1"
	"github.com/foxcool/psina/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupPATHandlerTest builds a handler and returns a session JWT and a PAT
// plaintext for the same user, so tests can exercise both credential kinds.
func setupPATHandlerTest(t *testing.T) (handler *Handler, jwt, pat string) {
	t.Helper()
	h, service, store := setupTestHandler(t)
	result := registerUser(t, store, "pat-handler@example.com", "SecurePassword123!", service)

	res, err := service.CreatePAT(context.Background(), result.UserID, "seed", nil, nil)
	require.NoError(t, err)

	return h, result.TokenPair.AccessToken, res.Plaintext
}

func createPATRequest(name string, bearer string) *connect.Request[authv1.CreatePersonalAccessTokenRequest] {
	req := connect.NewRequest(&authv1.CreatePersonalAccessTokenRequest{Name: name})
	if bearer != "" {
		req.Header().Set("Authorization", "Bearer "+bearer)
	}
	return req
}

func TestHandler_CreatePersonalAccessToken(t *testing.T) {
	ctx := context.Background()

	t.Run("success with JWT", func(t *testing.T) {
		handler, jwt, _ := setupPATHandlerTest(t)
		resp, err := handler.CreatePersonalAccessToken(ctx, createPATRequest("ci", jwt))
		require.NoError(t, err)
		assert.Contains(t, resp.Msg.Token, token.PATPrefix)
		assert.NotEmpty(t, resp.Msg.Pat.Id)
		assert.Equal(t, "ci", resp.Msg.Pat.Name)
	})

	t.Run("PAT cannot mint PATs", func(t *testing.T) {
		handler, _, pat := setupPATHandlerTest(t)
		_, err := handler.CreatePersonalAccessToken(ctx, createPATRequest("ci", pat))
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodePermissionDenied, connectErr.Code())
	})

	t.Run("missing authorization", func(t *testing.T) {
		handler, _, _ := setupPATHandlerTest(t)
		_, err := handler.CreatePersonalAccessToken(ctx, createPATRequest("ci", ""))
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
	})

	t.Run("empty name", func(t *testing.T) {
		handler, jwt, _ := setupPATHandlerTest(t)
		_, err := handler.CreatePersonalAccessToken(ctx, createPATRequest("", jwt))
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
	})

	t.Run("expiry in the past", func(t *testing.T) {
		handler, jwt, _ := setupPATHandlerTest(t)
		req := connect.NewRequest(&authv1.CreatePersonalAccessTokenRequest{
			Name:      "stale",
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		})
		req.Header().Set("Authorization", "Bearer "+jwt)
		_, err := handler.CreatePersonalAccessToken(ctx, req)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeInvalidArgument, connectErr.Code())
	})

	t.Run("limit reached", func(t *testing.T) {
		service, store := setupPATService(t, PATConfig{MaxPerUser: 1})
		handler := NewHandler(service)
		result := registerUser(t, store, "limit@example.com", "SecurePassword123!", service)

		req := createPATRequest("first", result.TokenPair.AccessToken)
		_, err := handler.CreatePersonalAccessToken(ctx, req)
		require.NoError(t, err)

		req = createPATRequest("second", result.TokenPair.AccessToken)
		_, err = handler.CreatePersonalAccessToken(ctx, req)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeResourceExhausted, connectErr.Code())
	})

	t.Run("disabled service", func(t *testing.T) {
		memStore := newMemStore(t)
		issuer, err := token.New()
		require.NoError(t, err)
		service := NewService(memStore, memStore, issuer, []Provider{&mockProvider{}}) // no WithPAT
		handler := NewHandler(service)
		result := registerUser(t, memStore, "disabled@example.com", "SecurePassword123!", service)

		_, err = handler.CreatePersonalAccessToken(ctx, createPATRequest("ci", result.TokenPair.AccessToken))
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeUnimplemented, connectErr.Code())
	})
}

func TestHandler_ListPersonalAccessTokens(t *testing.T) {
	ctx := context.Background()

	t.Run("success with JWT", func(t *testing.T) {
		handler, jwt, _ := setupPATHandlerTest(t)
		req := connect.NewRequest(&authv1.ListPersonalAccessTokensRequest{})
		req.Header().Set("Authorization", "Bearer "+jwt)
		resp, err := handler.ListPersonalAccessTokens(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Msg.Pats, 1) // the seed PAT
		assert.NotEmpty(t, resp.Msg.Pats[0].Id)
	})

	t.Run("PAT cannot list PATs", func(t *testing.T) {
		handler, _, pat := setupPATHandlerTest(t)
		req := connect.NewRequest(&authv1.ListPersonalAccessTokensRequest{})
		req.Header().Set("Authorization", "Bearer "+pat)
		_, err := handler.ListPersonalAccessTokens(ctx, req)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodePermissionDenied, connectErr.Code())
	})
}

func TestHandler_RevokePersonalAccessToken(t *testing.T) {
	ctx := context.Background()

	t.Run("success with JWT", func(t *testing.T) {
		handler, jwt, pat := setupPATHandlerTest(t)

		// Find the seed PAT id via List, revoke it, then the PAT stops working.
		listReq := connect.NewRequest(&authv1.ListPersonalAccessTokensRequest{})
		listReq.Header().Set("Authorization", "Bearer "+jwt)
		listResp, err := handler.ListPersonalAccessTokens(ctx, listReq)
		require.NoError(t, err)
		require.Len(t, listResp.Msg.Pats, 1)

		revokeReq := connect.NewRequest(&authv1.RevokePersonalAccessTokenRequest{Id: listResp.Msg.Pats[0].Id})
		revokeReq.Header().Set("Authorization", "Bearer "+jwt)
		resp, err := handler.RevokePersonalAccessToken(ctx, revokeReq)
		require.NoError(t, err)
		assert.True(t, resp.Msg.Success)

		verifyReq := connect.NewRequest(&authv1.VerifyRequest{})
		verifyReq.Header().Set("Authorization", "Bearer "+pat)
		_, err = handler.Verify(ctx, verifyReq)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
	})

	t.Run("unknown id", func(t *testing.T) {
		handler, jwt, _ := setupPATHandlerTest(t)
		req := connect.NewRequest(&authv1.RevokePersonalAccessTokenRequest{Id: "no-such-id"})
		req.Header().Set("Authorization", "Bearer "+jwt)
		_, err := handler.RevokePersonalAccessToken(ctx, req)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
	})

	t.Run("PAT cannot revoke PATs", func(t *testing.T) {
		handler, _, pat := setupPATHandlerTest(t)
		req := connect.NewRequest(&authv1.RevokePersonalAccessTokenRequest{Id: "anything"})
		req.Header().Set("Authorization", "Bearer "+pat)
		_, err := handler.RevokePersonalAccessToken(ctx, req)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodePermissionDenied, connectErr.Code())
	})
}

// TestHandler_ManageWithSessionCookie ensures PAT management works when the
// session JWT arrives in the psina_access cookie (browser clients can't set the
// Authorization header on the HttpOnly cookie).
func TestHandler_ManageWithSessionCookie(t *testing.T) {
	ctx := context.Background()

	// Cookie fallback only applies when cookies are enabled on the handler.
	setup := func(t *testing.T) (handler *Handler, jwt, pat string) {
		t.Helper()
		h, service, store := setupCookieHandler(t)
		result := registerUser(t, store, "pat-cookie@example.com", "SecurePassword123!", service)
		res, err := service.CreatePAT(context.Background(), result.UserID, "seed", nil, nil)
		require.NoError(t, err)
		return h, result.TokenPair.AccessToken, res.Plaintext
	}

	t.Run("create with cookie JWT", func(t *testing.T) {
		handler, jwt, _ := setup(t)
		req := connect.NewRequest(&authv1.CreatePersonalAccessTokenRequest{Name: "ci"})
		req.Header().Set("Cookie", AccessTokenCookie+"="+jwt)
		resp, err := handler.CreatePersonalAccessToken(ctx, req)
		require.NoError(t, err)
		assert.Contains(t, resp.Msg.Token, token.PATPrefix)
	})

	t.Run("PAT in cookie cannot manage", func(t *testing.T) {
		handler, _, pat := setup(t)
		req := connect.NewRequest(&authv1.CreatePersonalAccessTokenRequest{Name: "ci"})
		req.Header().Set("Cookie", AccessTokenCookie+"="+pat)
		_, err := handler.CreatePersonalAccessToken(ctx, req)
		var connectErr *connect.Error
		require.ErrorAs(t, err, &connectErr)
		assert.Equal(t, connect.CodePermissionDenied, connectErr.Code())
	})
}

// TestHandler_VerifyAcceptsPAT ensures the ForwardAuth path still accepts PATs
// even though management RPCs do not.
func TestHandler_VerifyAcceptsPAT(t *testing.T) {
	handler, _, pat := setupPATHandlerTest(t)

	req := connect.NewRequest(&authv1.VerifyRequest{})
	req.Header().Set("Authorization", "Bearer "+pat)
	resp, err := handler.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "user-123", resp.Msg.UserId)
	assert.Equal(t, "user-123", resp.Header().Get("X-User-Id"))
}
