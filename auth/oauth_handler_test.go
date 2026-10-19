package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/api/auth/v1"
	"github.com/foxcool/psina/api/auth/v1/authv1connect"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupOAuthHandler(t *testing.T, cookies bool) *Handler {
	t.Helper()
	svc, _ := setupOAuthService(t, OAuthConfig{}, newFakeGoogle(verifiedInfo("sub-1", "user@example.com")))
	if !cookies {
		return NewHandler(svc)
	}
	return NewHandler(svc, WithCookieConfig(&CookieConfig{
		Enabled:  true,
		Domain:   "app.example.com",
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}))
}

func getOAuthURL(t *testing.T, h *Handler) *connect.Response[authv1.GetOAuthURLResponse] {
	t.Helper()
	resp, err := h.GetOAuthURL(context.Background(), connect.NewRequest(&authv1.GetOAuthURLRequest{
		Provider:    entity.ProviderTypeGoogle,
		RedirectUri: testRedirectURI,
	}))
	require.NoError(t, err)
	return resp
}

func callbackRequest(state, binding string) *connect.Request[authv1.OAuthCallbackRequest] {
	return connect.NewRequest(&authv1.OAuthCallbackRequest{
		Provider:    entity.ProviderTypeGoogle,
		Code:        "auth-code",
		State:       state,
		RedirectUri: testRedirectURI,
		Binding:     binding,
	})
}

func TestHandler_OAuth_BearerMode(t *testing.T) {
	ctx := context.Background()
	h := setupOAuthHandler(t, false)

	start := getOAuthURL(t, h)
	assert.NotEmpty(t, start.Msg.Url)
	assert.NotEmpty(t, start.Msg.Binding, "without cookies the client keeps the binding")
	assert.Empty(t, start.Header().Values("Set-Cookie"))

	// A callback without the binding is a request from another browser.
	_, err := h.OAuthCallback(ctx, callbackRequest(start.Msg.State, ""))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	resp, err := h.OAuthCallback(ctx, callbackRequest(start.Msg.State, start.Msg.Binding))
	require.NoError(t, err)
	assert.True(t, resp.Msg.IsNewUser)
	assert.Equal(t, "user@example.com", resp.Msg.Email)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	assert.Empty(t, resp.Header().Values("Set-Cookie"))
}

func TestHandler_OAuth_CookieMode(t *testing.T) {
	ctx := context.Background()
	h := setupOAuthHandler(t, true)

	start := getOAuthURL(t, h)
	assert.Empty(t, start.Msg.Binding, "with cookies the binding never reaches script")

	name := oauthBindingCookieName(start.Msg.State)
	set := setCookiesByName(start.Header(), name)
	require.Len(t, set, 1)
	binding := set[0]
	assert.NotEmpty(t, binding.Value)
	assert.True(t, binding.HttpOnly)
	assert.True(t, binding.Secure)
	assert.Equal(t, http.SameSiteLaxMode, binding.SameSite, "must survive the redirect back from the provider")
	assert.Equal(t, authv1connect.AuthServiceOAuthCallbackProcedure, binding.Path)
	assert.Equal(t, "app.example.com", binding.Domain)
	assert.Equal(t, int(DefaultOAuthStateTTL.Seconds()), binding.MaxAge)

	req := callbackRequest(start.Msg.State, "")
	req.Header().Set("Cookie", fmt.Sprintf("%s=%s", name, binding.Value))
	resp, err := h.OAuthCallback(ctx, req)
	require.NoError(t, err)

	maxAge, ok := cookieMaxAge(resp.Header(), name)
	require.True(t, ok, "binding cookie is cleared")
	assert.Negative(t, maxAge)
	assert.True(t, hasCookie(resp.Header(), AccessTokenCookie))
	assert.True(t, hasCookie(resp.Header(), RefreshTokenCookie))
}

func TestHandler_OAuth_CookieModeRejectedClearsBinding(t *testing.T) {
	ctx := context.Background()
	h := setupOAuthHandler(t, true)
	start := getOAuthURL(t, h)

	// No cookie: the attacker's code and state delivered to a victim.
	_, err := h.OAuthCallback(ctx, callbackRequest(start.Msg.State, ""))
	require.Error(t, err)
	var cerr *connect.Error
	require.True(t, errors.As(err, &cerr))
	assert.Equal(t, connect.CodeUnauthenticated, cerr.Code())
	maxAge, ok := cookieMaxAge(cerr.Meta(), oauthBindingCookieName(start.Msg.State))
	require.True(t, ok, "binding cookie is cleared on failure too")
	assert.Negative(t, maxAge)
	assert.False(t, hasCookie(cerr.Meta(), AccessTokenCookie))
}

func TestHandler_OAuth_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	h := setupOAuthHandler(t, false)

	_, err := h.GetOAuthURL(ctx, connect.NewRequest(&authv1.GetOAuthURLRequest{Provider: entity.ProviderTypeGoogle}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = h.OAuthCallback(ctx, connect.NewRequest(&authv1.OAuthCallbackRequest{Code: "c", State: "s"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = h.GetOAuthURL(ctx, connect.NewRequest(&authv1.GetOAuthURLRequest{
		Provider: entity.ProviderTypeGitHub, RedirectUri: testRedirectURI,
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = h.GetOAuthURL(ctx, connect.NewRequest(&authv1.GetOAuthURLRequest{
		Provider: entity.ProviderTypeGoogle, RedirectUri: "https://evil.example.com/cb",
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestHandler_OAuth_Disabled(t *testing.T) {
	h, _, _ := setupTestHandler(t)
	_, err := h.GetOAuthURL(context.Background(), connect.NewRequest(&authv1.GetOAuthURLRequest{
		Provider: entity.ProviderTypeGoogle, RedirectUri: testRedirectURI,
	}))
	assert.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
}

func TestOAuthErrorToConnect(t *testing.T) {
	tests := []struct {
		err  error
		code connect.Code
	}{
		{ErrOAuthDisabled, connect.CodeUnimplemented},
		{fmt.Errorf("%w: %q", ErrOAuthProviderUnknown, "x"), connect.CodeInvalidArgument},
		{fmt.Errorf("build auth url: %w", oauth.ErrRedirectURINotAllowed), connect.CodePermissionDenied},
		{ErrOAuthStateInvalid, connect.CodeUnauthenticated},
		{fmt.Errorf("%w: %w", ErrOAuthExchangeFailed, oauth.ErrInvalidToken), connect.CodeUnauthenticated},
		{ErrOAuthEmailRequired, connect.CodeFailedPrecondition},
		{ErrOAuthEmailUnverified, connect.CodeFailedPrecondition},
		{ErrOAuthLinkDisabled, connect.CodeFailedPrecondition},
		{ErrOAuthAccountHasPassword, connect.CodeFailedPrecondition},
		{errors.New("save oauth state: dial tcp 10.0.0.5:5432: connection refused"), connect.CodeInternal},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			cerr := oauthErrorToConnect(context.Background(), tt.err)
			assert.Equal(t, tt.code, cerr.Code())
			assert.NotContains(t, cerr.Message(), "10.0.0.5", "no storage detail to the client")
			assert.NotContains(t, cerr.Message(), "invalid provider token", "no provider detail to the client")
		})
	}
}

func TestOAuthBindingCookieName_ShortState(t *testing.T) {
	assert.Equal(t, "psina_oauth_abc", oauthBindingCookieName("abc"))
	assert.Equal(t, "psina_oauth_abcdefgh", oauthBindingCookieName("abcdefghijk"))
}

// In cookie mode a binding in the body is ignored: only the browser that got
// the cookie may finish the flow, whatever a page puts into the request.
func TestHandler_OAuth_CookieModeIgnoresBodyBinding(t *testing.T) {
	ctx := context.Background()
	h := setupOAuthHandler(t, true)
	start := getOAuthURL(t, h)
	binding := setCookiesByName(start.Header(), oauthBindingCookieName(start.Msg.State))[0].Value

	_, err := h.OAuthCallback(ctx, callbackRequest(start.Msg.State, binding))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}
