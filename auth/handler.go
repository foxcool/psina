package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/api/auth/v1"
	"github.com/foxcool/psina/api/auth/v1/authv1connect"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/oauth"
	"github.com/foxcool/psina/store"
	"github.com/foxcool/psina/token"
)

const (
	// Cookie names
	AccessTokenCookie  = "psina_access"
	RefreshTokenCookie = "psina_refresh"
)

// CookieConfig holds cookie-related settings.
type CookieConfig struct {
	Enabled  bool
	Domain   string
	Path     string
	Secure   bool
	SameSite http.SameSite
}

// Handler implements Connect RPC AuthServiceHandler.
type Handler struct {
	service      *Service
	cookieConfig *CookieConfig
}

// HandlerOption configures the Handler.
type HandlerOption func(*Handler)

// WithCookieConfig sets cookie configuration.
func WithCookieConfig(config *CookieConfig) HandlerOption {
	return func(h *Handler) {
		h.cookieConfig = config
	}
}

// NewHandler creates a new RPC handler.
func NewHandler(service *Service, opts ...HandlerOption) *Handler {
	h := &Handler{
		service: service,
		cookieConfig: &CookieConfig{
			Enabled: false,
		},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Register creates a new user account.
func (h *Handler) Register(
	ctx context.Context,
	req *connect.Request[authv1.RegisterRequest],
) (*connect.Response[authv1.RegisterResponse], error) {
	result, err := h.service.Register(ctx, req.Msg.Email, req.Msg.Password)
	if err != nil {
		if errors.Is(err, ErrUserExists) {
			return nil, connect.NewError(connect.CodeAlreadyExists, err)
		}
		if errors.Is(err, ErrInvalidEmail) || errors.Is(err, ErrPasswordTooShort) || errors.Is(err, ErrPasswordTooLong) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := connect.NewResponse(&authv1.RegisterResponse{
		UserId:       result.UserID,
		Email:        result.Email,
		AccessToken:  result.TokenPair.AccessToken,
		RefreshToken: result.TokenPair.RefreshToken,
		ExpiresIn:    result.TokenPair.ExpiresIn,
	})

	// Set cookies if enabled
	if h.cookieConfig.Enabled {
		h.setTokenCookies(resp.Header(), result.TokenPair.AccessToken, result.TokenPair.RefreshToken)
	}

	return resp, nil
}

// Login authenticates a user.
func (h *Handler) Login(
	ctx context.Context,
	req *connect.Request[authv1.LoginRequest],
) (*connect.Response[authv1.LoginResponse], error) {
	result, err := h.service.Login(ctx, req.Msg.Email, req.Msg.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := connect.NewResponse(&authv1.LoginResponse{
		AccessToken:  result.TokenPair.AccessToken,
		RefreshToken: result.TokenPair.RefreshToken,
		ExpiresIn:    result.TokenPair.ExpiresIn,
	})

	// Set cookies if enabled
	if h.cookieConfig.Enabled {
		h.setTokenCookies(resp.Header(), result.TokenPair.AccessToken, result.TokenPair.RefreshToken)
	}

	return resp, nil
}

// Refresh exchanges a refresh token for new tokens.
func (h *Handler) Refresh(
	ctx context.Context,
	req *connect.Request[authv1.RefreshRequest],
) (*connect.Response[authv1.RefreshResponse], error) {
	// Try to get refresh token from request body first
	refreshToken := req.Msg.RefreshToken

	// If not in body and cookies enabled, try cookie
	if refreshToken == "" && h.cookieConfig.Enabled {
		if cookie := h.getCookieFromHeader(req.Header(), RefreshTokenCookie); cookie != "" {
			refreshToken = cookie
		}
	}

	if refreshToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("refresh token required"))
	}

	tokenPair, err := h.service.Refresh(ctx, refreshToken)
	if err != nil {
		var reuseErr *TokenReuseError
		if errors.As(err, &reuseErr) {
			slog.Warn("token reuse detected",
				"user_id", reuseErr.UserID,
				"ip", getClientIP(req.Header()),
				"user_agent", req.Header().Get("User-Agent"),
			)
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid refresh token"))
	}

	resp := connect.NewResponse(&authv1.RefreshResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
	})

	// Set new cookies if enabled
	if h.cookieConfig.Enabled {
		h.setTokenCookies(resp.Header(), tokenPair.AccessToken, tokenPair.RefreshToken)
	}

	return resp, nil
}

// Logout revokes a refresh token.
func (h *Handler) Logout(
	ctx context.Context,
	req *connect.Request[authv1.LogoutRequest],
) (*connect.Response[authv1.LogoutResponse], error) {
	// Try to get refresh token from request body first
	refreshToken := req.Msg.RefreshToken

	// If not in body and cookies enabled, try cookie
	if refreshToken == "" && h.cookieConfig.Enabled {
		if cookie := h.getCookieFromHeader(req.Header(), RefreshTokenCookie); cookie != "" {
			refreshToken = cookie
		}
	}

	if refreshToken != "" {
		_ = h.service.Logout(ctx, refreshToken)
	}

	resp := connect.NewResponse(&authv1.LogoutResponse{Success: true})

	// Clear cookies if enabled
	if h.cookieConfig.Enabled {
		h.clearTokenCookies(resp.Header())
	}

	return resp, nil
}

// Verify validates an access token (for ForwardAuth).
func (h *Handler) Verify(
	ctx context.Context,
	req *connect.Request[authv1.VerifyRequest],
) (*connect.Response[authv1.VerifyResponse], error) {
	// Extract token from Authorization header
	auth := req.Header().Get("Authorization")
	var accessToken string

	if auth != "" {
		accessToken = strings.TrimPrefix(auth, "Bearer ")
		if accessToken == auth {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid authorization format"))
		}
	}

	// If not in header and cookies enabled, try cookie
	if accessToken == "" && h.cookieConfig.Enabled {
		if cookie := h.getCookieFromHeader(req.Header(), AccessTokenCookie); cookie != "" {
			accessToken = cookie
		}
	}

	if accessToken == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization"))
	}

	claims, err := h.service.Verify(ctx, accessToken)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid token"))
	}

	// Return response with headers for gateway
	resp := connect.NewResponse(&authv1.VerifyResponse{
		UserId: claims.UserID,
		Email:  claims.Email,
		Roles:  claims.Roles,
	})
	resp.Header().Set("X-User-Id", claims.UserID)
	resp.Header().Set("X-User-Email", claims.Email)
	if len(claims.Roles) > 0 {
		resp.Header().Set("X-User-Roles", strings.Join(claims.Roles, ","))
	}

	return resp, nil
}

// GetOAuthURL starts an OAuth sign-in flow. The browser-binding secret goes
// into an HttpOnly cookie when cookies are enabled, otherwise into the
// response for the client to keep.
func (h *Handler) GetOAuthURL(
	ctx context.Context,
	req *connect.Request[authv1.GetOAuthURLRequest],
) (*connect.Response[authv1.GetOAuthURLResponse], error) {
	if req.Msg.Provider == "" || req.Msg.RedirectUri == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("provider and redirect_uri are required"))
	}

	result, err := h.service.GetOAuthURL(ctx, req.Msg.Provider, req.Msg.RedirectUri)
	if err != nil {
		return nil, oauthErrorToConnect(ctx, err)
	}

	resp := connect.NewResponse(&authv1.GetOAuthURLResponse{
		Url:   result.URL,
		State: result.State,
	})
	if h.cookieConfig.Enabled {
		h.setOAuthBindingCookie(resp.Header(), result.State, result.Binding, h.service.oauthConfig.StateTTL)
	} else {
		resp.Msg.Binding = result.Binding
	}
	return resp, nil
}

// OAuthCallback completes an OAuth sign-in flow and issues a session like Login.
func (h *Handler) OAuthCallback(
	ctx context.Context,
	req *connect.Request[authv1.OAuthCallbackRequest],
) (*connect.Response[authv1.OAuthCallbackResponse], error) {
	msg := req.Msg
	if msg.Provider == "" || msg.RedirectUri == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("provider and redirect_uri are required"))
	}

	// In cookie mode only the cookie counts: a binding in the body could come
	// from a page other than the one that started the flow.
	binding := msg.Binding
	if h.cookieConfig.Enabled {
		binding = h.getCookieFromHeader(req.Header(), oauthBindingCookieName(msg.State))
	}

	result, err := h.service.OAuthCallback(ctx, OAuthCallbackRequest{
		Provider:    msg.Provider,
		Code:        msg.Code,
		State:       msg.State,
		RedirectURI: msg.RedirectUri,
		Binding:     binding,
	})
	if err != nil {
		cerr := oauthErrorToConnect(ctx, err)
		// The binding cookie is single-use like the state; drop it on any outcome.
		if h.cookieConfig.Enabled {
			h.clearOAuthBindingCookie(cerr.Meta(), msg.State)
		}
		return nil, cerr
	}

	resp := connect.NewResponse(&authv1.OAuthCallbackResponse{
		UserId:       result.UserID,
		Email:        result.Email,
		AccessToken:  result.TokenPair.AccessToken,
		RefreshToken: result.TokenPair.RefreshToken,
		ExpiresIn:    result.TokenPair.ExpiresIn,
		IsNewUser:    result.IsNewUser,
	})
	if h.cookieConfig.Enabled {
		h.clearOAuthBindingCookie(resp.Header(), msg.State)
		h.setTokenCookies(resp.Header(), result.TokenPair.AccessToken, result.TokenPair.RefreshToken)
	}
	return resp, nil
}

// errOAuthStateOrCode is the one message for a rejected state and a rejected
// code, so a client cannot tell which check failed.
var errOAuthStateOrCode = errors.New("invalid oauth state or code")

// oauthErrorToConnect maps OAuth service errors to connect codes. Unexpected
// errors are logged and reach the client without storage or provider detail.
func oauthErrorToConnect(ctx context.Context, err error) *connect.Error {
	switch {
	case errors.Is(err, ErrOAuthDisabled):
		return connect.NewError(connect.CodeUnimplemented, ErrOAuthDisabled)
	case errors.Is(err, ErrOAuthProviderUnknown):
		return connect.NewError(connect.CodeInvalidArgument, ErrOAuthProviderUnknown)
	case errors.Is(err, oauth.ErrRedirectURINotAllowed):
		return connect.NewError(connect.CodePermissionDenied, oauth.ErrRedirectURINotAllowed)
	case errors.Is(err, ErrOAuthStateInvalid):
		return connect.NewError(connect.CodeUnauthenticated, errOAuthStateOrCode)
	case errors.Is(err, ErrOAuthExchangeFailed):
		// Also a provider outage looks like this; keep it visible.
		slog.WarnContext(ctx, "oauth code exchange failed", "error", err)
		return connect.NewError(connect.CodeUnauthenticated, errOAuthStateOrCode)
	case errors.Is(err, ErrOAuthEmailRequired):
		return connect.NewError(connect.CodeFailedPrecondition, ErrOAuthEmailRequired)
	case errors.Is(err, ErrOAuthEmailUnverified):
		return connect.NewError(connect.CodeFailedPrecondition, ErrOAuthEmailUnverified)
	case errors.Is(err, ErrOAuthLinkDisabled):
		return connect.NewError(connect.CodeFailedPrecondition, ErrOAuthLinkDisabled)
	case errors.Is(err, ErrOAuthAccountHasPassword):
		return connect.NewError(connect.CodeFailedPrecondition, ErrOAuthAccountHasPassword)
	default:
		slog.ErrorContext(ctx, "oauth sign-in failed", "error", err)
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
}

// GetChallenge issues the message a wallet must sign to sign in.
func (h *Handler) GetChallenge(
	ctx context.Context,
	req *connect.Request[authv1.GetChallengeRequest],
) (*connect.Response[authv1.GetChallengeResponse], error) {
	if req.Msg.Chain == "" || req.Msg.Address == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("chain and address are required"))
	}

	result, err := h.service.GetChallenge(ctx, req.Msg.Chain, req.Msg.Address)
	if err != nil {
		return nil, walletErrorToConnect(ctx, err)
	}

	return connect.NewResponse(&authv1.GetChallengeResponse{
		Nonce:     result.Nonce,
		Message:   result.Message,
		ExpiresAt: result.ExpiresAt.Unix(),
	}), nil
}

// AuthenticateWallet verifies a signed challenge and issues a session like Login.
func (h *Handler) AuthenticateWallet(
	ctx context.Context,
	req *connect.Request[authv1.AuthenticateWalletRequest],
) (*connect.Response[authv1.AuthenticateWalletResponse], error) {
	msg := req.Msg
	if msg.Chain == "" || msg.Address == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("chain and address are required"))
	}

	result, err := h.service.AuthenticateWallet(ctx, WalletAuthRequest{
		Chain:     msg.Chain,
		Address:   msg.Address,
		Nonce:     msg.Nonce,
		Signature: msg.Signature,
	})
	if err != nil {
		return nil, walletErrorToConnect(ctx, err)
	}

	resp := connect.NewResponse(&authv1.AuthenticateWalletResponse{
		UserId:       result.UserID,
		Email:        result.Email,
		AccessToken:  result.TokenPair.AccessToken,
		RefreshToken: result.TokenPair.RefreshToken,
		ExpiresIn:    result.TokenPair.ExpiresIn,
		IsNewUser:    result.IsNewUser,
	})
	if h.cookieConfig.Enabled {
		h.setTokenCookies(resp.Header(), result.TokenPair.AccessToken, result.TokenPair.RefreshToken)
	}
	return resp, nil
}

// walletErrorToConnect maps wallet service errors to connect codes. Unexpected
// errors are logged and reach the client without storage detail.
func walletErrorToConnect(ctx context.Context, err error) *connect.Error {
	switch {
	case errors.Is(err, ErrWalletDisabled):
		return connect.NewError(connect.CodeUnimplemented, ErrWalletDisabled)
	case errors.Is(err, ErrWalletChainUnsupported):
		return connect.NewError(connect.CodeInvalidArgument, ErrWalletChainUnsupported)
	case errors.Is(err, ErrWalletAddressInvalid):
		return connect.NewError(connect.CodeInvalidArgument, ErrWalletAddressInvalid)
	case errors.Is(err, ErrWalletChallengeInvalid):
		return connect.NewError(connect.CodeUnauthenticated, ErrWalletChallengeInvalid)
	default:
		slog.ErrorContext(ctx, "wallet sign-in failed", "error", err)
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
}

// CreatePersonalAccessToken mints a PAT for the authenticated caller.
func (h *Handler) CreatePersonalAccessToken(
	ctx context.Context,
	req *connect.Request[authv1.CreatePersonalAccessTokenRequest],
) (*connect.Response[authv1.CreatePersonalAccessTokenResponse], error) {
	userID, err := h.authenticateSession(ctx, req.Header())
	if err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if req.Msg.ExpiresAt > 0 {
		t := time.Unix(req.Msg.ExpiresAt, 0).UTC()
		expiresAt = &t
	}

	result, err := h.service.CreatePAT(ctx, userID, req.Msg.Name, req.Msg.Scopes, expiresAt)
	if err != nil {
		return nil, patErrorToConnect(err)
	}

	return connect.NewResponse(&authv1.CreatePersonalAccessTokenResponse{
		Token: result.Plaintext,
		Pat:   patToProto(result.Token),
	}), nil
}

// ListPersonalAccessTokens lists the caller's PATs (metadata only).
func (h *Handler) ListPersonalAccessTokens(
	ctx context.Context,
	req *connect.Request[authv1.ListPersonalAccessTokensRequest],
) (*connect.Response[authv1.ListPersonalAccessTokensResponse], error) {
	userID, err := h.authenticateSession(ctx, req.Header())
	if err != nil {
		return nil, err
	}

	pats, err := h.service.ListPATs(ctx, userID)
	if err != nil {
		return nil, patErrorToConnect(err)
	}

	resp := &authv1.ListPersonalAccessTokensResponse{
		Pats: make([]*authv1.PersonalAccessToken, 0, len(pats)),
	}
	for _, pat := range pats {
		resp.Pats = append(resp.Pats, patToProto(pat))
	}

	return connect.NewResponse(resp), nil
}

// RevokePersonalAccessToken deletes a PAT owned by the caller.
func (h *Handler) RevokePersonalAccessToken(
	ctx context.Context,
	req *connect.Request[authv1.RevokePersonalAccessTokenRequest],
) (*connect.Response[authv1.RevokePersonalAccessTokenResponse], error) {
	userID, err := h.authenticateSession(ctx, req.Header())
	if err != nil {
		return nil, err
	}

	if err := h.service.RevokePAT(ctx, userID, req.Msg.Id); err != nil {
		if errors.Is(err, store.ErrTokenNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
		}
		return nil, patErrorToConnect(err)
	}

	return connect.NewResponse(&authv1.RevokePersonalAccessTokenResponse{Success: true}), nil
}

// authenticateSession extracts the Bearer token from the request and resolves
// the caller's user ID. Only session (JWT) tokens are accepted: PATs cannot
// manage PATs, so a leaked PAT cannot mint replacements or revoke siblings.
func (h *Handler) authenticateSession(ctx context.Context, header http.Header) (string, error) {
	var accessToken string

	auth := header.Get("Authorization")
	if auth != "" {
		accessToken = strings.TrimPrefix(auth, "Bearer ")
		if accessToken == auth {
			return "", connect.NewError(connect.CodeUnauthenticated, errors.New("missing or invalid authorization"))
		}
	}

	// Browser clients hold the session in the HttpOnly psina_access cookie and
	// cannot set the Authorization header, so fall back to it (same as Verify).
	if accessToken == "" && h.cookieConfig.Enabled {
		if cookie := h.getCookieFromHeader(header, AccessTokenCookie); cookie != "" {
			accessToken = cookie
		}
	}

	if accessToken == "" {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("missing or invalid authorization"))
	}

	if strings.HasPrefix(accessToken, token.PATPrefix) {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("personal access tokens cannot manage tokens"))
	}

	claims, err := h.service.Verify(ctx, accessToken)
	if err != nil {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("invalid token"))
	}

	return claims.UserID, nil
}

// patErrorToConnect maps PAT service errors to connect codes.
func patErrorToConnect(err error) *connect.Error {
	switch {
	case errors.Is(err, ErrPATDisabled):
		return connect.NewError(connect.CodeUnimplemented, err)
	case errors.Is(err, ErrPATNameRequired), errors.Is(err, ErrPATNameTooLong), errors.Is(err, ErrPATExpiryInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, ErrPATLimitReached):
		return connect.NewError(connect.CodeResourceExhausted, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// patToProto maps a stored PAT to its metadata proto (never includes the secret).
func patToProto(pat *entity.PersonalAccessToken) *authv1.PersonalAccessToken {
	out := &authv1.PersonalAccessToken{
		Id:        pat.ID,
		Name:      pat.Name,
		Scopes:    pat.Scopes,
		CreatedAt: pat.CreatedAt.Unix(),
	}
	if pat.ExpiresAt != nil {
		out.ExpiresAt = pat.ExpiresAt.Unix()
	}
	if pat.LastUsedAt != nil {
		out.LastUsedAt = pat.LastUsedAt.Unix()
	}
	return out
}

// setTokenCookies sets access and refresh token cookies.
func (h *Handler) setTokenCookies(header http.Header, accessToken, refreshToken string) {
	// Access token cookie (shorter lived)
	// #nosec G124 -- Secure is driven by cookieConfig; deployments set it true behind TLS, dev needs http
	accessCookie := &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    accessToken,
		Domain:   h.cookieConfig.Domain,
		Path:     h.cookieConfig.Path,
		Expires:  time.Now().Add(token.AccessTokenTTL),
		MaxAge:   int(token.AccessTokenTTL.Seconds()),
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
		SameSite: h.cookieConfig.SameSite,
	}
	header.Add("Set-Cookie", accessCookie.String())

	// Refresh token cookie (longer lived)
	// #nosec G124 -- Secure is driven by cookieConfig; deployments set it true behind TLS, dev needs http
	refreshCookie := &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    refreshToken,
		Domain:   h.cookieConfig.Domain,
		Path:     h.cookieConfig.Path,
		Expires:  time.Now().Add(token.RefreshTokenTTL),
		MaxAge:   int(token.RefreshTokenTTL.Seconds()),
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
		SameSite: h.cookieConfig.SameSite,
	}
	header.Add("Set-Cookie", refreshCookie.String())

	// Evict any legacy duplicates left under a foreign scope so the fresh
	// Domain-scoped cookies are the only ones the browser sends back.
	h.clearLegacyScopedCookies(header)
}

// clearLegacyScopedCookies expires token cookies left under any scope other
// than the currently configured one — the host-only scope (no Domain) or a
// broader parent domain — by an earlier deployment that used a different
// cookie.domain. A cookie of the same name under a different scope is a
// distinct browser entry, so a Domain-scoped Set-Cookie never overwrites it:
// the browser keeps sending both and the server may read the stale token
// (401 invalid/not-found token), the outcome depending on how the browser
// orders the duplicates. Emitting an expiry for each foreign scope alongside
// every set/clear makes login and logout self-healing. No-op when Domain is
// unset, since the primary cookies are already host-only.
//
// A parent-domain duplicate (a cookie left on a broader Domain beside the live
// host-scoped one) is the case host-only-only eviction missed.
func (h *Handler) clearLegacyScopedCookies(header http.Header) {
	if h.cookieConfig.Domain == "" {
		return
	}
	// Foreign scopes to expire: host-only (Domain ""), plus every parent domain
	// above the configured one down to the registrable domain. Never the
	// configured domain itself — that carries the live cookie.
	scopes := append([]string{""}, parentDomains(h.cookieConfig.Domain)...)
	for _, name := range []string{AccessTokenCookie, RefreshTokenCookie} {
		for _, domain := range scopes {
			// #nosec G124 -- expiry of a legacy scoped cookie; carries no secret
			cookie := &http.Cookie{
				Name:     name,
				Value:    "",
				Domain:   domain,
				Path:     h.cookieConfig.Path,
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
				Secure:   h.cookieConfig.Secure,
				HttpOnly: true,
				SameSite: h.cookieConfig.SameSite,
			}
			header.Add("Set-Cookie", cookie.String())
		}
	}
}

// parentDomains returns the parent domains of host above the immediate one,
// down to (and including) the two-label registrable domain. For "a.b.example"
// it returns ["b.example"]. Returns nil when host has two or fewer labels. A
// leading dot is normalized away. A cookie can never be scoped to a public
// suffix, so a two-label floor is a safe stopping point for the common
// single-suffix case this heals.
func parentDomains(host string) []string {
	host = strings.TrimPrefix(host, ".")
	labels := strings.Split(host, ".")
	var out []string
	for i := 1; i <= len(labels)-2; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// clearTokenCookies removes token cookies.
func (h *Handler) clearTokenCookies(header http.Header) {
	// Clear access token cookie
	// #nosec G124 -- empty-value cookie clear; Secure mirrors cookieConfig used when set
	accessCookie := &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    "",
		Domain:   h.cookieConfig.Domain,
		Path:     h.cookieConfig.Path,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
		SameSite: h.cookieConfig.SameSite,
	}
	header.Add("Set-Cookie", accessCookie.String())

	// Clear refresh token cookie
	// #nosec G124 -- empty-value cookie clear; Secure mirrors cookieConfig used when set
	refreshCookie := &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    "",
		Domain:   h.cookieConfig.Domain,
		Path:     h.cookieConfig.Path,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
		SameSite: h.cookieConfig.SameSite,
	}
	header.Add("Set-Cookie", refreshCookie.String())

	// Also expire any legacy foreign-scope duplicates so logout leaves nothing behind.
	h.clearLegacyScopedCookies(header)
}

// Binding cookies are per flow: the name carries a state prefix so two flows
// in two tabs do not overwrite each other. 8 base64url characters (48 random
// bits) make a collision between one browser's concurrent flows negligible
// while keeping the name short.
const (
	oauthBindingCookiePrefix     = "psina_oauth_"
	oauthBindingCookieStateChars = 8
)

// oauthBindingCookieName returns the binding cookie of the flow with this state.
func oauthBindingCookieName(state string) string {
	return oauthBindingCookiePrefix + state[:min(len(state), oauthBindingCookieStateChars)]
}

// setOAuthBindingCookie hands the browser the binding secret of a new flow.
// SameSite=Lax rather than the session cookies' configured mode: the flow is
// a round trip through the provider, and a deployment that calls the callback
// RPC from the provider-redirected navigation itself must still get the
// cookie. The path limits it to the callback RPC, the only reader.
func (h *Handler) setOAuthBindingCookie(header http.Header, state, binding string, ttl time.Duration) {
	// #nosec G124 -- Secure is driven by cookieConfig, as for token cookies; dev needs http
	cookie := &http.Cookie{
		Name:     oauthBindingCookieName(state),
		Value:    binding,
		Domain:   h.cookieConfig.Domain,
		Path:     authv1connect.AuthServiceOAuthCallbackProcedure,
		MaxAge:   int(ttl.Seconds()),
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	header.Add("Set-Cookie", cookie.String())
}

// clearOAuthBindingCookie expires the binding cookie of a finished flow.
func (h *Handler) clearOAuthBindingCookie(header http.Header, state string) {
	// #nosec G124 -- empty-value clear; Secure mirrors cookieConfig used when set
	cookie := &http.Cookie{
		Name:     oauthBindingCookieName(state),
		Value:    "",
		Domain:   h.cookieConfig.Domain,
		Path:     authv1connect.AuthServiceOAuthCallbackProcedure,
		MaxAge:   -1,
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	header.Add("Set-Cookie", cookie.String())
}

// getCookieFromHeader extracts a cookie value from the Cookie header.
func (h *Handler) getCookieFromHeader(header http.Header, name string) string {
	cookieHeader := header.Get("Cookie")
	if cookieHeader == "" {
		return ""
	}

	// Parse cookies manually since we only have headers. A browser can send the
	// same name more than once (e.g. a legacy host-only duplicate mid-eviction);
	// skip empty values so a cleared duplicate never shadows the real token.
	for _, cookie := range strings.Split(cookieHeader, ";") {
		cookie = strings.TrimSpace(cookie)
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 && parts[0] == name && parts[1] != "" {
			return parts[1]
		}
	}
	return ""
}

// getClientIP extracts client IP from headers.
func getClientIP(headers interface{ Get(string) string }) string {
	// Check forwarded headers (reverse proxy)
	if ip := headers.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain multiple IPs, take the first
		if idx := strings.Index(ip, ","); idx != -1 {
			return strings.TrimSpace(ip[:idx])
		}
		return ip
	}
	if ip := headers.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return "unknown"
}
