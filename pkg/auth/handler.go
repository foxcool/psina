package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/pkg/api/auth/v1"
	"github.com/foxcool/psina/pkg/token"
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
	})
	resp.Header().Set("X-User-Id", claims.UserID)
	resp.Header().Set("X-User-Email", claims.Email)

	return resp, nil
}

// setTokenCookies sets access and refresh token cookies.
func (h *Handler) setTokenCookies(header http.Header, accessToken, refreshToken string) {
	// Access token cookie (shorter lived)
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
}

// clearTokenCookies removes token cookies.
func (h *Handler) clearTokenCookies(header http.Header) {
	// Clear access token cookie
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
}

// getCookieFromHeader extracts a cookie value from the Cookie header.
func (h *Handler) getCookieFromHeader(header http.Header, name string) string {
	cookieHeader := header.Get("Cookie")
	if cookieHeader == "" {
		return ""
	}

	// Parse cookies manually since we only have headers
	for _, cookie := range strings.Split(cookieHeader, ";") {
		cookie = strings.TrimSpace(cookie)
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 && parts[0] == name {
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
