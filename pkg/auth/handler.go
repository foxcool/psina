package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/pkg/api/auth/v1"
)

// Handler implements Connect RPC AuthServiceHandler.
type Handler struct {
	service *Service
}

// NewHandler creates a new RPC handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
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

	return connect.NewResponse(&authv1.RegisterResponse{
		UserId:       result.UserID,
		Email:        result.Email,
		AccessToken:  result.TokenPair.AccessToken,
		RefreshToken: result.TokenPair.RefreshToken,
		ExpiresIn:    result.TokenPair.ExpiresIn,
	}), nil
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

	return connect.NewResponse(&authv1.LoginResponse{
		AccessToken:  result.TokenPair.AccessToken,
		RefreshToken: result.TokenPair.RefreshToken,
		ExpiresIn:    result.TokenPair.ExpiresIn,
	}), nil
}

// Refresh exchanges a refresh token for new tokens.
func (h *Handler) Refresh(
	ctx context.Context,
	req *connect.Request[authv1.RefreshRequest],
) (*connect.Response[authv1.RefreshResponse], error) {
	tokenPair, err := h.service.Refresh(ctx, req.Msg.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrTokenReuse) {
			slog.Warn("token reuse detected",
				"ip", getClientIP(req.Header()),
				"user_agent", req.Header().Get("User-Agent"),
			)
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid refresh token"))
	}

	return connect.NewResponse(&authv1.RefreshResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
	}), nil
}

// Logout revokes a refresh token.
func (h *Handler) Logout(
	ctx context.Context,
	req *connect.Request[authv1.LogoutRequest],
) (*connect.Response[authv1.LogoutResponse], error) {
	err := h.service.Logout(ctx, req.Msg.RefreshToken)
	if err != nil {
		// Don't expose token not found errors
		return connect.NewResponse(&authv1.LogoutResponse{Success: true}), nil
	}

	return connect.NewResponse(&authv1.LogoutResponse{Success: true}), nil
}

// Verify validates an access token (for ForwardAuth).
func (h *Handler) Verify(
	ctx context.Context,
	req *connect.Request[authv1.VerifyRequest],
) (*connect.Response[authv1.VerifyResponse], error) {
	// Extract token from Authorization header
	auth := req.Header().Get("Authorization")
	if auth == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization header"))
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid authorization format"))
	}

	claims, err := h.service.Verify(ctx, token)
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
