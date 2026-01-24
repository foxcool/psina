package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/token"
	"github.com/go-jose/go-jose/v4"
)

// Service errors.
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrTokenRevoked       = errors.New("refresh token revoked")
	ErrTokenExpired       = errors.New("refresh token expired")
)

// Service orchestrates authentication operations.
type Service struct {
	provider   Provider
	tokenStore TokenStore
	userStore  UserStore
	issuer     *token.Issuer
}

// NewService creates a new authentication service.
func NewService(
	provider Provider,
	tokenStore TokenStore,
	userStore UserStore,
	issuer *token.Issuer,
) *Service {
	return &Service{
		provider:   provider,
		tokenStore: tokenStore,
		userStore:  userStore,
		issuer:     issuer,
	}
}

// RegisterResult contains registration result.
type RegisterResult struct {
	UserID    string
	Email     string
	TokenPair *entity.TokenPair
}

// Register creates a new user account and returns tokens.
func (s *Service) Register(ctx context.Context, email, password string) (*RegisterResult, error) {
	// Normalize and validate email
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, fmt.Errorf("validate email: %w", err)
	}

	// Validate password
	if err := ValidatePassword(password); err != nil {
		return nil, fmt.Errorf("validate password: %w", err)
	}

	// Register with provider (creates user and stores credentials)
	req := &entity.RegisterRequest{
		Email:    email,
		Password: password,
	}
	identity, err := s.provider.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	// Issue tokens
	tokenPair, err := s.issueTokens(ctx, identity.UserID, identity.Email)
	if err != nil {
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	return &RegisterResult{
		UserID:    identity.UserID,
		Email:     identity.Email,
		TokenPair: tokenPair,
	}, nil
}

// LoginResult contains login result.
type LoginResult struct {
	UserID    string
	Email     string
	TokenPair *entity.TokenPair
}

// Login authenticates a user and returns tokens.
func (s *Service) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	// Normalize email (don't expose validation errors for security)
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Authenticate with provider
	req := &entity.AuthRequest{
		Email:    email,
		Password: password,
	}
	identity, err := s.provider.Authenticate(ctx, req)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Issue tokens
	tokenPair, err := s.issueTokens(ctx, identity.UserID, identity.Email)
	if err != nil {
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	return &LoginResult{
		UserID:    identity.UserID,
		Email:     identity.Email,
		TokenPair: tokenPair,
	}, nil
}

// Refresh exchanges a refresh token for a new token pair.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*entity.TokenPair, error) {
	// Hash for lookup
	hash := token.HashToken(refreshToken)

	// Retrieve stored token
	rt, err := s.tokenStore.GetRefreshToken(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	// Check if revoked
	if rt.Revoked {
		// TODO: Token reuse detection - revoke all children (requires Parent field)
		return nil, ErrTokenRevoked
	}

	// Check expiration
	if time.Now().After(rt.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Revoke old token
	if err := s.tokenStore.RevokeRefreshToken(ctx, hash); err != nil {
		return nil, fmt.Errorf("revoke old token: %w", err)
	}

	// Get current user data
	user, err := s.userStore.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Issue new tokens
	return s.issueTokens(ctx, user.ID, user.Email)
}

// Logout revokes a refresh token.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	hash := token.HashToken(refreshToken)
	return s.tokenStore.RevokeRefreshToken(ctx, hash)
}

// Verify validates an access token and returns claims.
func (s *Service) Verify(ctx context.Context, accessToken string) (*entity.Claims, error) {
	return s.issuer.ParseToken(accessToken)
}

// JWKS returns the JSON Web Key Set for public key verification.
func (s *Service) JWKS() *jose.JSONWebKeySet {
	return s.issuer.JWKS()
}

// issueTokens generates tokens and saves refresh token to store.
func (s *Service) issueTokens(ctx context.Context, userID, email string) (*entity.TokenPair, error) {
	// Generate tokens
	tokenPair, refreshHash, err := s.issuer.GenerateTokens(userID, email)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	// Save refresh token
	rt := &entity.RefreshToken{
		Hash:      refreshHash,
		UserID:    userID,
		ExpiresAt: time.Now().Add(token.RefreshTokenTTL),
		CreatedAt: time.Now(),
		Revoked:   false,
	}
	if err := s.tokenStore.SaveRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	return tokenPair, nil
}
