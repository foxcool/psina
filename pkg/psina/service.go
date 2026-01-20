package psina

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Service errors.
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
)

// Service orchestrates authentication operations.
type Service struct {
	provider    Provider
	tokenStore  TokenStore
	tokenIssuer TokenIssuer
}

// NewService creates a new authentication service.
func NewService(
	provider Provider,
	tokenStore TokenStore,
	tokenIssuer TokenIssuer,
) *Service {
	return &Service{
		provider:    provider,
		tokenStore:  tokenStore,
		tokenIssuer: tokenIssuer,
	}
}

// RegisterResult contains registration result.
type RegisterResult struct {
	UserID    string
	Email     string
	TokenPair *TokenPair
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
	req := &RegisterRequest{
		Email:    email,
		Password: password,
	}
	identity, err := s.provider.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	// Issue tokens
	tokenPair, err := s.tokenIssuer.Issue(ctx, identity)
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
	TokenPair *TokenPair
}

// Login authenticates a user and returns tokens.
func (s *Service) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	// Normalize email (don't expose validation errors for security)
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Authenticate with provider
	req := &AuthRequest{
		Email:    email,
		Password: password,
	}
	identity, err := s.provider.Authenticate(ctx, req)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Issue tokens
	tokenPair, err := s.tokenIssuer.Issue(ctx, identity)
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
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	return s.tokenIssuer.Refresh(ctx, refreshToken)
}

// Logout revokes a refresh token.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	hash := hashToken(refreshToken)
	return s.tokenStore.RevokeRefreshToken(ctx, hash)
}

// Verify validates an access token and returns claims.
func (s *Service) Verify(ctx context.Context, accessToken string) (*Claims, error) {
	return s.tokenIssuer.Validate(ctx, accessToken)
}

// JWKS returns the JSON Web Key Set for public key verification.
func (s *Service) JWKS() interface{} {
	return s.tokenIssuer.JWKS()
}

// hashToken creates a SHA256 hash for secure token storage.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
