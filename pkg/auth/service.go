package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/token"
	"github.com/go-jose/go-jose/v4"
)

// Ensure token.Issuer implements TokenIssuer interface.
var _ TokenIssuer = (*token.Issuer)(nil)

// Service errors.
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrTokenRevoked       = errors.New("refresh token revoked")
	ErrTokenExpired       = errors.New("refresh token expired")
	ErrTokenReuse         = errors.New("refresh token reuse detected")
)

// TokenReuseError contains user context for security logging.
type TokenReuseError struct {
	UserID string
}

func (e *TokenReuseError) Error() string {
	return "refresh token reuse detected"
}

func (e *TokenReuseError) Is(target error) bool {
	return target == ErrTokenReuse
}

// Service orchestrates authentication operations.
type Service struct {
	provider   Provider
	tokenStore TokenStore
	userStore  UserStore
	patStore   PATStore
	issuer     TokenIssuer
}

// NewService creates a new authentication service.
func NewService(
	provider Provider,
	tokenStore TokenStore,
	userStore UserStore,
	patStore PATStore,
	issuer TokenIssuer,
) *Service {
	return &Service{
		provider:   provider,
		tokenStore: tokenStore,
		userStore:  userStore,
		patStore:   patStore,
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

	// Issue tokens (new session, no parent)
	tokenPair, err := s.issueTokens(ctx, identity.UserID, identity.Email, "")
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

	// Issue tokens (new session, no parent)
	tokenPair, err := s.issueTokens(ctx, identity.UserID, identity.Email, "")
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
	hash := token.HashToken(refreshToken)

	rt, err := s.tokenStore.GetRefreshToken(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	// Token reuse detection — revoke entire family
	if rt.Revoked {
		familyRoot := rt.Parent
		if familyRoot == "" {
			familyRoot = rt.Hash
		}
		_ = s.tokenStore.RevokeTokens(ctx, familyRoot)
		return nil, &TokenReuseError{UserID: rt.UserID}
	}

	if time.Now().After(rt.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Revoke current token (children have parent=root, not parent=current)
	_ = s.tokenStore.RevokeTokens(ctx, hash)

	user, err := s.userStore.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Preserve family root for new token
	parent := rt.Parent
	if parent == "" {
		parent = rt.Hash
	}

	return s.issueTokens(ctx, user.ID, user.Email, parent)
}

// Logout revokes a refresh token and its family.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	hash := token.HashToken(refreshToken)
	return s.tokenStore.RevokeTokens(ctx, hash)
}

// Verify validates a credential and returns claims. It accepts both short-lived
// access JWTs and opaque personal access tokens (distinguished by prefix).
func (s *Service) Verify(ctx context.Context, accessToken string) (*entity.Claims, error) {
	if strings.HasPrefix(accessToken, token.PATPrefix) {
		return s.verifyPAT(ctx, accessToken)
	}
	return s.issuer.ParseToken(accessToken)
}

// verifyPAT validates an opaque personal access token via DB lookup.
func (s *Service) verifyPAT(ctx context.Context, accessToken string) (*entity.Claims, error) {
	pat, err := s.patStore.GetPAT(ctx, token.HashToken(accessToken))
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if pat.ExpiresAt != nil && time.Now().After(*pat.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	user, err := s.userStore.GetByID(ctx, pat.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Best-effort last-used tracking; never fail verification on it.
	_ = s.patStore.TouchPAT(ctx, pat.Hash, time.Now())

	return &entity.Claims{
		UserID: user.ID,
		Email:  user.Email,
		Issuer: token.JWTIssuer,
	}, nil
}

// PATResult is a created personal access token. Plaintext is present only at
// creation time and is never persisted.
type PATResult struct {
	Plaintext string
	Token     *entity.PersonalAccessToken
}

// CreatePAT mints a personal access token for a user.
func (s *Service) CreatePAT(ctx context.Context, userID, name string, scopes []string, expiresAt *time.Time) (*PATResult, error) {
	plaintext, hash, err := token.GeneratePAT()
	if err != nil {
		return nil, fmt.Errorf("generate pat: %w", err)
	}

	pat := &entity.PersonalAccessToken{
		Hash:      hash,
		UserID:    userID,
		Name:      name,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	if err := s.patStore.SavePAT(ctx, pat); err != nil {
		return nil, fmt.Errorf("save pat: %w", err)
	}

	return &PATResult{Plaintext: plaintext, Token: pat}, nil
}

// ListPATs returns a user's personal access tokens (metadata only, no secrets).
func (s *Service) ListPATs(ctx context.Context, userID string) ([]*entity.PersonalAccessToken, error) {
	return s.patStore.ListPATs(ctx, userID)
}

// RevokePAT deletes a personal access token owned by the user.
func (s *Service) RevokePAT(ctx context.Context, userID, hash string) error {
	return s.patStore.DeletePAT(ctx, userID, hash)
}

// JWKS returns the JSON Web Key Set for public key verification.
func (s *Service) JWKS() *jose.JSONWebKeySet {
	return s.issuer.JWKS()
}

// issueTokens generates tokens and saves refresh token to store.
// parent is empty for new sessions, or contains the family root hash for refreshed tokens.
func (s *Service) issueTokens(ctx context.Context, userID, email, parent string) (*entity.TokenPair, error) {
	tokenPair, refreshHash, err := s.issuer.GenerateTokens(userID, email)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	rt := &entity.RefreshToken{
		Hash:      refreshHash,
		UserID:    userID,
		Parent:    parent,
		ExpiresAt: time.Now().Add(token.RefreshTokenTTL),
		CreatedAt: time.Now(),
		Revoked:   false,
	}
	if err := s.tokenStore.SaveRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	return tokenPair, nil
}
