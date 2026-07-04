package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/store"
	"github.com/foxcool/psina/pkg/token"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// Ensure token.Issuer implements TokenIssuer interface.
var _ TokenIssuer = (*token.Issuer)(nil)

// Service errors.
var (
	ErrUserNotFound          = errors.New("user not found")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserExists            = errors.New("user already exists")
	ErrTokenRevoked          = errors.New("refresh token revoked")
	ErrTokenExpired          = errors.New("refresh token expired")
	ErrTokenReuse            = errors.New("refresh token reuse detected")
	ErrPATDisabled           = errors.New("personal access tokens are disabled")
	ErrPATLimitReached       = errors.New("personal access token limit reached")
	ErrPATNameRequired       = errors.New("personal access token name is required")
	ErrPATNameTooLong        = errors.New("personal access token name is too long")
	ErrPATExpiryInvalid      = errors.New("personal access token expiry is invalid")
	ErrProviderNotConfigured = errors.New("no provider configured for request")
)

// PAT defaults (applied by WithPAT for zero-value PATConfig fields).
const (
	DefaultPATMaxPerUser    = 50
	DefaultPATTouchInterval = time.Minute
	maxPATNameLength        = 100
)

// PATConfig tunes personal access token behavior.
type PATConfig struct {
	// MaxPerUser limits how many PATs a user may hold. 0 = default, -1 = unlimited.
	MaxPerUser int
	// MaxTTL caps the lifetime of a new PAT. 0 = unlimited.
	MaxTTL time.Duration
	// TouchInterval throttles last-used updates on Verify.
	// 0 = default, -1 = update on every verification.
	TouchInterval time.Duration
}

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
	// providers is keyed by Provider.Type(); wallet/oauth RPCs dispatch through it.
	providers map[string]Provider
	// localProvider handles the password Register/Login path; nil if not registered.
	localProvider Provider

	tokenStore TokenStore
	userStore  UserStore
	issuer     TokenIssuer

	// PAT support is optional; nil patStore means the feature is disabled.
	patStore  PATStore
	patConfig PATConfig
}

// ServiceOption configures the Service.
type ServiceOption func(*Service)

// WithPAT enables personal access tokens. Zero-value config fields fall back
// to defaults (DefaultPATMaxPerUser, DefaultPATTouchInterval, unlimited TTL).
func WithPAT(store PATStore, cfg PATConfig) ServiceOption {
	if cfg.MaxPerUser == 0 {
		cfg.MaxPerUser = DefaultPATMaxPerUser
	}
	if cfg.TouchInterval == 0 {
		cfg.TouchInterval = DefaultPATTouchInterval
	}
	return func(s *Service) {
		s.patStore = store
		s.patConfig = cfg
	}
}

// NewService creates a new authentication service. providers must contain at
// least one Provider; they are indexed by Type() into the registry. A duplicate
// Type() is a wiring bug and panics. The local provider, if present, serves the
// password Register/Login path.
func NewService(
	tokenStore TokenStore,
	userStore UserStore,
	issuer TokenIssuer,
	providers []Provider,
	opts ...ServiceOption,
) *Service {
	registry := make(map[string]Provider, len(providers))
	for _, p := range providers {
		if _, dup := registry[p.Type()]; dup {
			panic(fmt.Sprintf("auth: duplicate provider type %q", p.Type()))
		}
		registry[p.Type()] = p
	}

	s := &Service{
		providers:     registry,
		localProvider: registry[entity.ProviderTypeLocal],
		tokenStore:    tokenStore,
		userStore:     userStore,
		issuer:        issuer,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// provider returns the registered provider for a type.
func (s *Service) provider(t string) (Provider, bool) {
	p, ok := s.providers[t]
	return p, ok
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

	if s.localProvider == nil {
		return nil, ErrProviderNotConfigured
	}

	// Register with provider (creates user and stores credentials)
	req := &entity.RegisterRequest{
		Email:    email,
		Password: password,
	}
	identity, err := s.localProvider.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	// Issue tokens (new session, no parent; fresh users have no roles)
	tokenPair, err := s.issueTokens(ctx, identity.UserID, identity.Email, nil, "")
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
	if s.localProvider == nil {
		return nil, ErrProviderNotConfigured
	}

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
	identity, err := s.localProvider.Authenticate(ctx, req)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Load the user to pick up roles for the JWT
	user, err := s.userStore.GetByID(ctx, identity.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Issue tokens (new session, no parent)
	tokenPair, err := s.issueTokens(ctx, identity.UserID, identity.Email, user.Roles, "")
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

	return s.issueTokens(ctx, user.ID, user.Email, user.Roles, parent)
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
	if s.patStore == nil {
		return nil, ErrInvalidCredentials
	}

	pat, err := s.patStore.GetPAT(ctx, token.HashToken(accessToken))
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if pat.ExpiresAt != nil && time.Now().After(*pat.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	user, err := s.userStore.GetByID(ctx, pat.UserID)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Best-effort, throttled last-used tracking; never fail verification on it.
	if s.patConfig.TouchInterval < 0 ||
		pat.LastUsedAt == nil ||
		time.Since(*pat.LastUsedAt) >= s.patConfig.TouchInterval {
		_ = s.patStore.TouchPAT(ctx, pat.Hash, time.Now())
	}

	return &entity.Claims{
		UserID: user.ID,
		Email:  user.Email,
		Roles:  user.Roles,
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
	if s.patStore == nil {
		return nil, ErrPATDisabled
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrPATNameRequired
	}
	if len(name) > maxPATNameLength {
		return nil, ErrPATNameTooLong
	}

	now := time.Now()
	if expiresAt != nil {
		if !expiresAt.After(now) {
			return nil, fmt.Errorf("%w: expiry is in the past", ErrPATExpiryInvalid)
		}
		if s.patConfig.MaxTTL > 0 && expiresAt.Sub(now) > s.patConfig.MaxTTL {
			return nil, fmt.Errorf("%w: expiry exceeds max ttl %s", ErrPATExpiryInvalid, s.patConfig.MaxTTL)
		}
	} else if s.patConfig.MaxTTL > 0 {
		return nil, fmt.Errorf("%w: expiry is required (max ttl %s)", ErrPATExpiryInvalid, s.patConfig.MaxTTL)
	}

	if s.patConfig.MaxPerUser > 0 {
		existing, err := s.patStore.ListPATs(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("list pats: %w", err)
		}
		if len(existing) >= s.patConfig.MaxPerUser {
			return nil, ErrPATLimitReached
		}
	}

	plaintext, hash, err := token.GeneratePAT()
	if err != nil {
		return nil, fmt.Errorf("generate pat: %w", err)
	}

	pat := &entity.PersonalAccessToken{
		ID:        uuid.NewString(),
		Hash:      hash,
		UserID:    userID,
		Name:      name,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := s.patStore.SavePAT(ctx, pat); err != nil {
		return nil, fmt.Errorf("save pat: %w", err)
	}

	return &PATResult{Plaintext: plaintext, Token: pat}, nil
}

// ListPATs returns a user's personal access tokens (metadata only, no secrets).
func (s *Service) ListPATs(ctx context.Context, userID string) ([]*entity.PersonalAccessToken, error) {
	if s.patStore == nil {
		return nil, ErrPATDisabled
	}
	return s.patStore.ListPATs(ctx, userID)
}

// RevokePAT deletes a personal access token (by its UUID) owned by the user.
func (s *Service) RevokePAT(ctx context.Context, userID, id string) error {
	if s.patStore == nil {
		return ErrPATDisabled
	}
	return s.patStore.DeletePAT(ctx, userID, id)
}

// JWKS returns the JSON Web Key Set for public key verification.
func (s *Service) JWKS() *jose.JSONWebKeySet {
	return s.issuer.JWKS()
}

// issueTokens generates tokens and saves refresh token to store.
// parent is empty for new sessions, or contains the family root hash for refreshed tokens.
func (s *Service) issueTokens(ctx context.Context, userID, email string, roles []string, parent string) (*entity.TokenPair, error) {
	tokenPair, refreshHash, err := s.issuer.GenerateTokens(userID, email, roles)
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
