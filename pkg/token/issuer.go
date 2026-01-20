package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/foxcool/psina/pkg/psina"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour
	JWTAlgorithm    = jose.RS256
	JWTIssuer       = "psina"
	KeyID           = "psina-key-1"
)

// Issuer implements psina.TokenIssuer using RS256 JWT.
type Issuer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	signer     jose.Signer
	jwks       *jose.JSONWebKeySet
	tokenStore psina.TokenStore
	userStore  psina.UserStore
}

// customClaims extends jwt.Claims with custom fields.
type customClaims struct {
	jwt.Claims
	Email string `json:"email"`
}

// New creates a new Issuer with generated RSA keys.
func New(tokenStore psina.TokenStore, userStore psina.UserStore) (*Issuer, error) {
	// Generate RSA-2048 key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	return NewWithKey(privateKey, tokenStore, userStore)
}

// NewWithKey creates an Issuer with an existing private key.
func NewWithKey(privateKey *rsa.PrivateKey, tokenStore psina.TokenStore, userStore psina.UserStore) (*Issuer, error) {
	publicKey := &privateKey.PublicKey

	// Create signer for JWT
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: JWTAlgorithm, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", KeyID),
	)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	// Create JWKS
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       publicKey,
				KeyID:     KeyID,
				Algorithm: string(JWTAlgorithm),
				Use:       "sig",
			},
		},
	}

	return &Issuer{
		privateKey: privateKey,
		publicKey:  publicKey,
		signer:     signer,
		jwks:       jwks,
		tokenStore: tokenStore,
		userStore:  userStore,
	}, nil
}

// Issue generates a new token pair for an authenticated identity.
func (i *Issuer) Issue(ctx context.Context, identity *psina.Identity) (*psina.TokenPair, error) {
	now := time.Now()
	expiresAt := now.Add(AccessTokenTTL)

	// Generate unique JWT ID
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)

	// Build JWT claims
	claims := customClaims{
		Claims: jwt.Claims{
			ID:        jti,
			Subject:   identity.UserID,
			Issuer:    JWTIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
		Email: identity.Email,
	}

	// Sign access token
	accessToken, err := jwt.Signed(i.signer).Claims(claims).Serialize()
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	// Generate refresh token (random bytes)
	refreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	refreshToken := base64.RawURLEncoding.EncodeToString(refreshTokenBytes)

	// Hash refresh token for storage
	hash := hashToken(refreshToken)

	// Save refresh token
	rt := &psina.RefreshToken{
		Hash:      hash,
		UserID:    identity.UserID,
		ExpiresAt: now.Add(RefreshTokenTTL),
		CreatedAt: now,
		Revoked:   false,
	}
	if err := i.tokenStore.SaveRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	return &psina.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(AccessTokenTTL.Seconds()),
	}, nil
}

// Validate verifies an access token and returns its claims.
func (i *Issuer) Validate(ctx context.Context, accessToken string) (*psina.Claims, error) {
	// Parse and verify token
	tok, err := jwt.ParseSigned(accessToken, []jose.SignatureAlgorithm{JWTAlgorithm})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	// Extract claims
	var claims customClaims
	if err := tok.Claims(i.publicKey, &claims); err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// Validate standard claims
	if err := claims.Validate(jwt.Expected{
		Issuer: JWTIssuer,
		Time:   time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("validate claims: %w", err)
	}

	return &psina.Claims{
		UserID: claims.Subject,
		Email:  claims.Email,
		Issuer: claims.Issuer,
		Exp:    claims.Expiry.Time().Unix(),
		Iat:    claims.IssuedAt.Time().Unix(),
	}, nil
}

// Refresh generates a new token pair using a refresh token.
func (i *Issuer) Refresh(ctx context.Context, refreshToken string) (*psina.TokenPair, error) {
	// Hash the provided refresh token
	hash := hashToken(refreshToken)

	// Retrieve stored refresh token
	rt, err := i.tokenStore.GetRefreshToken(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	// Validate refresh token
	if rt.Revoked {
		return nil, fmt.Errorf("refresh token revoked")
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}

	// Lookup user to get current email
	user, err := i.userStore.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Revoke old refresh token
	if err := i.tokenStore.RevokeRefreshToken(ctx, hash); err != nil {
		return nil, fmt.Errorf("revoke old token: %w", err)
	}

	// Issue new token pair
	identity := &psina.Identity{
		UserID: user.ID,
		Email:  user.Email,
	}

	return i.Issue(ctx, identity)
}

// JWKS returns the JSON Web Key Set for public key verification.
func (i *Issuer) JWKS() *jose.JSONWebKeySet {
	return i.jwks
}

// hashToken creates a SHA256 hash of a token for secure storage.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
