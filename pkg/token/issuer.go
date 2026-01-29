package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour
	JWTIssuer       = "psina"
	KeyID           = "psina-key-1"
	// ClockSkewTolerance allows for clock drift between servers.
	ClockSkewTolerance = 30 * time.Second
)

// Algorithm represents supported JWT signing algorithms.
type Algorithm string

const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
)

// Issuer handles JWT cryptography operations.
// Does NOT handle storage - that's the service's responsibility.
type Issuer struct {
	algorithm  jose.SignatureAlgorithm
	privateKey crypto.Signer
	publicKey  crypto.PublicKey
	signer     jose.Signer
	jwks       *jose.JSONWebKeySet
}

// customClaims extends jwt.Claims with custom fields.
type customClaims struct {
	jwt.Claims
	Email string `json:"email"`
}

// New creates a new Issuer with generated keys (dev only).
// Uses RS256 by default.
func New() (*Issuer, error) {
	return NewWithAlgorithm(RS256)
}

// NewWithAlgorithm creates a new Issuer with generated keys for the specified algorithm.
func NewWithAlgorithm(alg Algorithm) (*Issuer, error) {
	switch alg {
	case ES256:
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ECDSA key: %w", err)
		}
		return NewWithECDSAKey(privateKey)
	case RS256:
		fallthrough
	default:
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate RSA key: %w", err)
		}
		return NewWithRSAKey(privateKey)
	}
}

// NewWithRSAKey creates an Issuer with an existing RSA private key (RS256).
func NewWithRSAKey(privateKey *rsa.PrivateKey) (*Issuer, error) {
	return newIssuer(jose.RS256, privateKey, &privateKey.PublicKey)
}

// NewWithECDSAKey creates an Issuer with an existing ECDSA private key (ES256).
func NewWithECDSAKey(privateKey *ecdsa.PrivateKey) (*Issuer, error) {
	return newIssuer(jose.ES256, privateKey, &privateKey.PublicKey)
}

// NewWithKey creates an Issuer with an existing RSA private key (production).
// Deprecated: Use NewWithRSAKey instead.
func NewWithKey(privateKey *rsa.PrivateKey) (*Issuer, error) {
	return NewWithRSAKey(privateKey)
}

// newIssuer creates an Issuer with the given algorithm and keys.
func newIssuer(alg jose.SignatureAlgorithm, privateKey crypto.Signer, publicKey crypto.PublicKey) (*Issuer, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", KeyID),
	)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       publicKey,
				KeyID:     KeyID,
				Algorithm: string(alg),
				Use:       "sig",
			},
		},
	}

	return &Issuer{
		algorithm:  alg,
		privateKey: privateKey,
		publicKey:  publicKey,
		signer:     signer,
		jwks:       jwks,
	}, nil
}

// Algorithm returns the signing algorithm used by this issuer.
func (i *Issuer) Algorithm() string {
	return string(i.algorithm)
}

// GenerateTokens creates access and refresh tokens.
// Returns: TokenPair, refresh token hash (for storage), error.
func (i *Issuer) GenerateTokens(userID, email string) (*entity.TokenPair, string, error) {
	now := time.Now()

	// Generate unique JWT ID
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return nil, "", fmt.Errorf("generate jti: %w", err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)

	// Build JWT claims
	claims := customClaims{
		Claims: jwt.Claims{
			ID:        jti,
			Subject:   userID,
			Issuer:    JWTIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(AccessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now.Add(-ClockSkewTolerance)),
		},
		Email: email,
	}

	// Sign access token
	accessToken, err := jwt.Signed(i.signer).Claims(claims).Serialize()
	if err != nil {
		return nil, "", fmt.Errorf("sign access token: %w", err)
	}

	// Generate refresh token (random bytes)
	refreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return nil, "", fmt.Errorf("generate refresh token: %w", err)
	}
	refreshToken := base64.RawURLEncoding.EncodeToString(refreshTokenBytes)

	// Hash for storage
	refreshHash := HashToken(refreshToken)

	return &entity.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(AccessTokenTTL.Seconds()),
	}, refreshHash, nil
}

// ParseToken validates an access token and returns claims.
func (i *Issuer) ParseToken(accessToken string) (*entity.Claims, error) {
	tok, err := jwt.ParseSigned(accessToken, []jose.SignatureAlgorithm{i.algorithm})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	var claims customClaims
	if err := tok.Claims(i.publicKey, &claims); err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer: JWTIssuer,
		Time:   time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("validate claims: %w", err)
	}

	return &entity.Claims{
		UserID: claims.Subject,
		Email:  claims.Email,
		Issuer: claims.Issuer,
		Exp:    claims.Expiry.Time().Unix(),
		Iat:    claims.IssuedAt.Time().Unix(),
	}, nil
}

// JWKS returns the JSON Web Key Set for public key verification.
func (i *Issuer) JWKS() *jose.JSONWebKeySet {
	return i.jwks
}

// HashToken creates a SHA256 hash of a token for secure storage.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
