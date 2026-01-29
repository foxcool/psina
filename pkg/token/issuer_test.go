package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/foxcool/psina/pkg/token"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuer_GenerateTokens(t *testing.T) {
	issuer, err := token.New()
	require.NoError(t, err)

	pair, hash, err := issuer.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.NotEmpty(t, hash)
	assert.Equal(t, int64(900), pair.ExpiresIn) // 15 minutes

	// Hash should match HashToken output
	assert.Equal(t, hash, token.HashToken(pair.RefreshToken))
}

func TestIssuer_ParseToken(t *testing.T) {
	issuer, err := token.New()
	require.NoError(t, err)

	pair, _, err := issuer.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	claims, err := issuer.ParseToken(pair.AccessToken)
	require.NoError(t, err)

	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, "psina", claims.Issuer)
	assert.Greater(t, claims.Exp, claims.Iat)
}

func TestIssuer_ParseToken_Invalid(t *testing.T) {
	issuer, err := token.New()
	require.NoError(t, err)

	_, err = issuer.ParseToken("invalid-token")
	assert.Error(t, err)
}

func TestIssuer_ParseToken_WrongKey(t *testing.T) {
	issuer1, err := token.New()
	require.NoError(t, err)

	issuer2, err := token.New()
	require.NoError(t, err)

	// Generate with issuer1
	pair, _, err := issuer1.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	// Verify with issuer2 should fail
	_, err = issuer2.ParseToken(pair.AccessToken)
	assert.Error(t, err)
}

func TestIssuer_JWKS_RS256(t *testing.T) {
	issuer, err := token.New()
	require.NoError(t, err)

	jwks := issuer.JWKS()
	require.NotNil(t, jwks)
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "psina-key-1", jwks.Keys[0].KeyID)
	assert.Equal(t, "RS256", jwks.Keys[0].Algorithm)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
}

func TestHashToken(t *testing.T) {
	hash1 := token.HashToken("token-123")
	hash2 := token.HashToken("token-123")
	hash3 := token.HashToken("token-456")

	// Same input = same output
	assert.Equal(t, hash1, hash2)

	// Different input = different output
	assert.NotEqual(t, hash1, hash3)

	// Hash is not empty
	assert.NotEmpty(t, hash1)
}

func TestIssuer_ParseToken_Expired(t *testing.T) {
	// Create an expired token using go-jose directly
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer, err := token.NewWithRSAKey(privateKey)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "psina-key-1"),
	)
	require.NoError(t, err)

	// Create token that expired 1 hour ago
	past := time.Now().Add(-1 * time.Hour)
	claims := jwt.Claims{
		ID:        "test-jti",
		Subject:   "user-123",
		Issuer:    "psina",
		IssuedAt:  jwt.NewNumericDate(past.Add(-15 * time.Minute)),
		Expiry:    jwt.NewNumericDate(past),
		NotBefore: jwt.NewNumericDate(past.Add(-15 * time.Minute)),
	}

	expiredToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	// ParseToken should reject expired token
	_, err = issuer.ParseToken(expiredToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validate claims")
}

func TestIssuer_ParseToken_WrongAlgorithm(t *testing.T) {
	issuer, err := token.New()
	require.NoError(t, err)

	// Create a token with HS256 (symmetric) instead of RS256
	// This should be rejected because issuer expects RS256
	key := []byte("symmetric-secret-key-32-bytes!!!")
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	claims := jwt.Claims{
		Subject: "user-123",
		Issuer:  "psina",
		Expiry:  jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
	}

	wrongAlgToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	// Should fail - wrong algorithm
	_, err = issuer.ParseToken(wrongAlgToken)
	assert.Error(t, err)
}

// --- ES256 Tests ---

func TestIssuer_ES256_GenerateTokens(t *testing.T) {
	issuer, err := token.NewWithAlgorithm(token.ES256)
	require.NoError(t, err)

	assert.Equal(t, "ES256", issuer.Algorithm())

	pair, hash, err := issuer.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.NotEmpty(t, hash)
	assert.Equal(t, int64(900), pair.ExpiresIn)
}

func TestIssuer_ES256_ParseToken(t *testing.T) {
	issuer, err := token.NewWithAlgorithm(token.ES256)
	require.NoError(t, err)

	pair, _, err := issuer.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	claims, err := issuer.ParseToken(pair.AccessToken)
	require.NoError(t, err)

	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, "psina", claims.Issuer)
}

func TestIssuer_ES256_JWKS(t *testing.T) {
	issuer, err := token.NewWithAlgorithm(token.ES256)
	require.NoError(t, err)

	jwks := issuer.JWKS()
	require.NotNil(t, jwks)
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "psina-key-1", jwks.Keys[0].KeyID)
	assert.Equal(t, "ES256", jwks.Keys[0].Algorithm)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
}

func TestIssuer_ES256_WithKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer, err := token.NewWithECDSAKey(privateKey)
	require.NoError(t, err)

	assert.Equal(t, "ES256", issuer.Algorithm())

	pair, _, err := issuer.GenerateTokens("user-456", "ec@example.com")
	require.NoError(t, err)

	claims, err := issuer.ParseToken(pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user-456", claims.UserID)
}

func TestIssuer_ES256_WrongKey(t *testing.T) {
	issuer1, err := token.NewWithAlgorithm(token.ES256)
	require.NoError(t, err)

	issuer2, err := token.NewWithAlgorithm(token.ES256)
	require.NoError(t, err)

	// Generate with issuer1
	pair, _, err := issuer1.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	// Verify with issuer2 should fail (different key)
	_, err = issuer2.ParseToken(pair.AccessToken)
	assert.Error(t, err)
}

func TestIssuer_RS256_CannotParseES256(t *testing.T) {
	rsaIssuer, err := token.NewWithAlgorithm(token.RS256)
	require.NoError(t, err)

	ecIssuer, err := token.NewWithAlgorithm(token.ES256)
	require.NoError(t, err)

	// Generate with ES256
	pair, _, err := ecIssuer.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	// RSA issuer should not parse ES256 token
	_, err = rsaIssuer.ParseToken(pair.AccessToken)
	assert.Error(t, err)
}

func TestIssuer_ES256_CannotParseRS256(t *testing.T) {
	rsaIssuer, err := token.NewWithAlgorithm(token.RS256)
	require.NoError(t, err)

	ecIssuer, err := token.NewWithAlgorithm(token.ES256)
	require.NoError(t, err)

	// Generate with RS256
	pair, _, err := rsaIssuer.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	// EC issuer should not parse RS256 token
	_, err = ecIssuer.ParseToken(pair.AccessToken)
	assert.Error(t, err)
}

// Test backward compatibility
func TestIssuer_NewWithKey_Deprecated(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// NewWithKey is deprecated but should still work
	issuer, err := token.NewWithKey(privateKey)
	require.NoError(t, err)

	assert.Equal(t, "RS256", issuer.Algorithm())

	pair, _, err := issuer.GenerateTokens("user-123", "test@example.com")
	require.NoError(t, err)

	claims, err := issuer.ParseToken(pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
}
