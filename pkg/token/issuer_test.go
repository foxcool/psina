package token_test

import (
	"testing"

	"github.com/foxcool/psina/pkg/token"
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

func TestIssuer_JWKS(t *testing.T) {
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
