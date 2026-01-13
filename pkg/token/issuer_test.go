package token_test

import (
	"context"
	"testing"

	"github.com/foxcool/psina/pkg/psina"
	"github.com/foxcool/psina/pkg/store/memory"
	"github.com/foxcool/psina/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuer_Issue(t *testing.T) {
	store := memory.New()
	issuer, err := token.New(store)
	require.NoError(t, err)

	identity := &psina.Identity{
		UserID:   "user-123",
		Email:    "test@example.com",
		Provider: "local",
	}

	// Issue token pair
	pair, err := issuer.Issue(context.Background(), identity)
	require.NoError(t, err)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.Equal(t, int64(900), pair.ExpiresIn) // 15 minutes
}

func TestIssuer_Validate(t *testing.T) {
	store := memory.New()
	issuer, err := token.New(store)
	require.NoError(t, err)

	identity := &psina.Identity{
		UserID:   "user-123",
		Email:    "test@example.com",
		Provider: "local",
	}

	// Issue token
	pair, err := issuer.Issue(context.Background(), identity)
	require.NoError(t, err)

	// Validate token
	claims, err := issuer.Validate(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, identity.UserID, claims.UserID)
	assert.Equal(t, identity.Email, claims.Email)
	assert.Equal(t, "psina", claims.Issuer)
}

func TestIssuer_Refresh(t *testing.T) {
	store := memory.New()
	issuer, err := token.New(store)
	require.NoError(t, err)

	identity := &psina.Identity{
		UserID:   "user-123",
		Email:    "test@example.com",
		Provider: "local",
	}

	// Issue initial token pair
	pair1, err := issuer.Issue(context.Background(), identity)
	require.NoError(t, err)

	// Refresh tokens
	pair2, err := issuer.Refresh(context.Background(), pair1.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, pair2.AccessToken)
	assert.NotEmpty(t, pair2.RefreshToken)
	assert.NotEqual(t, pair1.AccessToken, pair2.AccessToken)
	assert.NotEqual(t, pair1.RefreshToken, pair2.RefreshToken)

	// Old refresh token should be revoked
	_, err = issuer.Refresh(context.Background(), pair1.RefreshToken)
	assert.Error(t, err)
}

func TestIssuer_JWKS(t *testing.T) {
	store := memory.New()
	issuer, err := token.New(store)
	require.NoError(t, err)

	jwks := issuer.JWKS()
	require.NotNil(t, jwks)
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "psina-key-1", jwks.Keys[0].KeyID)
	assert.Equal(t, "RS256", jwks.Keys[0].Algorithm)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
}

func TestIssuer_ValidateExpiredToken(t *testing.T) {
	// This test would require mocking time or waiting for token expiration
	// Skipped for MVP - can be added with time mocking library
	t.Skip("Token expiration testing requires time mocking")
}
