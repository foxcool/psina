package auth

import (
	"context"
	"testing"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/store/memory"
	"github.com/foxcool/psina/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedUser inserts a user directly into the store so PAT verification (which
// loads the user) has something to resolve.
func seedUser(t *testing.T, store *memory.Store) *entity.User {
	t.Helper()
	user := &entity.User{ID: "user-pat-1", Email: "pat@example.com"}
	require.NoError(t, store.Create(context.Background(), user))
	return user
}

func TestService_CreateAndVerifyPAT(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	user := seedUser(t, store)

	res, err := service.CreatePAT(ctx, user.ID, "ci", []string{"eye:read"}, nil)
	require.NoError(t, err)
	assert.Contains(t, res.Plaintext, token.PATPrefix)
	assert.Equal(t, "ci", res.Token.Name)
	assert.Equal(t, []string{"eye:read"}, res.Token.Scopes)

	claims, err := service.Verify(ctx, res.Plaintext)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Email, claims.Email)
}

func TestService_VerifyPAT_Invalid(t *testing.T) {
	service, _ := setupTestService(t)

	_, err := service.Verify(context.Background(), token.PATPrefix+"bogus")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestService_VerifyPAT_Expired(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	user := seedUser(t, store)

	past := time.Now().Add(-time.Hour)
	res, err := service.CreatePAT(ctx, user.ID, "expired", nil, &past)
	require.NoError(t, err)

	_, err = service.Verify(ctx, res.Plaintext)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestService_ListAndRevokePAT(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	user := seedUser(t, store)

	a, err := service.CreatePAT(ctx, user.ID, "a", nil, nil)
	require.NoError(t, err)
	_, err = service.CreatePAT(ctx, user.ID, "b", nil, nil)
	require.NoError(t, err)

	pats, err := service.ListPATs(ctx, user.ID)
	require.NoError(t, err)
	assert.Len(t, pats, 2)

	// Revoke one; it stops verifying, the other still works.
	require.NoError(t, service.RevokePAT(ctx, user.ID, a.Token.Hash))
	_, err = service.Verify(ctx, a.Plaintext)
	assert.ErrorIs(t, err, ErrInvalidCredentials)

	pats, err = service.ListPATs(ctx, user.ID)
	require.NoError(t, err)
	assert.Len(t, pats, 1)
}

func TestService_RevokePAT_WrongOwner(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	user := seedUser(t, store)

	res, err := service.CreatePAT(ctx, user.ID, "a", nil, nil)
	require.NoError(t, err)

	err = service.RevokePAT(ctx, "someone-else", res.Token.Hash)
	assert.Error(t, err)

	// Still valid for the real owner.
	_, err = service.Verify(ctx, res.Plaintext)
	require.NoError(t, err)
}

// TestService_Verify_JWTPathUnchanged ensures adding the PAT branch did not
// break access-token verification.
func TestService_Verify_JWTPathUnchanged(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	user := seedUser(t, store)

	pair, _, err := service.issuer.GenerateTokens(user.ID, user.Email)
	require.NoError(t, err)

	claims, err := service.Verify(ctx, pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
}
