package auth

import (
	"context"
	"strings"
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

// setupPATService builds a service with a custom PAT config over a fresh
// memory store.
func setupPATService(t *testing.T, cfg PATConfig) (*Service, *memory.Store) {
	t.Helper()
	memStore := newMemStore(t)
	issuer, err := token.New()
	require.NoError(t, err)
	service := NewService(&mockProvider{}, memStore, memStore, issuer, WithPAT(memStore, cfg))
	return service, memStore
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
	assert.NotEmpty(t, res.Token.ID)

	claims, err := service.Verify(ctx, res.Plaintext)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Email, claims.Email)
}

func TestService_CreatePAT_Validation(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	user := seedUser(t, store)

	t.Run("empty name", func(t *testing.T) {
		_, err := service.CreatePAT(ctx, user.ID, "  ", nil, nil)
		assert.ErrorIs(t, err, ErrPATNameRequired)
	})

	t.Run("name too long", func(t *testing.T) {
		_, err := service.CreatePAT(ctx, user.ID, strings.Repeat("x", maxPATNameLength+1), nil, nil)
		assert.ErrorIs(t, err, ErrPATNameTooLong)
	})

	t.Run("expiry in the past", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		_, err := service.CreatePAT(ctx, user.ID, "stale", nil, &past)
		assert.ErrorIs(t, err, ErrPATExpiryInvalid)
	})
}

func TestService_CreatePAT_MaxTTL(t *testing.T) {
	service, store := setupPATService(t, PATConfig{MaxTTL: time.Hour})
	ctx := context.Background()
	user := seedUser(t, store)

	// Beyond the cap.
	tooFar := time.Now().Add(2 * time.Hour)
	_, err := service.CreatePAT(ctx, user.ID, "long", nil, &tooFar)
	assert.ErrorIs(t, err, ErrPATExpiryInvalid)

	// No expiry at all is also rejected when MaxTTL is set.
	_, err = service.CreatePAT(ctx, user.ID, "forever", nil, nil)
	assert.ErrorIs(t, err, ErrPATExpiryInvalid)

	// Within the cap.
	ok := time.Now().Add(30 * time.Minute)
	_, err = service.CreatePAT(ctx, user.ID, "short", nil, &ok)
	require.NoError(t, err)
}

func TestService_CreatePAT_LimitReached(t *testing.T) {
	service, store := setupPATService(t, PATConfig{MaxPerUser: 2})
	ctx := context.Background()
	user := seedUser(t, store)

	_, err := service.CreatePAT(ctx, user.ID, "a", nil, nil)
	require.NoError(t, err)
	_, err = service.CreatePAT(ctx, user.ID, "b", nil, nil)
	require.NoError(t, err)

	_, err = service.CreatePAT(ctx, user.ID, "c", nil, nil)
	assert.ErrorIs(t, err, ErrPATLimitReached)
}

func TestService_PATDisabled(t *testing.T) {
	memStore := newMemStore(t)
	issuer, err := token.New()
	require.NoError(t, err)
	service := NewService(&mockProvider{}, memStore, memStore, issuer) // no WithPAT
	ctx := context.Background()

	_, err = service.CreatePAT(ctx, "u1", "ci", nil, nil)
	assert.ErrorIs(t, err, ErrPATDisabled)

	_, err = service.ListPATs(ctx, "u1")
	assert.ErrorIs(t, err, ErrPATDisabled)

	err = service.RevokePAT(ctx, "u1", "some-id")
	assert.ErrorIs(t, err, ErrPATDisabled)

	// A psn_-prefixed credential must not fall through to the JWT path.
	_, err = service.Verify(ctx, token.PATPrefix+"whatever")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
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

	// CreatePAT rejects past expiry, so seed an expired token directly.
	plaintext, hash, err := token.GeneratePAT()
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour)
	require.NoError(t, store.SavePAT(ctx, &entity.PersonalAccessToken{
		ID:        "pat-expired",
		Hash:      hash,
		UserID:    user.ID,
		Name:      "expired",
		ExpiresAt: &past,
	}))

	_, err = service.Verify(ctx, plaintext)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestService_VerifyPAT_TouchThrottle(t *testing.T) {
	t.Run("default interval skips rapid touches", func(t *testing.T) {
		service, store := setupPATService(t, PATConfig{}) // TouchInterval = 1m default
		ctx := context.Background()
		user := seedUser(t, store)

		res, err := service.CreatePAT(ctx, user.ID, "ci", nil, nil)
		require.NoError(t, err)

		_, err = service.Verify(ctx, res.Plaintext)
		require.NoError(t, err)
		first, err := store.GetPAT(ctx, res.Token.Hash)
		require.NoError(t, err)
		require.NotNil(t, first.LastUsedAt)

		// Second verify within the interval must not move last_used_at.
		_, err = service.Verify(ctx, res.Plaintext)
		require.NoError(t, err)
		second, err := store.GetPAT(ctx, res.Token.Hash)
		require.NoError(t, err)
		assert.True(t, second.LastUsedAt.Equal(*first.LastUsedAt))
	})

	t.Run("interval -1 touches every verify", func(t *testing.T) {
		service, store := setupPATService(t, PATConfig{TouchInterval: -1})
		ctx := context.Background()
		user := seedUser(t, store)

		res, err := service.CreatePAT(ctx, user.ID, "ci", nil, nil)
		require.NoError(t, err)

		_, err = service.Verify(ctx, res.Plaintext)
		require.NoError(t, err)
		first, err := store.GetPAT(ctx, res.Token.Hash)
		require.NoError(t, err)
		require.NotNil(t, first.LastUsedAt)

		_, err = service.Verify(ctx, res.Plaintext)
		require.NoError(t, err)
		second, err := store.GetPAT(ctx, res.Token.Hash)
		require.NoError(t, err)
		assert.True(t, second.LastUsedAt.After(*first.LastUsedAt))
	})
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

	// Revoke one by its UUID; it stops verifying, the other still works.
	require.NoError(t, service.RevokePAT(ctx, user.ID, a.Token.ID))
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

	err = service.RevokePAT(ctx, "someone-else", res.Token.ID)
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
