//go:build integration

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/local"
	"github.com/foxcool/psina/store/postgres"
	"github.com/foxcool/psina/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// claimAfterPasswordCheck is the local provider with a takeover committed
// right after a successful password check or registration, before the
// session is saved.
type claimAfterPasswordCheck struct {
	auth.Provider
	claim func(ctx context.Context, userID string)
}

func (c *claimAfterPasswordCheck) Register(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error) {
	identity, err := c.Provider.Register(ctx, req)
	if err == nil && c.claim != nil {
		c.claim(ctx, identity.UserID)
	}
	return identity, err
}

func (c *claimAfterPasswordCheck) Authenticate(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error) {
	identity, err := c.Provider.Authenticate(ctx, req)
	if err == nil && c.claim != nil {
		c.claim(ctx, identity.UserID)
	}
	return identity, err
}

// Same race as TestTakeover_LoginRacingClaimRefused, against postgres.
func TestIntegration_LoginRacingClaimRefused(t *testing.T) {
	ctx := context.Background()
	testDB.MustTruncate(t)
	store := postgres.New(testDB.Pool)
	provider := &claimAfterPasswordCheck{Provider: local.New(store, store)}
	issuer, err := token.New()
	require.NoError(t, err)
	svc := auth.NewService(store, store, issuer, []auth.Provider{provider},
		auth.WithClock(func() time.Time { return time.Now().Add(time.Hour) }))

	reg, err := svc.Register(ctx, "squat@example.com", "SecurePassword123!")
	require.NoError(t, err)
	provider.claim = func(ctx context.Context, userID string) {
		epoch, err := store.ClaimAccountWithOAuthIdentity(ctx, &entity.OAuthIdentity{
			ID: "00000000-0000-0000-0000-000000000001", UserID: userID,
			Provider: entity.ProviderTypeGoogle, ExternalID: "sub-1",
		})
		require.NoError(t, err)
		require.NotNil(t, epoch)
	}

	_, err = svc.Login(ctx, "squat@example.com", "SecurePassword123!")
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)

	var live int
	require.NoError(t, testDB.Pool.QueryRow(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND ended_at IS NULL`, reg.UserID).Scan(&live))
	assert.Zero(t, live, "no session of the password holder survives")
}

// Register's password is saved, the takeover commits, then the session is
// saved: the registrant gets no session.
func TestIntegration_RegisterRacingClaimRefused(t *testing.T) {
	ctx := context.Background()
	testDB.MustTruncate(t)
	store := postgres.New(testDB.Pool)
	provider := &claimAfterPasswordCheck{Provider: local.New(store, store)}
	issuer, err := token.New()
	require.NoError(t, err)
	svc := auth.NewService(store, store, issuer, []auth.Provider{provider})
	var userID string
	provider.claim = func(ctx context.Context, id string) {
		userID = id
		epoch, err := store.ClaimAccountWithOAuthIdentity(ctx, &entity.OAuthIdentity{
			ID: "00000000-0000-0000-0000-000000000002", UserID: id,
			Provider: entity.ProviderTypeGoogle, ExternalID: "sub-2",
		})
		require.NoError(t, err)
		require.NotNil(t, epoch)
	}

	_, err = svc.Register(ctx, "squat2@example.com", "SecurePassword123!")
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)

	var live int
	require.NoError(t, testDB.Pool.QueryRow(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND ended_at IS NULL`, userID).Scan(&live))
	assert.Zero(t, live, "no session of the registrant survives")
}
