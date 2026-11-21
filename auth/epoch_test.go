package auth

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/api/auth/v1"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/oauth"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialEpoch(t *testing.T) {
	at := time.Unix(1_000, 400_000_000) // 1000.4 s
	epoch, never := credentialEpoch{at: &at}, credentialEpoch{}

	t.Run("access token", func(t *testing.T) {
		assert.False(t, never.tokenStale(1))
		assert.True(t, epoch.tokenStale(999), "second before")
		assert.True(t, epoch.tokenStale(1000), "same second")
		assert.False(t, epoch.tokenStale(1001), "next second")
	})

	t.Run("session start", func(t *testing.T) {
		assert.False(t, never.sessionStale(at))
		assert.True(t, epoch.sessionStale(at.Add(-time.Microsecond)))
		assert.True(t, epoch.sessionStale(at), "a tie counts as before")
		assert.False(t, epoch.sessionStale(at.Add(time.Microsecond)))
	})
}

// takeoverFixture is a password account local@example.com ("user-123", the
// mockProvider's user) whose squatter has signed in, and a service that lets a
// verified Google sign-in take it over.
type takeoverFixture struct {
	svc      *Service
	handler  *Handler
	store    *memory.Store
	squatter *entity.TokenPair
}

func newTakeoverFixture(t *testing.T, memStore *memory.Store, pats PATStore) *takeoverFixture {
	t.Helper()
	ctx := context.Background()
	google := newFakeGoogle(verifiedInfo("sub-1", "local@example.com"))
	svc := newOAuthService(t, memStore, WithOAuth([]oauth.Provider{google}, memStore, memStore, OAuthConfig{}),
		WithPAT(pats, PATConfig{}))
	require.NoError(t, memStore.Create(ctx, &entity.User{ID: "user-123", Email: "local@example.com"}))
	require.NoError(t, memStore.SavePasswordHash(ctx, "user-123", "hash"))

	login, err := svc.Login(ctx, "local@example.com", "squatter-password")
	require.NoError(t, err)
	return &takeoverFixture{svc: svc, handler: NewHandler(svc), store: memStore, squatter: login.TokenPair}
}

func (f *takeoverFixture) takeOver(t *testing.T) *OAuthCallbackResult {
	t.Helper()
	res, err := f.svc.OAuthCallback(context.Background(), startFlow(t, f.svc))
	require.NoError(t, err)
	require.True(t, res.PasswordDropped)
	return res
}

func TestTakeover_StaleAccessTokenRefused(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	f := newTakeoverFixture(t, memStore, memStore)
	owner := f.takeOver(t)

	_, err := f.handler.CreatePersonalAccessToken(ctx, createPATRequest("squatter", f.squatter.AccessToken))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "squatter cannot mint a PAT")
	list := connect.NewRequest(&authv1.ListPersonalAccessTokensRequest{})
	list.Header().Set("Authorization", "Bearer "+f.squatter.AccessToken)
	_, err = f.handler.ListPersonalAccessTokens(ctx, list)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "squatter cannot list PATs")
	pats, err := f.store.ListPATs(ctx, "user-123")
	require.NoError(t, err)
	assert.Empty(t, pats)

	// The owner's token is issued after the epoch's second: it is accepted.
	claims, err := f.svc.Verify(ctx, owner.TokenPair.AccessToken)
	require.NoError(t, err)
	user, err := f.store.GetByID(ctx, "user-123")
	require.NoError(t, err)
	require.NotNil(t, user.CredentialsChangedAt)
	assert.Greater(t, claims.Iat, user.CredentialsChangedAt.Unix())
	_, err = f.handler.CreatePersonalAccessToken(ctx, createPATRequest("owner", owner.TokenPair.AccessToken))
	require.NoError(t, err, "owner mints a PAT")
}

func TestTakeover_SessionStartedBeforeEpochRefused(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	f := newTakeoverFixture(t, memStore, memStore)
	f.takeOver(t)
	user, err := f.store.GetByID(ctx, "user-123")
	require.NoError(t, err)

	// A root that escaped the claim's revocation: saved after it, for a
	// sign-in that began before it.
	pair, hash, err := f.svc.issuer.GenerateTokens("user-123", "local@example.com", nil)
	require.NoError(t, err)
	require.NoError(t, f.store.SaveRefreshToken(ctx, &entity.RefreshToken{
		Hash: hash, UserID: "user-123", ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: user.CredentialsChangedAt.Add(-time.Millisecond),
	}))

	_, err = f.svc.Refresh(ctx, pair.RefreshToken)
	require.ErrorIs(t, err, ErrInvalidCredentials)
	assert.ErrorIs(t, err, ErrSessionEnded)
	rt, err := f.store.GetRefreshToken(ctx, hash)
	require.NoError(t, err)
	assert.NotNil(t, rt.EndedAt, "the stale session is ended")
}

// recordingTokens records the refresh token hashes saved.
type recordingTokens struct {
	*memory.Store
	saved []string
}

func (r *recordingTokens) SaveRefreshToken(ctx context.Context, rt *entity.RefreshToken) error {
	r.saved = append(r.saved, rt.Hash)
	return r.Store.SaveRefreshToken(ctx, rt)
}

// The failing order: the login reads the password, the claim commits with an
// epoch earlier than the login's own start (the service clock runs ahead of
// the store's), and only then is the session saved. Comparing times alone
// would accept both the login and later refreshes of its session.
func TestTakeover_LoginRacingClaimRefused(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	require.NoError(t, memStore.Create(ctx, &entity.User{ID: "user-123", Email: "local@example.com"}))
	require.NoError(t, memStore.SavePasswordHash(ctx, "user-123", "hash"))
	tokens := &recordingTokens{Store: memStore}
	var epoch *time.Time
	provider := &mockProvider{authenticateFn: func(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error) {
		var err error
		epoch, err = memStore.ClaimAccountWithOAuthIdentity(ctx, &entity.OAuthIdentity{
			ID: "link", UserID: "user-123", Provider: entity.ProviderTypeGoogle, ExternalID: "sub-1",
		})
		require.NoError(t, err)
		return &entity.Identity{UserID: "user-123", Email: req.Email, Provider: entity.ProviderTypeLocal}, nil
	}}
	issuer, err := token.New()
	require.NoError(t, err)
	clock := newFakeClock()
	clock.Advance(time.Hour)
	svc := NewService(tokens, memStore, issuer, []Provider{provider}, WithClock(clock.Now))

	_, err = svc.Login(ctx, "local@example.com", "squatter-password")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	require.Len(t, tokens.saved, 1)
	rt, err := memStore.GetRefreshToken(ctx, tokens.saved[0])
	require.NoError(t, err)
	require.NotNil(t, epoch)
	require.True(t, epoch.Before(rt.CreatedAt), "arranged: the epoch precedes the session start")
	assert.NotNil(t, rt.EndedAt, "the racing session is ended")
}

func TestWaitPastSecond(t *testing.T) {
	ctx := context.Background()
	epoch := time.Unix(1_000, 400_000_000)

	t.Run("sleeps through the injected clock", func(t *testing.T) {
		clock := &fakeClock{t: epoch}
		svc, _ := setupTestService(t, WithClock(clock.Now))
		svc.sleep = func(_ context.Context, d time.Duration) error { clock.Advance(d); return nil }

		require.NoError(t, svc.waitPastSecond(ctx, epoch))
		assert.Equal(t, time.Unix(1_001, 0), clock.Now(), "stops at the next whole second")
	})

	t.Run("a frozen clock is an error, not a lie", func(t *testing.T) {
		clock := &fakeClock{t: epoch}
		svc, _ := setupTestService(t, WithClock(clock.Now))
		svc.sleep = func(context.Context, time.Duration) error { return nil }

		assert.Error(t, svc.waitPastSecond(ctx, epoch))
	})

	t.Run("already past", func(t *testing.T) {
		clock := &fakeClock{t: epoch.Add(time.Second)}
		svc, _ := setupTestService(t, WithClock(clock.Now))
		svc.sleep = func(context.Context, time.Duration) error { t.Fatal("no sleep needed"); return nil }

		require.NoError(t, svc.waitPastSecond(ctx, epoch))
	})
}

// claimingPATs runs a takeover at one point of a PAT store call, once, as if
// it committed there: before the save (the claim misses the new PAT), after
// the save (the claim deletes it), or before a list.
type claimingPATs struct {
	*memory.Store
	beforeSave, afterSave, beforeList func(ctx context.Context)
}

func once(ctx context.Context, f *func(context.Context)) {
	if *f != nil {
		(*f)(ctx)
		*f = nil
	}
}

func (c *claimingPATs) SavePATLimited(ctx context.Context, pat *entity.PersonalAccessToken, limit int, now time.Time) error {
	once(ctx, &c.beforeSave)
	err := c.Store.SavePATLimited(ctx, pat, limit, now)
	once(ctx, &c.afterSave)
	return err
}

func (c *claimingPATs) ListPATs(ctx context.Context, userID string) ([]*entity.PersonalAccessToken, error) {
	once(ctx, &c.beforeList)
	return c.Store.ListPATs(ctx, userID)
}

// claimFunc takes over user-123 of store.
func claimFunc(t *testing.T, s *memory.Store) func(context.Context) {
	return func(ctx context.Context) {
		epoch, err := s.ClaimAccountWithOAuthIdentity(ctx, &entity.OAuthIdentity{
			ID: "link", UserID: "user-123", Provider: entity.ProviderTypeGoogle, ExternalID: "sub-1",
		})
		require.NoError(t, err)
		require.NotNil(t, epoch)
	}
}

func TestTakeover_PATCreateRacingClaimRefused(t *testing.T) {
	ctx := context.Background()
	for name, stage := range map[string]func(p *claimingPATs, claim func(context.Context)){
		// The claim misses the new PAT: the re-check deletes it.
		"claim before the save": func(p *claimingPATs, claim func(context.Context)) { p.beforeSave = claim },
		// The claim deleted it already: the re-check's delete finds nothing,
		// which is no internal error.
		"claim after the save": func(p *claimingPATs, claim func(context.Context)) { p.afterSave = claim },
	} {
		t.Run(name, func(t *testing.T) {
			memStore := memory.New()
			pats := &claimingPATs{Store: memStore}
			f := newTakeoverFixture(t, memStore, pats)
			stage(pats, claimFunc(t, memStore))

			_, err := f.handler.CreatePersonalAccessToken(ctx, createPATRequest("squatter", f.squatter.AccessToken))
			assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
			list, err := f.store.ListPATs(ctx, "user-123")
			require.NoError(t, err)
			assert.Empty(t, list, "the racing PAT is gone")
		})
	}
}

func TestTakeover_PATListRacingClaimRefused(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	pats := &claimingPATs{Store: memStore}
	f := newTakeoverFixture(t, memStore, pats)
	pats.beforeList = claimFunc(t, memStore)

	req := connect.NewRequest(&authv1.ListPersonalAccessTokensRequest{})
	req.Header().Set("Authorization", "Bearer "+f.squatter.AccessToken)
	resp, err := f.handler.ListPersonalAccessTokens(ctx, req)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Nil(t, resp, "no rows for a stale session")
}

// The takeover commits after Register saved the password and before it saved
// the session: the registrant gets no session.
func TestTakeover_RegisterRacingClaimRefused(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	tokens := &recordingTokens{Store: memStore}
	provider := &mockProvider{registerFn: func(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error) {
		require.NoError(t, memStore.Create(ctx, &entity.User{ID: "user-123", Email: req.Email}))
		require.NoError(t, memStore.SavePasswordHash(ctx, "user-123", "hash"))
		claimFunc(t, memStore)(ctx)
		return &entity.Identity{UserID: "user-123", Email: req.Email, Provider: entity.ProviderTypeLocal}, nil
	}}
	issuer, err := token.New()
	require.NoError(t, err)
	svc := NewService(tokens, memStore, issuer, []Provider{provider})

	_, err = svc.Register(ctx, "local@example.com", "SecurePassword123!")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	require.Len(t, tokens.saved, 1)
	rt, err := memStore.GetRefreshToken(ctx, tokens.saved[0])
	require.NoError(t, err)
	assert.NotNil(t, rt.EndedAt, "the racing session is ended")
}
