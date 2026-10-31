package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/oauth"
	"github.com/foxcool/psina/store"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRedirectURI = "https://app.example.com/oauth/callback"

// fakeOAuthProvider records the params it receives and returns a fixed identity.
type fakeOAuthProvider struct {
	name        string
	info        *oauth.UserInfo
	exchangeErr error
	authParams  oauth.AuthParams
	exchParams  oauth.AuthParams
	exchanges   int
}

func (f *fakeOAuthProvider) ProviderName() string { return f.name }

func (f *fakeOAuthProvider) AuthCodeURL(p oauth.AuthParams) (string, error) {
	if p.RedirectURI != testRedirectURI {
		return "", oauth.ErrRedirectURINotAllowed
	}
	f.authParams = p
	return "https://idp.example.com/auth?state=" + p.State, nil
}

func (f *fakeOAuthProvider) ExchangeCode(_ context.Context, _ string, p oauth.AuthParams) (*oauth.UserInfo, error) {
	f.exchanges++
	f.exchParams = p
	if f.exchangeErr != nil {
		return nil, f.exchangeErr
	}
	info := *f.info
	return &info, nil
}

func newFakeGoogle(info oauth.UserInfo) *fakeOAuthProvider {
	return &fakeOAuthProvider{name: entity.ProviderTypeGoogle, info: &info}
}

// countingChallenges counts saved challenges.
type countingChallenges struct {
	ChallengeStore
	saves int
}

func (c *countingChallenges) SaveChallenge(ctx context.Context, ch *entity.Challenge) error {
	c.saves++
	return c.ChallengeStore.SaveChallenge(ctx, ch)
}

func setupOAuthService(t *testing.T, cfg OAuthConfig, providers ...oauth.Provider) (*Service, *memory.Store) {
	t.Helper()
	memStore := memory.New()
	return newOAuthService(t, memStore, WithOAuth(providers, memStore, memStore, memStore, cfg)), memStore
}

// newOAuthService builds a service over memStore with the given OAuth wiring.
func newOAuthService(t *testing.T, memStore *memory.Store, withOAuth ServiceOption, opts ...ServiceOption) *Service {
	t.Helper()
	issuer, err := token.New()
	require.NoError(t, err)
	opts = append([]ServiceOption{withOAuth}, opts...)
	return NewService(memStore, memStore, issuer, []Provider{&mockProvider{}}, opts...)
}

// startFlow runs GetOAuthURL and returns the callback request the browser would send.
func startFlow(t *testing.T, svc *Service) OAuthCallbackRequest {
	t.Helper()
	res, err := svc.GetOAuthURL(context.Background(), entity.ProviderTypeGoogle, testRedirectURI)
	require.NoError(t, err)
	return OAuthCallbackRequest{
		Provider:    entity.ProviderTypeGoogle,
		Code:        "auth-code",
		State:       res.State,
		RedirectURI: testRedirectURI,
		Binding:     res.Binding,
	}
}

func verifiedInfo(sub, email string) oauth.UserInfo {
	return oauth.UserInfo{ExternalID: sub, Email: email, EmailVerified: true}
}

func TestOAuth_NewUser(t *testing.T) {
	ctx := context.Background()
	google := newFakeGoogle(verifiedInfo("sub-1", "New@Example.com"))
	svc, memStore := setupOAuthService(t, OAuthConfig{}, google)

	req := startFlow(t, svc)
	res, err := svc.OAuthCallback(ctx, req)
	require.NoError(t, err)

	assert.True(t, res.IsNewUser)
	assert.Equal(t, "new@example.com", res.Email, "provider email is normalized")

	// Server-side flow values reach the exchange unchanged.
	assert.Equal(t, google.authParams, google.exchParams)
	assert.NotEmpty(t, google.exchParams.CodeVerifier)
	assert.NotEmpty(t, google.exchParams.Nonce)

	identity, err := memStore.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-1")
	require.NoError(t, err)
	assert.Equal(t, res.UserID, identity.UserID)

	claims, err := svc.Verify(ctx, res.TokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, res.UserID, claims.UserID)
}

func TestOAuth_ExistingIdentity(t *testing.T) {
	ctx := context.Background()
	// The provider reports another, unverified email: the link is by external
	// id, so it neither matters nor leaks into the token.
	google := newFakeGoogle(oauth.UserInfo{ExternalID: "sub-1", Email: "other@example.com"})
	svc, memStore := setupOAuthService(t, OAuthConfig{}, google)

	user := &entity.User{ID: "user-1", Email: "user@example.com", Roles: []string{"admin"}}
	require.NoError(t, memStore.Create(ctx, user))
	require.NoError(t, memStore.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
		ID: "id-1", UserID: user.ID, Provider: entity.ProviderTypeGoogle, ExternalID: "sub-1",
	}))

	res, err := svc.OAuthCallback(ctx, startFlow(t, svc))
	require.NoError(t, err)
	assert.False(t, res.IsNewUser)
	assert.Equal(t, user.ID, res.UserID)
	assert.Equal(t, user.Email, res.Email)

	claims, err := svc.Verify(ctx, res.TokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.Email, claims.Email)
	assert.Equal(t, []string{"admin"}, claims.Roles)
}

func TestOAuth_LinkOrCreate(t *testing.T) {
	tests := []struct {
		name     string
		cfg      OAuthConfig
		info     oauth.UserInfo
		existing bool
		password bool // the existing account holds a password
		wantErr  error
		wantNew  bool
	}{
		{name: "verified email links passwordless account", info: verifiedInfo("sub-1", "local@example.com"), existing: true},
		// Pre-account takeover: whoever registered the address with a password
		// may not own it, so a verified sign-in must not join that account.
		{name: "password account is not linked", info: verifiedInfo("sub-1", "local@example.com"), existing: true, password: true, wantErr: ErrOAuthAccountHasPassword},
		{name: "unverified email does not link", info: oauth.UserInfo{ExternalID: "sub-1", Email: "local@example.com"}, existing: true, wantErr: ErrOAuthEmailUnverified},
		{name: "unverified email does not create", info: oauth.UserInfo{ExternalID: "sub-1", Email: "fresh@example.com"}, wantErr: ErrOAuthEmailUnverified},
		{name: "auto-link disabled", cfg: OAuthConfig{DisableAutoLinkEmail: true}, info: verifiedInfo("sub-1", "local@example.com"), existing: true, wantErr: ErrOAuthLinkDisabled},
		{name: "auto-link disabled still creates", cfg: OAuthConfig{DisableAutoLinkEmail: true}, info: verifiedInfo("sub-1", "fresh@example.com"), wantNew: true},
		{name: "missing email", info: verifiedInfo("sub-1", ""), wantErr: ErrOAuthEmailRequired},
		{name: "invalid email", info: verifiedInfo("sub-1", "not-an-email"), wantErr: ErrOAuthEmailRequired},
		{name: "overlong email", info: verifiedInfo("sub-1", strings.Repeat("a", 250)+"@example.com"), wantErr: ErrOAuthEmailRequired},
		{name: "missing external id", info: verifiedInfo("", "fresh@example.com"), wantErr: ErrOAuthExchangeFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			svc, memStore := setupOAuthService(t, tt.cfg, newFakeGoogle(tt.info))
			local := &entity.User{ID: "local-user", Email: "local@example.com"}
			require.NoError(t, memStore.Create(ctx, local))
			if tt.password {
				require.NoError(t, memStore.SavePasswordHash(ctx, local.ID, "hash"))
			}

			res, err := svc.OAuthCallback(ctx, startFlow(t, svc))
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				_, err := memStore.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-1")
				assert.ErrorIs(t, err, store.ErrOAuthIdentityNotFound, "no identity on failure")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantNew, res.IsNewUser)
			if tt.existing {
				assert.Equal(t, local.ID, res.UserID)
			}
		})
	}
}

func TestOAuth_StateRejected(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		mutate func(*OAuthCallbackRequest)
	}{
		{"unknown state", func(r *OAuthCallbackRequest) { r.State = "forged" }},
		{"empty state", func(r *OAuthCallbackRequest) { r.State = "" }},
		{"empty code", func(r *OAuthCallbackRequest) { r.Code = "" }},
		{"other redirect uri", func(r *OAuthCallbackRequest) { r.RedirectURI = "https://evil.example.com/cb" }},
		{"other provider", func(r *OAuthCallbackRequest) { r.Provider = entity.ProviderTypeGitHub }},
		{"other browser", func(r *OAuthCallbackRequest) { r.Binding = "attacker-binding" }},
		{"no binding", func(r *OAuthCallbackRequest) { r.Binding = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
			github := &fakeOAuthProvider{name: entity.ProviderTypeGitHub, info: google.info}
			svc, _ := setupOAuthService(t, OAuthConfig{}, google, github)

			req := startFlow(t, svc)
			bad := req
			tt.mutate(&bad)
			_, err := svc.OAuthCallback(ctx, bad)
			require.ErrorIs(t, err, ErrOAuthStateInvalid)
			assert.Zero(t, google.exchanges+github.exchanges, "no exchange on a rejected state")

			// A rejected callback must not burn the legitimate one.
			_, err = svc.OAuthCallback(ctx, req)
			require.NoError(t, err)
		})
	}
}

func TestOAuth_StateSingleUse(t *testing.T) {
	ctx := context.Background()
	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	svc, _ := setupOAuthService(t, OAuthConfig{}, google)

	req := startFlow(t, svc)
	_, err := svc.OAuthCallback(ctx, req)
	require.NoError(t, err)

	_, err = svc.OAuthCallback(ctx, req)
	require.ErrorIs(t, err, ErrOAuthStateInvalid)
	assert.Equal(t, 1, google.exchanges)
}

func TestOAuth_StateExpired(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	memStore := memory.New()
	svc := newOAuthService(t, memStore,
		WithOAuth([]oauth.Provider{google}, memStore, memStore, memStore, OAuthConfig{StateTTL: time.Minute}),
		WithClock(clock.Now))

	req := startFlow(t, svc)
	clock.Advance(time.Minute)
	_, err := svc.OAuthCallback(ctx, req)
	require.ErrorIs(t, err, ErrOAuthStateInvalid)
	assert.Zero(t, google.exchanges)
}

func TestOAuth_ExchangeFailureBurnsState(t *testing.T) {
	ctx := context.Background()
	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	google.exchangeErr = oauth.ErrInvalidToken
	svc, _ := setupOAuthService(t, OAuthConfig{}, google)

	req := startFlow(t, svc)
	_, err := svc.OAuthCallback(ctx, req)
	require.ErrorIs(t, err, ErrOAuthExchangeFailed)
	require.ErrorIs(t, err, oauth.ErrInvalidToken)

	google.exchangeErr = nil
	_, err = svc.OAuthCallback(ctx, req)
	require.ErrorIs(t, err, ErrOAuthStateInvalid)
}

func TestOAuth_GetURL(t *testing.T) {
	ctx := context.Background()
	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	memStore := memory.New()
	challenges := &countingChallenges{ChallengeStore: memStore}
	svc := newOAuthService(t, memStore, WithOAuth([]oauth.Provider{google}, memStore, challenges, memStore, OAuthConfig{}))

	_, err := svc.GetOAuthURL(ctx, entity.ProviderTypeGoogle, "https://evil.example.com/cb")
	require.ErrorIs(t, err, oauth.ErrRedirectURINotAllowed)
	assert.Zero(t, challenges.saves, "rejected redirect uri leaves no state behind")

	_, err = svc.GetOAuthURL(ctx, entity.ProviderTypeGitHub, testRedirectURI)
	require.ErrorIs(t, err, ErrOAuthProviderUnknown)

	a, err := svc.GetOAuthURL(ctx, entity.ProviderTypeGoogle, testRedirectURI)
	require.NoError(t, err)
	b, err := svc.GetOAuthURL(ctx, entity.ProviderTypeGoogle, testRedirectURI)
	require.NoError(t, err)
	assert.NotEqual(t, a.State, b.State)
	assert.NotEqual(t, a.Binding, b.Binding)
	assert.Len(t, a.State, base64.RawURLEncoding.EncodedLen(oauthSecretBytes))
	assert.Equal(t, 2, challenges.saves)
}

func TestOAuth_Disabled(t *testing.T) {
	ctx := context.Background()
	svc, _ := setupTestService(t)

	_, err := svc.GetOAuthURL(ctx, entity.ProviderTypeGoogle, testRedirectURI)
	require.ErrorIs(t, err, ErrOAuthDisabled)
	_, err = svc.OAuthCallback(ctx, OAuthCallbackRequest{Provider: entity.ProviderTypeGoogle})
	require.ErrorIs(t, err, ErrOAuthDisabled)
}

func TestOAuth_DuplicateProviderPanics(t *testing.T) {
	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	memStore := memory.New()
	assert.PanicsWithValue(t, `auth: duplicate oauth provider "google"`, func() {
		WithOAuth([]oauth.Provider{google, google}, memStore, memStore, memStore, OAuthConfig{})
	})
}

func TestOAuth_NilStorePanics(t *testing.T) {
	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	memStore := memory.New()
	assert.Panics(t, func() {
		WithOAuth([]oauth.Provider{google}, memStore, memStore, nil, OAuthConfig{})
	})
}

// raceIdentities hides an existing identity from the first lookup, as if a
// concurrent callback linked the provider account in between.
type raceIdentities struct {
	OAuthIdentityStore
	lookups int
}

func (r *raceIdentities) GetOAuthIdentity(ctx context.Context, provider, externalID string) (*entity.OAuthIdentity, error) {
	r.lookups++
	if r.lookups == 1 {
		return nil, store.ErrOAuthIdentityNotFound
	}
	return r.OAuthIdentityStore.GetOAuthIdentity(ctx, provider, externalID)
}

func TestOAuth_ConcurrentLinkWins(t *testing.T) {
	ctx := context.Background()
	google := newFakeGoogle(verifiedInfo("sub-1", "fresh@example.com"))
	memStore := memory.New()
	svc := newOAuthService(t, memStore,
		WithOAuth([]oauth.Provider{google}, &raceIdentities{OAuthIdentityStore: memStore}, memStore, memStore, OAuthConfig{}))

	winner := &entity.User{ID: "winner", Email: "winner@example.com"}
	require.NoError(t, memStore.Create(ctx, winner))
	require.NoError(t, memStore.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
		ID: "id-1", UserID: winner.ID, Provider: entity.ProviderTypeGoogle, ExternalID: "sub-1",
	}))

	res, err := svc.OAuthCallback(ctx, startFlow(t, svc))
	require.NoError(t, err)
	assert.Equal(t, winner.ID, res.UserID)
	assert.False(t, res.IsNewUser)

	// The user created for the lost race is rolled back.
	_, err = memStore.GetByEmail(ctx, "fresh@example.com")
	assert.True(t, errors.Is(err, store.ErrUserNotFound), "orphan user removed, got: %v", err)
}

// raceUsers hides an existing user from the first email lookup, as if a
// concurrent registration took the email in between.
type raceUsers struct {
	*memory.Store
	lookups int
}

func (r *raceUsers) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	r.lookups++
	if r.lookups == 1 {
		return nil, store.ErrUserNotFound
	}
	return r.Store.GetByEmail(ctx, email)
}

func TestOAuth_ConcurrentRegistration(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	users := &raceUsers{Store: memStore}
	registered := &entity.User{ID: "registered", Email: "user@example.com"}
	require.NoError(t, memStore.Create(ctx, registered))

	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	issuer, err := token.New()
	require.NoError(t, err)
	svc := NewService(memStore, users, issuer, []Provider{&mockProvider{}},
		WithOAuth([]oauth.Provider{google}, memStore, memStore, memStore, OAuthConfig{}))

	res, err := svc.OAuthCallback(ctx, startFlow(t, svc))
	require.NoError(t, err)
	assert.Equal(t, registered.ID, res.UserID)
	assert.False(t, res.IsNewUser)
}

// hookIdentities hides the first identity lookup and runs onSave in place of
// the first save, so a test can stage what a concurrent flow did meanwhile.
type hookIdentities struct {
	*memory.Store
	onSave  func(ctx context.Context, identity *entity.OAuthIdentity) error
	lookups int
	saves   int
}

func (h *hookIdentities) GetOAuthIdentity(ctx context.Context, provider, externalID string) (*entity.OAuthIdentity, error) {
	h.lookups++
	if h.lookups == 1 {
		return nil, store.ErrOAuthIdentityNotFound
	}
	return h.Store.GetOAuthIdentity(ctx, provider, externalID)
}

func (h *hookIdentities) SaveOAuthIdentity(ctx context.Context, identity *entity.OAuthIdentity) error {
	h.saves++
	if h.saves == 1 {
		return h.onSave(ctx, identity)
	}
	return h.Store.SaveOAuthIdentity(ctx, identity)
}

func TestOAuth_FailedLinkRollback(t *testing.T) {
	errSave := errors.New("save failed")
	tests := []struct {
		name     string
		onSave   func(t *testing.T, m *memory.Store) func(context.Context, *entity.OAuthIdentity) error
		wantErr  error
		wantKept bool
	}{
		{
			// Two flows for one account: the other one found our new user by
			// email and linked it first. The user is the winner, not an orphan.
			name: "same account linked to the new user",
			onSave: func(t *testing.T, m *memory.Store) func(context.Context, *entity.OAuthIdentity) error {
				return func(ctx context.Context, id *entity.OAuthIdentity) error {
					winner := *id
					winner.ID = "winner"
					require.NoError(t, m.SaveOAuthIdentity(ctx, &winner))
					return m.SaveOAuthIdentity(ctx, id)
				}
			},
			wantKept: true,
		},
		{
			name: "other provider linked the new user, then save fails",
			onSave: func(t *testing.T, m *memory.Store) func(context.Context, *entity.OAuthIdentity) error {
				return func(ctx context.Context, id *entity.OAuthIdentity) error {
					require.NoError(t, m.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
						ID: "gh", UserID: id.UserID, Provider: entity.ProviderTypeGitHub, ExternalID: "7",
					}))
					return errSave
				}
			},
			wantErr:  errSave,
			wantKept: true,
		},
		{
			name: "unlinked new user is removed",
			onSave: func(*testing.T, *memory.Store) func(context.Context, *entity.OAuthIdentity) error {
				return func(context.Context, *entity.OAuthIdentity) error { return errSave }
			},
			wantErr: errSave,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			memStore := memory.New()
			identities := &hookIdentities{Store: memStore, onSave: tt.onSave(t, memStore)}
			google := newFakeGoogle(verifiedInfo("sub-1", "fresh@example.com"))
			svc := newOAuthService(t, memStore, WithOAuth([]oauth.Provider{google}, identities, memStore, memStore, OAuthConfig{}))

			res, err := svc.OAuthCallback(ctx, startFlow(t, svc))
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.False(t, res.IsNewUser, "the concurrent flow created the session first")
			}

			user, err := memStore.GetByEmail(ctx, "fresh@example.com")
			if !tt.wantKept {
				assert.ErrorIs(t, err, store.ErrUserNotFound)
				return
			}
			require.NoError(t, err)
			if res != nil {
				assert.Equal(t, user.ID, res.UserID)
			}
		})
	}
}

// failingCredentials fails every password lookup.
type failingCredentials struct{ CredentialStore }

func (failingCredentials) GetPasswordHash(context.Context, string) (string, error) {
	return "", errors.New("db down")
}

func TestOAuth_AutoLinkCredentialLookupFails(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	svc := newOAuthService(t, memStore,
		WithOAuth([]oauth.Provider{google}, memStore, memStore, failingCredentials{}, OAuthConfig{}))
	require.NoError(t, memStore.Create(ctx, &entity.User{ID: "u1", Email: "user@example.com"}))

	_, err := svc.OAuthCallback(ctx, startFlow(t, svc))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrOAuthAccountHasPassword)

	_, err = memStore.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-1")
	assert.ErrorIs(t, err, store.ErrOAuthIdentityNotFound, "an unknown password state does not link")
}
