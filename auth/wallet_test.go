package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/oauth"
	"github.com/foxcool/psina/provider/wallet"
	"github.com/foxcool/psina/provider/wallet/evm"
	"github.com/foxcool/psina/provider/wallet/evm/evmtest"
	"github.com/foxcool/psina/store"
	"github.com/foxcool/psina/store/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testWalletAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" // evmtest.Key0, as foundry derives it

var testWalletConfig = WalletConfig{
	Domain:    "app.example.com",
	URI:       "https://app.example.com",
	Statement: "Sign in to psina.",
}

func newTestSigner(t *testing.T, keyHex string) *evmtest.Signer {
	t.Helper()
	signer, err := evmtest.NewSigner(keyHex)
	require.NoError(t, err)
	return signer
}

// testNow is a fixed clock near real time: the memory store checks expiry
// against time.Now, so a clock far from it would expire challenges there first.
func testNow() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// setupNoWalletService builds a service without WithWallet.
func setupNoWalletService(t *testing.T) *Service {
	t.Helper()
	svc, _ := setupOAuthService(t, OAuthConfig{})
	return svc
}

func setupWalletService(t *testing.T, opts ...ServiceOption) (*Service, *memory.Store) {
	t.Helper()
	memStore := memory.New()
	return newWalletService(t, memStore, memStore, opts...), memStore
}

func walletTestDispatcher() *wallet.Dispatcher {
	return wallet.NewDispatcher(evm.New("ethereum", 1), evm.New("polygon", 137))
}

func newWalletService(t *testing.T, memStore *memory.Store, identities WalletIdentityStore, opts ...ServiceOption) *Service {
	t.Helper()
	return newOAuthService(t, memStore, WithWallet(walletTestDispatcher(), identities, memStore, testWalletConfig), opts...)
}

// signIn runs GetChallenge and returns the AuthenticateWallet request the
// wallet would send.
func signIn(t *testing.T, svc *Service, signer *evmtest.Signer, chain string) WalletAuthRequest {
	t.Helper()
	ch, err := svc.GetChallenge(context.Background(), chain, signer.Address)
	require.NoError(t, err)
	return WalletAuthRequest{Chain: chain, Address: signer.Address, Nonce: ch.Nonce, Signature: signer.Sign(ch.Message)}
}

func TestWallet_SignerMatchesFoundry(t *testing.T) {
	assert.Equal(t, testWalletAddress, newTestSigner(t, evmtest.Key0).Address)
}

func TestWallet_GetChallenge(t *testing.T) {
	ctx := context.Background()
	now := testNow()
	svc, memStore := setupWalletService(t, WithClock(func() time.Time { return now }))

	res, err := svc.GetChallenge(ctx, "polygon", strings.ToLower(testWalletAddress))
	require.NoError(t, err)

	assert.Len(t, res.Nonce, 32)
	assert.Equal(t, now.Add(DefaultWalletChallengeTTL), res.ExpiresAt)
	for _, line := range []string{
		"app.example.com wants you to sign in with your Ethereum account:",
		testWalletAddress, // checksummed
		"Sign in to psina.",
		"Chain ID: 137",
		"Nonce: " + res.Nonce,
		"Expiration Time: " + now.Add(DefaultWalletChallengeTTL).Format(time.RFC3339),
	} {
		assert.Contains(t, res.Message, line)
	}

	stored, err := memStore.GetChallenge(ctx, res.Nonce)
	require.NoError(t, err)
	assert.Equal(t, "polygon", stored.Chain)
	assert.Equal(t, testWalletAddress, stored.Address)
	assert.Equal(t, res.Message, stored.Message)
}

func TestWallet_NewUserThenReturningUser(t *testing.T) {
	ctx := context.Background()
	svc, memStore := setupWalletService(t)
	signer := newTestSigner(t, evmtest.Key0)

	first, err := svc.AuthenticateWallet(ctx, signIn(t, svc, signer, "ethereum"))
	require.NoError(t, err)
	assert.True(t, first.IsNewUser)
	assert.Empty(t, first.Email, "wallet users have no email")
	assert.NotEmpty(t, first.TokenPair.AccessToken)

	identity, err := memStore.GetWalletIdentity(ctx, "ethereum", testWalletAddress)
	require.NoError(t, err)
	assert.Equal(t, first.UserID, identity.UserID)

	// Lowercase address in the request still matches the checksummed challenge.
	req := signIn(t, svc, signer, "ethereum")
	req.Address = strings.ToLower(req.Address)
	second, err := svc.AuthenticateWallet(ctx, req)
	require.NoError(t, err)
	assert.False(t, second.IsNewUser)
	assert.Equal(t, first.UserID, second.UserID)

	// The same wallet on another chain is another identity, hence another user.
	other, err := svc.AuthenticateWallet(ctx, signIn(t, svc, signer, "polygon"))
	require.NoError(t, err)
	assert.True(t, other.IsNewUser)
	assert.NotEqual(t, first.UserID, other.UserID)

	// Two wallet users without email coexist.
	another, err := svc.AuthenticateWallet(ctx, signIn(t, svc, newTestSigner(t, evmtest.Key1), "ethereum"))
	require.NoError(t, err)
	assert.True(t, another.IsNewUser)
}

func TestWallet_RejectedSignIns(t *testing.T) {
	ctx := context.Background()
	signer := newTestSigner(t, evmtest.Key0)
	otherSigner := newTestSigner(t, evmtest.Key1)

	tests := []struct {
		name string
		// mutate turns a valid request into the one under test.
		mutate func(t *testing.T, svc *Service, req *WalletAuthRequest)
		// burnt reports whether the original challenge is gone afterwards.
		burnt bool
	}{
		{
			name: "replayed",
			mutate: func(t *testing.T, svc *Service, req *WalletAuthRequest) {
				_, err := svc.AuthenticateWallet(ctx, *req)
				require.NoError(t, err)
			},
			burnt: true,
		},
		{
			name:   "unknown nonce",
			mutate: func(_ *testing.T, _ *Service, req *WalletAuthRequest) { req.Nonce = strings.Repeat("0", 32) },
		},
		{
			name:   "empty nonce",
			mutate: func(_ *testing.T, _ *Service, req *WalletAuthRequest) { req.Nonce = "" },
		},
		{
			name:   "empty signature",
			mutate: func(_ *testing.T, _ *Service, req *WalletAuthRequest) { req.Signature = "" },
		},
		{
			name: "signed by another wallet",
			mutate: func(t *testing.T, svc *Service, req *WalletAuthRequest) {
				stored, err := svc.walletChallenges.GetChallenge(ctx, req.Nonce)
				require.NoError(t, err)
				req.Signature = otherSigner.Sign(stored.Message)
			},
		},
		{
			// Anyone can fetch a challenge for a victim's address; signing
			// it with their own key must not pass for their own address.
			name: "challenge of another address",
			mutate: func(t *testing.T, svc *Service, req *WalletAuthRequest) {
				stored, err := svc.walletChallenges.GetChallenge(ctx, req.Nonce)
				require.NoError(t, err)
				req.Address = otherSigner.Address
				req.Signature = otherSigner.Sign(stored.Message)
			},
		},
		{
			name:   "challenge of another chain",
			mutate: func(_ *testing.T, _ *Service, req *WalletAuthRequest) { req.Chain = "polygon" },
		},
		{
			name:   "garbage signature",
			mutate: func(_ *testing.T, _ *Service, req *WalletAuthRequest) { req.Signature = "0xdeadbeef" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, memStore := setupWalletService(t)
			req := signIn(t, svc, signer, "ethereum")
			valid := req
			tt.mutate(t, svc, &req)

			_, err := svc.AuthenticateWallet(ctx, req)
			assert.True(t, errors.Is(err, ErrWalletChallengeInvalid), "got %v", err)

			_, err = memStore.GetChallenge(ctx, valid.Nonce)
			if tt.burnt {
				assert.True(t, errors.Is(err, store.ErrChallengeNotFound), "got %v", err)
				return
			}
			require.NoError(t, err, "a rejected attempt must not burn the challenge")
			_, err = svc.AuthenticateWallet(ctx, valid)
			assert.NoError(t, err, "the wallet can still sign in")
		})
	}
}

func TestWallet_ExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	start := testNow()
	now := start
	svc, _ := setupWalletService(t, WithClock(func() time.Time { return now }))
	signer := newTestSigner(t, evmtest.Key0)
	lastSecond, atExpiry := signIn(t, svc, signer, "ethereum"), signIn(t, svc, signer, "ethereum")

	now = start.Add(DefaultWalletChallengeTTL - time.Second)
	_, err := svc.AuthenticateWallet(ctx, lastSecond)
	assert.NoError(t, err, "valid until the last moment")

	now = start.Add(DefaultWalletChallengeTTL)
	_, err = svc.AuthenticateWallet(ctx, atExpiry)
	assert.True(t, errors.Is(err, ErrWalletChallengeInvalid), "got %v", err)
}

func TestWallet_ChallengesDoNotCrossWithOAuthState(t *testing.T) {
	ctx := context.Background()
	memStore := memory.New()
	google := newFakeGoogle(verifiedInfo("sub-1", "user@example.com"))
	svc := newWalletService(t, memStore, memStore, WithOAuth([]oauth.Provider{google}, memStore, memStore, memStore, OAuthConfig{}))
	signer := newTestSigner(t, evmtest.Key0)

	// An OAuth state used as a wallet nonce, with a valid signature of the
	// stored payload, so only the chain/address binding can refuse it.
	oauthReq := startFlow(t, svc)
	storedState, err := memStore.GetChallenge(ctx, oauthReq.State)
	require.NoError(t, err)
	_, err = svc.AuthenticateWallet(ctx, WalletAuthRequest{
		Chain: "ethereum", Address: signer.Address, Nonce: oauthReq.State, Signature: signer.Sign(storedState.Message),
	})
	assert.True(t, errors.Is(err, ErrWalletChallengeInvalid), "got %v", err)

	// A wallet nonce used as an OAuth state.
	walletReq := signIn(t, svc, signer, "ethereum")
	_, err = svc.OAuthCallback(ctx, OAuthCallbackRequest{
		Provider: entity.ProviderTypeGoogle, Code: "auth-code", State: walletReq.Nonce,
		RedirectURI: testRedirectURI, Binding: "any",
	})
	assert.True(t, errors.Is(err, ErrOAuthStateInvalid), "got %v", err)

	// Both still work for their own flow.
	_, err = svc.OAuthCallback(ctx, oauthReq)
	assert.NoError(t, err)
	_, err = svc.AuthenticateWallet(ctx, walletReq)
	assert.NoError(t, err)
}

func TestWallet_RequestErrors(t *testing.T) {
	ctx := context.Background()
	svc, _ := setupWalletService(t)
	disabled := setupNoWalletService(t)

	tests := []struct {
		name    string
		svc     *Service
		chain   string
		address string
		wantErr error
	}{
		{"disabled", disabled, "ethereum", testWalletAddress, ErrWalletDisabled},
		{"unsupported chain", svc, "solana", testWalletAddress, ErrWalletChainUnsupported},
		{"bad checksum", svc, "ethereum", "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266", ErrWalletAddressInvalid},
		{"not an address", svc, "ethereum", "vitalik.eth", ErrWalletAddressInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.svc.GetChallenge(ctx, tt.chain, tt.address)
			assert.True(t, errors.Is(err, tt.wantErr), "GetChallenge: got %v", err)

			_, err = tt.svc.AuthenticateWallet(ctx, WalletAuthRequest{
				Chain: tt.chain, Address: tt.address, Nonce: "n", Signature: "s",
			})
			assert.True(t, errors.Is(err, tt.wantErr), "AuthenticateWallet: got %v", err)
		})
	}
}

// hookWalletIdentities runs onSave instead of the store's SaveWalletIdentity.
type hookWalletIdentities struct {
	WalletIdentityStore
	onSave func(ctx context.Context, identity *entity.WalletIdentity) error
}

func (h *hookWalletIdentities) SaveWalletIdentity(ctx context.Context, identity *entity.WalletIdentity) error {
	return h.onSave(ctx, identity)
}

func TestWallet_FirstSignInLinkFailures(t *testing.T) {
	ctx := context.Background()
	signer := newTestSigner(t, evmtest.Key0)
	errSave := errors.New("db down")

	tests := []struct {
		name string
		// onSave simulates what happens when the new user's link is saved.
		onSave   func(t *testing.T, m *memory.Store) func(context.Context, *entity.WalletIdentity) error
		wantErr  error
		wantUser string // the user signed in on success
	}{
		{
			name: "concurrent first sign-in won",
			onSave: func(t *testing.T, m *memory.Store) func(context.Context, *entity.WalletIdentity) error {
				return func(ctx context.Context, id *entity.WalletIdentity) error {
					require.NoError(t, m.Create(ctx, &entity.User{ID: "winner"}))
					require.NoError(t, m.SaveWalletIdentity(ctx, &entity.WalletIdentity{
						ID: "w", UserID: "winner", Chain: id.Chain, Address: id.Address,
					}))
					return m.SaveWalletIdentity(ctx, id)
				}
			},
			wantUser: "winner",
		},
		{
			name: "save fails",
			onSave: func(*testing.T, *memory.Store) func(context.Context, *entity.WalletIdentity) error {
				return func(context.Context, *entity.WalletIdentity) error { return errSave }
			},
			wantErr: errSave,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			memStore := memory.New()
			var created string
			hooked := &hookWalletIdentities{WalletIdentityStore: memStore}
			onSave := tt.onSave(t, memStore)
			hooked.onSave = func(ctx context.Context, id *entity.WalletIdentity) error {
				created = id.UserID
				return onSave(ctx, id)
			}
			svc := newWalletService(t, memStore, hooked)

			res, err := svc.AuthenticateWallet(ctx, signIn(t, svc, signer, "ethereum"))
			if tt.wantErr != nil {
				assert.True(t, errors.Is(err, tt.wantErr), "got %v", err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantUser, res.UserID)
				assert.False(t, res.IsNewUser)
			}

			require.NotEmpty(t, created)
			_, err = memStore.GetByID(ctx, created)
			assert.True(t, errors.Is(err, store.ErrUserNotFound), "the unlinked user is discarded, got %v", err)
		})
	}
}

func TestWithWallet_RejectsBadWiring(t *testing.T) {
	memStore := memory.New()
	d := wallet.NewDispatcher(evm.New("ethereum", 1))

	tests := []struct {
		name  string
		build func()
	}{
		{"nil dispatcher", func() { WithWallet(nil, memStore, memStore, testWalletConfig) }},
		{"nil identities", func() { WithWallet(d, nil, memStore, testWalletConfig) }},
		{"nil challenges", func() { WithWallet(d, memStore, nil, testWalletConfig) }},
		{"no domain", func() { WithWallet(d, memStore, memStore, WalletConfig{URI: "https://a.example"}) }},
		{"no uri", func() { WithWallet(d, memStore, memStore, WalletConfig{Domain: "a.example"}) }},
		{"line break in statement", func() {
			WithWallet(d, memStore, memStore, WalletConfig{
				Domain: "a.example", URI: "https://a.example", Statement: "hi\nURI: https://evil.example",
			})
		}},
		{"carriage return in domain", func() {
			WithWallet(d, memStore, memStore, WalletConfig{Domain: "a.example\r", URI: "https://a.example"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Panics(t, tt.build)
		})
	}
}
