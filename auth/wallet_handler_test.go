package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/api/auth/v1"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/wallet/evm/evmtest"
	"github.com/foxcool/psina/store/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupWalletHandler(t *testing.T, cookies bool) *Handler {
	t.Helper()
	svc, _ := setupWalletService(t)
	if !cookies {
		return NewHandler(svc)
	}
	return NewHandler(svc, WithCookieConfig(&CookieConfig{
		Enabled:  true,
		Domain:   "app.example.com",
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}))
}

// walletSignIn runs GetChallenge through the handler and signs the message.
func walletSignIn(t *testing.T, h *Handler, signer *evmtest.Signer) *connect.Request[authv1.AuthenticateWalletRequest] {
	t.Helper()
	ch, err := h.GetChallenge(context.Background(), connect.NewRequest(&authv1.GetChallengeRequest{
		Chain:   "ethereum",
		Address: signer.Address,
	}))
	require.NoError(t, err)
	assert.Positive(t, ch.Msg.ExpiresAt)
	return connect.NewRequest(&authv1.AuthenticateWalletRequest{
		Chain:     "ethereum",
		Address:   signer.Address,
		Nonce:     ch.Msg.Nonce,
		Signature: signer.Sign(ch.Msg.Message),
	})
}

func TestHandler_Wallet_BearerMode(t *testing.T) {
	h := setupWalletHandler(t, false)

	resp, err := h.AuthenticateWallet(context.Background(), walletSignIn(t, h, newTestSigner(t, evmtest.Key0)))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.UserId)
	assert.Empty(t, resp.Msg.Email)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	assert.True(t, resp.Msg.IsNewUser)
	assert.Empty(t, resp.Header().Values("Set-Cookie"))
}

func TestHandler_Wallet_CookieMode(t *testing.T) {
	h := setupWalletHandler(t, true)

	resp, err := h.AuthenticateWallet(context.Background(), walletSignIn(t, h, newTestSigner(t, evmtest.Key0)))
	require.NoError(t, err)
	assert.True(t, hasCookie(resp.Header(), AccessTokenCookie))
	assert.True(t, hasCookie(resp.Header(), RefreshTokenCookie))
}

func TestHandler_Wallet_ErrorCodes(t *testing.T) {
	ctx := context.Background()
	h := setupWalletHandler(t, false)
	disabled := NewHandler(setupNoWalletService(t))
	signer := newTestSigner(t, evmtest.Key0)

	replayed := walletSignIn(t, h, signer)
	_, err := h.AuthenticateWallet(ctx, replayed)
	require.NoError(t, err)

	tests := []struct {
		name string
		call func() error
		want connect.Code
	}{
		{"challenge: missing address", func() error {
			_, err := h.GetChallenge(ctx, connect.NewRequest(&authv1.GetChallengeRequest{Chain: "ethereum"}))
			return err
		}, connect.CodeInvalidArgument},
		{"challenge: unsupported chain", func() error {
			_, err := h.GetChallenge(ctx, connect.NewRequest(&authv1.GetChallengeRequest{Chain: "solana", Address: signer.Address}))
			return err
		}, connect.CodeInvalidArgument},
		{"challenge: bad address", func() error {
			_, err := h.GetChallenge(ctx, connect.NewRequest(&authv1.GetChallengeRequest{Chain: "ethereum", Address: "0x1234"}))
			return err
		}, connect.CodeInvalidArgument},
		{"challenge: disabled", func() error {
			_, err := disabled.GetChallenge(ctx, connect.NewRequest(&authv1.GetChallengeRequest{Chain: "ethereum", Address: signer.Address}))
			return err
		}, connect.CodeUnimplemented},
		{"authenticate: missing chain", func() error {
			_, err := h.AuthenticateWallet(ctx, connect.NewRequest(&authv1.AuthenticateWalletRequest{Address: signer.Address}))
			return err
		}, connect.CodeInvalidArgument},
		{"authenticate: replayed", func() error {
			_, err := h.AuthenticateWallet(ctx, replayed)
			return err
		}, connect.CodeUnauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			var cerr *connect.Error
			require.True(t, errors.As(err, &cerr), "got %v", err)
			assert.Equal(t, tt.want, cerr.Code())
		})
	}
}

// failingChallenges fails every save, standing in for a storage outage.
type failingChallenges struct{ ChallengeStore }

func (failingChallenges) SaveChallenge(context.Context, *entity.Challenge) error {
	return errors.New("pq: connection refused to 10.0.0.5")
}

func TestHandler_Wallet_InternalErrorHidesDetail(t *testing.T) {
	memStore := memory.New()
	svc := newOAuthService(t, memStore, WithWallet(
		walletTestDispatcher(), memStore, failingChallenges{memStore}, testWalletConfig))
	h := NewHandler(svc)

	_, err := h.GetChallenge(context.Background(), connect.NewRequest(&authv1.GetChallengeRequest{
		Chain: "ethereum", Address: testWalletAddress,
	}))
	var cerr *connect.Error
	require.True(t, errors.As(err, &cerr), "got %v", err)
	assert.Equal(t, connect.CodeInternal, cerr.Code())
	assert.NotContains(t, cerr.Message(), "10.0.0.5")
}
