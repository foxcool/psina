package auth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/api/auth/v1"
	"github.com/foxcool/psina/api/auth/v1/authv1connect"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/wallet/evm/evmtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const auditTestUA = "audit-test/1.0"

// auditSink collects JSON log records. The server logs on its own goroutine,
// synchronised with the test only through the socket, which the race
// detector does not see; hence the mutex.
type auditSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *auditSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

// records returns every record written so far and resets the sink.
func (s *auditSink) records(t *testing.T) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(&s.buf)
	for sc.Scan() {
		var rec map[string]any
		require.NoError(t, json.Unmarshal(sc.Bytes(), &rec))
		out = append(out, rec)
	}
	s.buf.Reset()
	return out
}

// raw returns everything written so far without consuming it.
func (s *auditSink) raw() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// serveAudited serves h over HTTP so requests carry a real peer address, with
// audit events going to the returned sink.
func serveAudited(t *testing.T, svc *Service, opts ...HandlerOption) (authv1connect.AuthServiceClient, *auditSink) {
	t.Helper()
	sink := &auditSink{}
	opts = append(opts, WithAuditLogger(slog.New(slog.NewJSONHandler(sink, nil))))
	path, handler := authv1connect.NewAuthServiceHandler(NewHandler(svc, opts...))
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return authv1connect.NewAuthServiceClient(srv.Client(), srv.URL), sink
}

func withUA[T any](msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("User-Agent", auditTestUA)
	return req
}

// requireAuditEvent checks the common fields of an audit record and returns it.
func requireAuditEvent(t *testing.T, rec map[string]any, event, result string) map[string]any {
	t.Helper()
	assert.Equal(t, true, rec["audit"], "marker attribute")
	assert.Equal(t, event, rec["event"])
	assert.Equal(t, result, rec["result"])
	assert.Equal(t, "127.0.0.1", rec["ip"])
	assert.Equal(t, auditTestUA, rec["user_agent"])
	if result == auditResultSuccess {
		assert.Equal(t, "INFO", rec["level"])
		assert.NotEmpty(t, rec["user_id"])
		assert.NotContains(t, rec, "reason")
	} else {
		assert.Equal(t, "WARN", rec["level"])
		assert.NotEmpty(t, rec["reason"])
	}
	return rec
}

// assertNoSecrets fails if any secret appears anywhere in the log output.
func assertNoSecrets(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" {
			assert.NotContains(t, out, s)
		}
	}
}

func TestAudit_RegisterAndLogin(t *testing.T) {
	ctx := context.Background()
	const email, password = "user@example.com", "SecurePassword123!"

	svc, store := setupTestService(t)
	_ = store.Create(ctx, &entity.User{ID: "user-123", Email: email})
	client, sink := serveAudited(t, svc)

	reg, err := client.Register(ctx, withUA(&authv1.RegisterRequest{Email: email, Password: password}))
	require.NoError(t, err)
	login, err := client.Login(ctx, withUA(&authv1.LoginRequest{Email: email, Password: password}))
	require.NoError(t, err)
	_, err = client.Register(ctx, withUA(&authv1.RegisterRequest{Email: email, Password: "Xq7"}))
	require.Error(t, err)

	out := sink.raw()
	recs := sink.records(t)
	require.Len(t, recs, 3)
	assert.Equal(t, "user-123", requireAuditEvent(t, recs[0], auditEventRegister, auditResultSuccess)["user_id"])
	assert.Equal(t, "user-123", requireAuditEvent(t, recs[1], auditEventLogin, auditResultSuccess)["user_id"])
	assert.Equal(t, "password_too_short", requireAuditEvent(t, recs[2], auditEventRegister, auditResultFailure)["reason"])

	assertNoSecrets(t, out, password, "Xq7",
		reg.Msg.AccessToken, reg.Msg.RefreshToken, login.Msg.AccessToken, login.Msg.RefreshToken)
}

func TestAudit_LoginFailure(t *testing.T) {
	ctx := context.Background()
	// A password typed into the identifier field must not reach the log.
	const identifier, password = "hunter2-secret@typo.example", "TypedPassword123!"

	tests := []struct {
		name       string
		err        error
		wantReason string
		wantUserID any
	}{
		{"unknown user", &CredentialsError{Reason: ReasonUnknownUser}, ReasonUnknownUser, nil},
		{"bad password", &CredentialsError{Reason: ReasonBadPassword, UserID: "user-9"}, ReasonBadPassword, "user-9"},
		{"provider without reason", ErrInvalidCredentials, ReasonInvalidCredentials, nil},
		{"storage failure", errors.New("db down"), reasonInternalError, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockProvider{authenticateFn: func(context.Context, *entity.AuthRequest) (*entity.Identity, error) {
				return nil, tt.err
			}}
			client, sink := serveAudited(t, newServiceWithProvider(t, provider, newMemStore(t)))

			_, err := client.Login(ctx, withUA(&authv1.LoginRequest{Email: identifier, Password: password}))
			require.Error(t, err)

			out := sink.raw()
			recs := sink.records(t)
			require.Len(t, recs, 1)
			rec := requireAuditEvent(t, recs[0], auditEventLogin, auditResultFailure)
			assert.Equal(t, tt.wantReason, rec["reason"])
			assert.Equal(t, tt.wantUserID, rec["user_id"])
			assertNoSecrets(t, out, identifier, "hunter2", password)
		})
	}

	t.Run("malformed identifier", func(t *testing.T) {
		svc, _ := setupTestService(t)
		client, sink := serveAudited(t, svc)

		_, err := client.Login(ctx, withUA(&authv1.LoginRequest{Email: "hunter2", Password: password}))
		require.Error(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 1)
		assert.Equal(t, ReasonMalformedCredentials, requireAuditEvent(t, recs[0], auditEventLogin, auditResultFailure)["reason"])
		assertNoSecrets(t, out, "hunter2", password)
	})
}

func TestAudit_OAuth(t *testing.T) {
	ctx := context.Background()

	// signIn runs a whole bearer-mode flow and returns the callback outcome and
	// every secret the flow handled.
	signIn := func(t *testing.T, client authv1connect.AuthServiceClient) (*connect.Response[authv1.OAuthCallbackResponse], []string, error) {
		t.Helper()
		start, err := client.GetOAuthURL(ctx, withUA(&authv1.GetOAuthURLRequest{
			Provider: entity.ProviderTypeGoogle, RedirectUri: testRedirectURI,
		}))
		require.NoError(t, err)
		resp, err := client.OAuthCallback(ctx, withUA(&authv1.OAuthCallbackRequest{
			Provider: entity.ProviderTypeGoogle, Code: "auth-code-secret", State: start.Msg.State,
			RedirectUri: testRedirectURI, Binding: start.Msg.Binding,
		}))
		secrets := []string{"auth-code-secret", start.Msg.State, start.Msg.Binding}
		if resp != nil {
			secrets = append(secrets, resp.Msg.AccessToken, resp.Msg.RefreshToken)
		}
		return resp, secrets, err
	}

	t.Run("new user", func(t *testing.T) {
		svc, _ := setupOAuthService(t, OAuthConfig{}, newFakeGoogle(verifiedInfo("sub-1", "new@example.com")))
		client, sink := serveAudited(t, svc)

		resp, secrets, err := signIn(t, client)
		require.NoError(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 2, "GetOAuthURL writes nothing")
		created := requireAuditEvent(t, recs[0], auditEventUserCreated, auditResultSuccess)
		assert.Equal(t, "oauth", created["method"])
		assert.Equal(t, entity.ProviderTypeGoogle, created["provider"])
		assert.Equal(t, resp.Msg.UserId, created["user_id"])
		signedIn := requireAuditEvent(t, recs[1], auditEventOAuthSignIn, auditResultSuccess)
		assert.Equal(t, entity.ProviderTypeGoogle, signedIn["provider"])
		assert.Equal(t, true, signedIn["new_user"])
		assertNoSecrets(t, out, secrets...)
	})

	t.Run("auto-link", func(t *testing.T) {
		svc, store := setupOAuthService(t, OAuthConfig{}, newFakeGoogle(verifiedInfo("sub-1", "old@example.com")))
		require.NoError(t, store.Create(ctx, &entity.User{ID: "user-old", Email: "old@example.com"}))
		client, sink := serveAudited(t, svc)

		_, secrets, err := signIn(t, client)
		require.NoError(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 2)
		linked := requireAuditEvent(t, recs[0], auditEventOAuthLink, auditResultSuccess)
		assert.Equal(t, "user-old", linked["user_id"])
		assert.Equal(t, entity.ProviderTypeGoogle, linked["provider"])
		assert.Equal(t, false, requireAuditEvent(t, recs[1], auditEventOAuthSignIn, auditResultSuccess)["new_user"])
		assertNoSecrets(t, out, secrets...)

		// The second sign-in finds the link: no link event again.
		_, _, err = signIn(t, client)
		require.NoError(t, err)
		recs = sink.records(t)
		require.Len(t, recs, 1)
		requireAuditEvent(t, recs[0], auditEventOAuthSignIn, auditResultSuccess)
	})

	t.Run("link refused", func(t *testing.T) {
		svc, store := setupOAuthService(t, OAuthConfig{}, newFakeGoogle(verifiedInfo("sub-1", "pw@example.com")))
		require.NoError(t, store.Create(ctx, &entity.User{ID: "user-pw", Email: "pw@example.com"}))
		require.NoError(t, store.SavePasswordHash(ctx, "user-pw", "argon2-hash-secret"))
		client, sink := serveAudited(t, svc)

		_, secrets, err := signIn(t, client)
		require.Error(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 1)
		rec := requireAuditEvent(t, recs[0], auditEventOAuthSignIn, auditResultFailure)
		assert.Equal(t, "account_has_password", rec["reason"])
		assert.Equal(t, entity.ProviderTypeGoogle, rec["provider"])
		assertNoSecrets(t, out, append(secrets, "argon2-hash-secret")...)
	})

	t.Run("invalid state", func(t *testing.T) {
		svc, _ := setupOAuthService(t, OAuthConfig{}, newFakeGoogle(verifiedInfo("sub-1", "new@example.com")))
		client, sink := serveAudited(t, svc)

		_, err := client.OAuthCallback(ctx, withUA(&authv1.OAuthCallbackRequest{
			Provider: entity.ProviderTypeGoogle, Code: "auth-code-secret", State: "forged-state",
			RedirectUri: testRedirectURI, Binding: "forged-binding",
		}))
		require.Error(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 1)
		assert.Equal(t, "invalid_state", requireAuditEvent(t, recs[0], auditEventOAuthSignIn, auditResultFailure)["reason"])
		assertNoSecrets(t, out, "auth-code-secret", "forged-state", "forged-binding")
	})

	t.Run("invalid request", func(t *testing.T) {
		svc, _ := setupOAuthService(t, OAuthConfig{})
		client, sink := serveAudited(t, svc)

		_, err := client.OAuthCallback(ctx, withUA(&authv1.OAuthCallbackRequest{Provider: entity.ProviderTypeGoogle}))
		require.Error(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 1)
		assert.Equal(t, reasonInvalidRequest, requireAuditEvent(t, recs[0], auditEventOAuthSignIn, auditResultFailure)["reason"])
	})
}

func TestAudit_Wallet(t *testing.T) {
	ctx := context.Background()
	svc, _ := setupWalletService(t)
	client, sink := serveAudited(t, svc)
	signer := newTestSigner(t, evmtest.Key0)

	signIn := func(t *testing.T) (*authv1.AuthenticateWalletRequest, *connect.Response[authv1.AuthenticateWalletResponse]) {
		t.Helper()
		ch, err := client.GetChallenge(ctx, withUA(&authv1.GetChallengeRequest{Chain: "ethereum", Address: signer.Address}))
		require.NoError(t, err)
		msg := &authv1.AuthenticateWalletRequest{
			Chain: "ethereum", Address: signer.Address, Nonce: ch.Msg.Nonce, Signature: signer.Sign(ch.Msg.Message),
		}
		resp, err := client.AuthenticateWallet(ctx, withUA(msg))
		require.NoError(t, err)
		return msg, resp
	}

	msg, resp := signIn(t)
	out := sink.raw()
	recs := sink.records(t)
	require.Len(t, recs, 2, "GetChallenge writes nothing")
	created := requireAuditEvent(t, recs[0], auditEventUserCreated, auditResultSuccess)
	assert.Equal(t, "wallet", created["method"])
	assert.Equal(t, "ethereum", created["chain"])
	assert.Equal(t, resp.Msg.UserId, created["user_id"])
	signedIn := requireAuditEvent(t, recs[1], auditEventWalletSignIn, auditResultSuccess)
	assert.Equal(t, "ethereum", signedIn["chain"])
	assert.Equal(t, true, signedIn["new_user"])
	assertNoSecrets(t, out, msg.Signature, msg.Nonce, resp.Msg.AccessToken, resp.Msg.RefreshToken)

	// A returning wallet signs in without creating a user.
	_, _ = signIn(t)
	recs = sink.records(t)
	require.Len(t, recs, 1)
	assert.Equal(t, false, requireAuditEvent(t, recs[0], auditEventWalletSignIn, auditResultSuccess)["new_user"])

	// A replayed signature is refused.
	_, err := client.AuthenticateWallet(ctx, withUA(msg))
	require.Error(t, err)
	out = sink.raw()
	recs = sink.records(t)
	require.Len(t, recs, 1)
	rec := requireAuditEvent(t, recs[0], auditEventWalletSignIn, auditResultFailure)
	assert.Equal(t, "invalid_challenge", rec["reason"])
	assert.Equal(t, "ethereum", rec["chain"])
	assertNoSecrets(t, out, msg.Signature, msg.Nonce)

	_, err = client.AuthenticateWallet(ctx, withUA(&authv1.AuthenticateWalletRequest{Chain: "ethereum"}))
	require.Error(t, err)
	recs = sink.records(t)
	require.Len(t, recs, 1)
	assert.Equal(t, reasonInvalidRequest, requireAuditEvent(t, recs[0], auditEventWalletSignIn, auditResultFailure)["reason"])
}

// Verify is the hot ForwardAuth path and refresh is routine: neither audits.
func TestAudit_SilentPaths(t *testing.T) {
	ctx := context.Background()
	svc, store := setupTestService(t)
	reg := registerUser(t, store, "user@example.com", "SecurePassword123!", svc)
	client, sink := serveAudited(t, svc)

	verify := connect.NewRequest(&authv1.VerifyRequest{})
	verify.Header().Set("Authorization", "Bearer "+reg.TokenPair.AccessToken)
	_, err := client.Verify(ctx, verify)
	require.NoError(t, err)

	bad := connect.NewRequest(&authv1.VerifyRequest{})
	bad.Header().Set("Authorization", "Bearer not-a-token")
	_, err = client.Verify(ctx, bad)
	require.Error(t, err)

	_, err = client.Refresh(ctx, connect.NewRequest(&authv1.RefreshRequest{RefreshToken: reg.TokenPair.RefreshToken}))
	require.NoError(t, err)

	assert.Empty(t, sink.raw())
}

func TestAudit_UserAgentTruncated(t *testing.T) {
	svc, _ := setupTestService(t)
	client, sink := serveAudited(t, svc)

	req := connect.NewRequest(&authv1.LoginRequest{Email: "x", Password: "y"})
	req.Header().Set("User-Agent", strings.Repeat("a", 10*maxAuditValue))
	_, err := client.Login(context.Background(), req)
	require.Error(t, err)

	recs := sink.records(t)
	require.Len(t, recs, 1)
	assert.Len(t, recs[0]["user_agent"], maxAuditValue)
}

func TestCredentialsError(t *testing.T) {
	err := &CredentialsError{Reason: ReasonBadPassword, UserID: "user-1"}
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.NotErrorIs(t, err, ErrUserNotFound)
	assert.Equal(t, "invalid credentials: bad_password", err.Error())
}
