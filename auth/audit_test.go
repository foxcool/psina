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
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/api/auth/v1"
	"github.com/foxcool/psina/api/auth/v1/authv1connect"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/oauth"
	"github.com/foxcool/psina/provider/wallet/evm/evmtest"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/token"
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
	require.NoError(t, store.Create(ctx, &entity.User{ID: "user-123", Email: email}))
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
		{"empty reason", &CredentialsError{}, ReasonInvalidCredentials, nil},
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

// auditOAuthSignIn runs a whole bearer-mode flow and returns the callback
// outcome and every secret the flow handled.
func auditOAuthSignIn(t *testing.T, client authv1connect.AuthServiceClient) (*connect.Response[authv1.OAuthCallbackResponse], []string, error) {
	t.Helper()
	ctx := context.Background()
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

func TestAudit_OAuth(t *testing.T) {
	ctx := context.Background()

	t.Run("new user", func(t *testing.T) {
		svc, _ := setupOAuthService(t, OAuthConfig{}, newFakeGoogle(verifiedInfo("sub-1", "new@example.com")))
		client, sink := serveAudited(t, svc)

		resp, secrets, err := auditOAuthSignIn(t, client)
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

		_, secrets, err := auditOAuthSignIn(t, client)
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
		_, _, err = auditOAuthSignIn(t, client)
		require.NoError(t, err)
		recs = sink.records(t)
		require.Len(t, recs, 1)
		requireAuditEvent(t, recs[0], auditEventOAuthSignIn, auditResultSuccess)
	})

	t.Run("password dropped", func(t *testing.T) {
		svc, store := setupOAuthService(t, OAuthConfig{}, newFakeGoogle(verifiedInfo("sub-1", "pw@example.com")))
		require.NoError(t, store.Create(ctx, &entity.User{ID: "user-pw", Email: "pw@example.com"}))
		require.NoError(t, store.SavePasswordHash(ctx, "user-pw", "argon2-hash-secret"))
		client, sink := serveAudited(t, svc)

		_, secrets, err := auditOAuthSignIn(t, client)
		require.NoError(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 3)
		dropped := requireAuditEvent(t, recs[0], auditEventPasswordDropped, auditResultSuccess)
		assert.Equal(t, "user-pw", dropped["user_id"])
		assert.Equal(t, entity.ProviderTypeGoogle, dropped["provider"])
		linked := requireAuditEvent(t, recs[1], auditEventOAuthLink, auditResultSuccess)
		assert.Equal(t, "user-pw", linked["user_id"])
		requireAuditEvent(t, recs[2], auditEventOAuthSignIn, auditResultSuccess)
		assertNoSecrets(t, out, append(secrets, "argon2-hash-secret")...)
	})

	t.Run("link refused", func(t *testing.T) {
		svc, store := setupOAuthService(t, OAuthConfig{}, newFakeGoogle(verifiedInfo("sub-1", "pw@example.com")))
		require.NoError(t, store.Create(ctx, &entity.User{ID: "user-pw", Email: "pw@example.com"}))
		require.NoError(t, store.SavePasswordHash(ctx, "user-pw", "argon2-hash-secret"))
		// An identity proves the account's ownership: it is not taken over.
		require.NoError(t, store.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
			ID: "gh", UserID: "user-pw", Provider: entity.ProviderTypeGitHub, ExternalID: "42",
		}))
		client, sink := serveAudited(t, svc)

		_, secrets, err := auditOAuthSignIn(t, client)
		require.Error(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 1)
		rec := requireAuditEvent(t, recs[0], auditEventOAuthSignIn, auditResultFailure)
		assert.Equal(t, "account_has_password", rec["reason"])
		assert.Equal(t, entity.ProviderTypeGoogle, rec["provider"])
		assert.Equal(t, "user-pw", rec["user_id"], "the account the link targeted")
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
	assert.Equal(t, ErrInvalidCredentials.Error(), err.Error())
}

// failingTokens fails every refresh token save: the last step of a sign-in,
// after the account was created or linked.
type failingTokens struct{ *memory.Store }

func (failingTokens) SaveRefreshToken(context.Context, *entity.RefreshToken) error {
	return errors.New("db down")
}

// failingUserLookup fails every user lookup by ID.
type failingUserLookup struct{ *memory.Store }

func (failingUserLookup) GetByID(context.Context, string) (*entity.User, error) {
	return nil, errors.New("db down")
}

// A creation or link committed before the sign-in failed stands, so it is
// recorded, and the failure names the account.
func TestAudit_AccountChangeBeforeFailure(t *testing.T) {
	ctx := context.Background()
	newService := func(t *testing.T, memStore *memory.Store, opts ...ServiceOption) *Service {
		t.Helper()
		issuer, err := token.New()
		require.NoError(t, err)
		return NewService(failingTokens{memStore}, memStore, issuer, []Provider{&mockProvider{}}, opts...)
	}
	withGoogle := func(memStore *memory.Store, email string) ServiceOption {
		return WithOAuth([]oauth.Provider{newFakeGoogle(verifiedInfo("sub-1", email))}, memStore, memStore, OAuthConfig{})
	}

	t.Run("register", func(t *testing.T) {
		client, sink := serveAudited(t, newService(t, memory.New()))

		_, err := client.Register(ctx, withUA(&authv1.RegisterRequest{Email: "user@example.com", Password: "SecurePassword123!"}))
		require.Error(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 1)
		rec := requireAuditEvent(t, recs[0], auditEventRegister, auditResultFailure)
		assert.Equal(t, reasonInternalError, rec["reason"])
		assert.Equal(t, "user-123", rec["user_id"])
	})

	t.Run("login", func(t *testing.T) {
		memStore := memory.New()
		require.NoError(t, memStore.Create(ctx, &entity.User{ID: "user-123", Email: "user@example.com"}))
		client, sink := serveAudited(t, newService(t, memStore))

		_, err := client.Login(ctx, withUA(&authv1.LoginRequest{Email: "user@example.com", Password: "SecurePassword123!"}))
		require.Error(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 1)
		rec := requireAuditEvent(t, recs[0], auditEventLogin, auditResultFailure)
		assert.Equal(t, reasonInternalError, rec["reason"])
		assert.Equal(t, "user-123", rec["user_id"])
	})

	t.Run("login, user lookup fails", func(t *testing.T) {
		memStore := memory.New()
		issuer, err := token.New()
		require.NoError(t, err)
		svc := NewService(memStore, failingUserLookup{memStore}, issuer, []Provider{&mockProvider{}})
		client, sink := serveAudited(t, svc)

		_, err = client.Login(ctx, withUA(&authv1.LoginRequest{Email: "user@example.com", Password: "SecurePassword123!"}))
		require.Error(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 1)
		assert.Equal(t, "user-123", requireAuditEvent(t, recs[0], auditEventLogin, auditResultFailure)["user_id"])
	})

	t.Run("oauth new user", func(t *testing.T) {
		memStore := memory.New()
		client, sink := serveAudited(t, newService(t, memStore, withGoogle(memStore, "new@example.com")))

		_, _, err := auditOAuthSignIn(t, client)
		require.Error(t, err)

		user, err := memStore.GetByEmail(ctx, "new@example.com")
		require.NoError(t, err, "the account stays")
		recs := sink.records(t)
		require.Len(t, recs, 2)
		created := requireAuditEvent(t, recs[0], auditEventUserCreated, auditResultSuccess)
		assert.Equal(t, user.ID, created["user_id"])
		assert.Equal(t, string(auditMethodOAuth), created["method"])
		failed := requireAuditEvent(t, recs[1], auditEventOAuthSignIn, auditResultFailure)
		assert.Equal(t, reasonInternalError, failed["reason"])
		assert.Equal(t, user.ID, failed["user_id"])
	})

	t.Run("oauth auto-link", func(t *testing.T) {
		memStore := memory.New()
		require.NoError(t, memStore.Create(ctx, &entity.User{ID: "user-old", Email: "old@example.com"}))
		client, sink := serveAudited(t, newService(t, memStore, withGoogle(memStore, "old@example.com")))

		_, _, err := auditOAuthSignIn(t, client)
		require.Error(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 2)
		assert.Equal(t, "user-old", requireAuditEvent(t, recs[0], auditEventOAuthLink, auditResultSuccess)["user_id"])
		assert.Equal(t, "user-old", requireAuditEvent(t, recs[1], auditEventOAuthSignIn, auditResultFailure)["user_id"])
	})

	t.Run("oauth password account takeover", func(t *testing.T) {
		memStore := memory.New()
		require.NoError(t, memStore.Create(ctx, &entity.User{ID: "user-pw", Email: "pw@example.com"}))
		require.NoError(t, memStore.SavePasswordHash(ctx, "user-pw", "hash"))
		client, sink := serveAudited(t, newService(t, memStore, withGoogle(memStore, "pw@example.com")))

		_, _, err := auditOAuthSignIn(t, client)
		require.Error(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 3, "the takeover stands")
		assert.Equal(t, "user-pw", requireAuditEvent(t, recs[0], auditEventPasswordDropped, auditResultSuccess)["user_id"])
		assert.Equal(t, "user-pw", requireAuditEvent(t, recs[1], auditEventOAuthLink, auditResultSuccess)["user_id"])
		assert.Equal(t, "user-pw", requireAuditEvent(t, recs[2], auditEventOAuthSignIn, auditResultFailure)["user_id"])
	})

	t.Run("wallet new user", func(t *testing.T) {
		memStore := memory.New()
		svc := newService(t, memStore, WithWallet(walletTestDispatcher(), memStore, memStore, testWalletConfig))
		client, sink := serveAudited(t, svc)
		signer := newTestSigner(t, evmtest.Key0)

		ch, err := client.GetChallenge(ctx, withUA(&authv1.GetChallengeRequest{Chain: "ethereum", Address: signer.Address}))
		require.NoError(t, err)
		_, err = client.AuthenticateWallet(ctx, withUA(&authv1.AuthenticateWalletRequest{
			Chain: "ethereum", Address: signer.Address, Nonce: ch.Msg.Nonce, Signature: signer.Sign(ch.Msg.Message),
		}))
		require.Error(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 2)
		created := requireAuditEvent(t, recs[0], auditEventUserCreated, auditResultSuccess)
		assert.Equal(t, string(auditMethodWallet), created["method"])
		failed := requireAuditEvent(t, recs[1], auditEventWalletSignIn, auditResultFailure)
		assert.Equal(t, reasonInternalError, failed["reason"])
		assert.Equal(t, created["user_id"], failed["user_id"])
	})
}

func TestAudit_SessionEvents(t *testing.T) {
	ctx := context.Background()

	t.Run("logout", func(t *testing.T) {
		svc, store := setupTestService(t)
		reg := registerUser(t, store, "user@example.com", "SecurePassword123!", svc)
		client, sink := serveAudited(t, svc)

		_, err := client.Logout(ctx, withUA(&authv1.LogoutRequest{RefreshToken: reg.TokenPair.RefreshToken}))
		require.NoError(t, err)
		_, err = client.Logout(ctx, withUA(&authv1.LogoutRequest{RefreshToken: "not-a-token"}))
		require.NoError(t, err, "logout of an unknown token still answers success")
		_, err = client.Logout(ctx, withUA(&authv1.LogoutRequest{}))
		require.NoError(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 3)
		assert.Equal(t, "user-123", requireAuditEvent(t, recs[0], auditEventLogout, auditResultSuccess)["user_id"])
		unknown := requireAuditEvent(t, recs[1], auditEventLogout, auditResultFailure)
		assert.Equal(t, "unknown_token", unknown["reason"])
		assert.NotContains(t, unknown, "user_id")
		assert.Equal(t, reasonInvalidRequest, requireAuditEvent(t, recs[2], auditEventLogout, auditResultFailure)["reason"])
		assertNoSecrets(t, out, reg.TokenPair.RefreshToken, token.HashToken(reg.TokenPair.RefreshToken), "not-a-token")
	})

	t.Run("refresh failures", func(t *testing.T) {
		svc, store := setupTestService(t, WithRefreshReuseLeeway(0))
		reg := registerUser(t, store, "user@example.com", "SecurePassword123!", svc)
		client, sink := serveAudited(t, svc)
		r1 := reg.TokenPair.RefreshToken

		r2, err := client.Refresh(ctx, withUA(&authv1.RefreshRequest{RefreshToken: r1}))
		require.NoError(t, err, "a successful refresh is not audited")
		_, err = client.Refresh(ctx, withUA(&authv1.RefreshRequest{RefreshToken: r1}))
		require.Error(t, err)
		_, err = client.Refresh(ctx, withUA(&authv1.RefreshRequest{RefreshToken: "not-a-token"}))
		require.Error(t, err)
		_, err = client.Refresh(ctx, withUA(&authv1.RefreshRequest{}))
		require.Error(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 3)
		reuse := requireAuditEvent(t, recs[0], auditEventRefresh, auditResultFailure)
		assert.Equal(t, "token_reuse", reuse["reason"])
		assert.Equal(t, "user-123", reuse["user_id"])
		unknown := requireAuditEvent(t, recs[1], auditEventRefresh, auditResultFailure)
		assert.Equal(t, "unknown_token", unknown["reason"])
		assert.NotContains(t, unknown, "user_id")
		assert.Equal(t, reasonInvalidRequest, requireAuditEvent(t, recs[2], auditEventRefresh, auditResultFailure)["reason"])
		assertNoSecrets(t, out, r1, r2.Msg.RefreshToken, r2.Msg.AccessToken,
			token.HashToken(r1), token.HashToken(r2.Msg.RefreshToken), "not-a-token")
		assert.NotContains(t, out, "token reuse detected", "the ad-hoc diagnostic record is gone")
	})

	t.Run("refresh after logout is not reuse", func(t *testing.T) {
		svc, store := setupTestService(t)
		reg := registerUser(t, store, "user@example.com", "SecurePassword123!", svc)
		client, sink := serveAudited(t, svc)
		r1 := reg.TokenPair.RefreshToken

		_, err := client.Logout(ctx, withUA(&authv1.LogoutRequest{RefreshToken: r1}))
		require.NoError(t, err)
		_, err = client.Refresh(ctx, withUA(&authv1.RefreshRequest{RefreshToken: r1}))
		assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

		recs := sink.records(t)
		require.Len(t, recs, 2)
		requireAuditEvent(t, recs[0], auditEventLogout, auditResultSuccess)
		rec := requireAuditEvent(t, recs[1], auditEventRefresh, auditResultFailure)
		assert.Equal(t, "token_revoked", rec["reason"])
		assert.Equal(t, "user-123", rec["user_id"])
	})

	t.Run("refresh expired", func(t *testing.T) {
		clock := newFakeClock()
		svc, store := setupTestService(t, WithClock(clock.Now))
		reg := registerUser(t, store, "user@example.com", "SecurePassword123!", svc)
		client, sink := serveAudited(t, svc)

		clock.Advance(token.RefreshTokenTTL + time.Minute)
		_, err := client.Refresh(ctx, withUA(&authv1.RefreshRequest{RefreshToken: reg.TokenPair.RefreshToken}))
		require.Error(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 1)
		assert.Equal(t, "token_expired", requireAuditEvent(t, recs[0], auditEventRefresh, auditResultFailure)["reason"])
	})

	t.Run("refresh racing a logout", func(t *testing.T) {
		memStore := memory.New()
		issuer, err := token.New()
		require.NoError(t, err)
		racy := &logoutBeforeSave{Store: memStore}
		svc := NewService(racy, memStore, issuer, []Provider{&mockProvider{}})
		r1 := registerForRefresh(t, svc, memStore)
		racy.root = token.HashToken(r1)
		client, sink := serveAudited(t, svc)

		_, err = client.Refresh(ctx, withUA(&authv1.RefreshRequest{RefreshToken: r1}))
		assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

		recs := sink.records(t)
		require.Len(t, recs, 1)
		rec := requireAuditEvent(t, recs[0], auditEventRefresh, auditResultFailure)
		assert.Equal(t, "session_ended", rec["reason"])
		assert.Equal(t, "user-123", rec["user_id"])
	})
}

func TestAudit_PATEvents(t *testing.T) {
	ctx := context.Background()
	bearer := func(req connect.AnyRequest, tok string) {
		req.Header().Set("Authorization", "Bearer "+tok)
	}

	t.Run("create and revoke", func(t *testing.T) {
		svc, store := setupTestService(t)
		reg := registerUser(t, store, "user@example.com", "SecurePassword123!", svc)
		client, sink := serveAudited(t, svc)

		expiresAt := time.Now().Add(24 * time.Hour).Unix()
		create := withUA(&authv1.CreatePersonalAccessTokenRequest{Name: "ci", ExpiresAt: expiresAt})
		bearer(create, reg.TokenPair.AccessToken)
		created, err := client.CreatePersonalAccessToken(ctx, create)
		require.NoError(t, err)

		revoke := withUA(&authv1.RevokePersonalAccessTokenRequest{Id: created.Msg.Pat.Id})
		bearer(revoke, reg.TokenPair.AccessToken)
		_, err = client.RevokePersonalAccessToken(ctx, revoke)
		require.NoError(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 2)
		wantExpiry := time.Unix(expiresAt, 0).UTC().Format(time.RFC3339)
		for i, event := range []string{auditEventPATCreate, auditEventPATRevoke} {
			rec := requireAuditEvent(t, recs[i], event, auditResultSuccess)
			assert.Equal(t, "user-123", rec["user_id"])
			assert.Equal(t, created.Msg.Pat.Id, rec["pat_id"])
			assert.Equal(t, "ci", rec["name"])
			assert.Equal(t, wantExpiry, rec["expires_at"])
		}
		assertNoSecrets(t, out, created.Msg.Token, token.HashToken(created.Msg.Token), reg.TokenPair.AccessToken)
	})

	t.Run("no expiry", func(t *testing.T) {
		svc, store := setupTestService(t)
		reg := registerUser(t, store, "user@example.com", "SecurePassword123!", svc)
		client, sink := serveAudited(t, svc)

		create := withUA(&authv1.CreatePersonalAccessTokenRequest{Name: "ci"})
		bearer(create, reg.TokenPair.AccessToken)
		_, err := client.CreatePersonalAccessToken(ctx, create)
		require.NoError(t, err)

		recs := sink.records(t)
		require.Len(t, recs, 1)
		assert.NotContains(t, requireAuditEvent(t, recs[0], auditEventPATCreate, auditResultSuccess), "expires_at")
	})

	t.Run("failures", func(t *testing.T) {
		svc, store := setupTestService(t)
		reg := registerUser(t, store, "user@example.com", "SecurePassword123!", svc)
		pat, err := svc.CreatePAT(ctx, reg.UserID, "seed", nil, nil)
		require.NoError(t, err)
		client, sink := serveAudited(t, svc)

		noName := withUA(&authv1.CreatePersonalAccessTokenRequest{})
		bearer(noName, reg.TokenPair.AccessToken)
		_, err = client.CreatePersonalAccessToken(ctx, noName)
		require.Error(t, err)

		byPAT := withUA(&authv1.CreatePersonalAccessTokenRequest{Name: "ci"})
		bearer(byPAT, pat.Plaintext)
		_, err = client.CreatePersonalAccessToken(ctx, byPAT)
		require.Error(t, err)

		noSession := withUA(&authv1.RevokePersonalAccessTokenRequest{Id: pat.Token.ID})
		_, err = client.RevokePersonalAccessToken(ctx, noSession)
		require.Error(t, err)

		unknown := withUA(&authv1.RevokePersonalAccessTokenRequest{Id: "00000000-0000-0000-0000-000000000000"})
		bearer(unknown, reg.TokenPair.AccessToken)
		_, err = client.RevokePersonalAccessToken(ctx, unknown)
		require.Error(t, err)

		out := sink.raw()
		recs := sink.records(t)
		require.Len(t, recs, 4)

		rec := requireAuditEvent(t, recs[0], auditEventPATCreate, auditResultFailure)
		assert.Equal(t, "name_required", rec["reason"])
		assert.Equal(t, "user-123", rec["user_id"])

		rec = requireAuditEvent(t, recs[1], auditEventPATCreate, auditResultFailure)
		assert.Equal(t, "pat_not_allowed", rec["reason"])
		assert.NotContains(t, rec, "user_id")

		rec = requireAuditEvent(t, recs[2], auditEventPATRevoke, auditResultFailure)
		assert.Equal(t, "invalid_session", rec["reason"])
		assert.Equal(t, pat.Token.ID, rec["pat_id"])

		rec = requireAuditEvent(t, recs[3], auditEventPATRevoke, auditResultFailure)
		assert.Equal(t, "not_found", rec["reason"])
		assert.Equal(t, "user-123", rec["user_id"])

		assertNoSecrets(t, out, pat.Plaintext, pat.Token.Hash, reg.TokenPair.AccessToken)
	})
}
