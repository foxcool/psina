package local_test

import (
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
	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/local"
	psinastore "github.com/foxcool/psina/store"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider_Register(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	req := &entity.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	identity, err := provider.Register(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, identity.UserID)
	assert.Equal(t, "test@example.com", identity.Email)
	assert.Equal(t, "local", identity.Provider)
}

func TestProvider_RegisterDuplicateEmail(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	req := &entity.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	// First registration
	_, err := provider.Register(context.Background(), req)
	require.NoError(t, err)

	// Second registration with same email should fail
	_, err = provider.Register(context.Background(), req)
	assert.ErrorIs(t, err, psinastore.ErrUserExists)
}

func TestProvider_Authenticate(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	// Register user
	registerReq := &entity.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}
	_, err := provider.Register(context.Background(), registerReq)
	require.NoError(t, err)

	// Authenticate
	authReq := &entity.AuthRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}
	identity, err := provider.Authenticate(context.Background(), authReq)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", identity.Email)
	assert.Equal(t, "local", identity.Provider)
}

func TestProvider_AuthenticateWrongPassword(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	// Register user
	registerReq := &entity.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}
	_, err := provider.Register(context.Background(), registerReq)
	require.NoError(t, err)

	// Authenticate with wrong password
	authReq := &entity.AuthRequest{
		Email:    "test@example.com",
		Password: "WrongPassword",
	}
	_, err = provider.Authenticate(context.Background(), authReq)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestProvider_AuthenticateNonexistentUser(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	authReq := &entity.AuthRequest{
		Email:    "nonexistent@example.com",
		Password: "password",
	}
	_, err := provider.Authenticate(context.Background(), authReq)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestProvider_PasswordHashing(t *testing.T) {
	store := memory.New()
	provider := local.New(store, store)

	// Register two users with same password
	req1 := &entity.RegisterRequest{
		Email:    "user1@example.com",
		Password: "SamePassword123!",
	}
	identity1, err := provider.Register(context.Background(), req1)
	require.NoError(t, err)

	req2 := &entity.RegisterRequest{
		Email:    "user2@example.com",
		Password: "SamePassword123!",
	}
	identity2, err := provider.Register(context.Background(), req2)
	require.NoError(t, err)

	// Password hashes should be different (different salts)
	hash1, err := store.GetPasswordHash(context.Background(), identity1.UserID)
	require.NoError(t, err)

	hash2, err := store.GetPasswordHash(context.Background(), identity2.UserID)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "Password hashes should differ due to random salts")
}

// failingCredentialStore always fails on SavePasswordHash
type failingCredentialStore struct {
	auth.CredentialStore
}

func (f *failingCredentialStore) SavePasswordHash(ctx context.Context, userID, hash string) error {
	return errDBDown
}

func (f *failingCredentialStore) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	return "", errDBDown
}

func TestProvider_RegisterCompensatingDelete(t *testing.T) {
	userStore := memory.New()
	credStore := &failingCredentialStore{}
	provider := local.New(userStore, credStore)

	req := &entity.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	// Registration should fail due to credential store error
	_, err := provider.Register(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store password")

	// User should NOT exist (compensating delete worked)
	_, err = userStore.GetByEmail(context.Background(), "test@example.com")
	assert.Error(t, err, "user should be deleted after credential store failure")
}

// brokenUserStore fails every call it overrides; the rest delegate to the embedded store.
type brokenUserStore struct {
	auth.UserStore
	failGetByEmail bool
	failDelete     bool
	created        bool
}

var errDBDown = errors.New("database connection lost")

func (b *brokenUserStore) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	if b.failGetByEmail {
		return nil, errDBDown
	}
	return b.UserStore.GetByEmail(ctx, email)
}

func (b *brokenUserStore) Create(ctx context.Context, user *entity.User) error {
	b.created = true
	return b.UserStore.Create(ctx, user)
}

func (b *brokenUserStore) Delete(ctx context.Context, id string) error {
	if b.failDelete {
		return errDBDown
	}
	return b.UserStore.Delete(ctx, id)
}

func TestProvider_StorageFailuresAreNotMasked(t *testing.T) {
	ctx := context.Background()

	t.Run("register lookup failure", func(t *testing.T) {
		mem := memory.New()
		users := &brokenUserStore{UserStore: mem, failGetByEmail: true}
		provider := local.New(users, mem)

		_, err := provider.Register(ctx, &entity.RegisterRequest{Email: "a@example.com", Password: "SecurePassword123!"})
		require.ErrorIs(t, err, errDBDown)
		assert.NotErrorIs(t, err, psinastore.ErrUserExists)
		assert.False(t, users.created, "must not create a user when the duplicate check failed")
	})

	t.Run("authenticate user lookup failure", func(t *testing.T) {
		mem := memory.New()
		provider := local.New(&brokenUserStore{UserStore: mem, failGetByEmail: true}, mem)

		_, err := provider.Authenticate(ctx, &entity.AuthRequest{Email: "a@example.com", Password: "x"})
		require.ErrorIs(t, err, errDBDown)
		assert.NotErrorIs(t, err, auth.ErrInvalidCredentials)
	})

	t.Run("authenticate credential lookup failure", func(t *testing.T) {
		mem := memory.New()
		require.NoError(t, mem.Create(ctx, &entity.User{ID: "u1", Email: "a@example.com"}))
		provider := local.New(mem, &failingCredentialStore{})

		_, err := provider.Authenticate(ctx, &entity.AuthRequest{Email: "a@example.com", Password: "x"})
		require.ErrorIs(t, err, errDBDown)
		assert.NotErrorIs(t, err, auth.ErrInvalidCredentials)
	})
}

func TestProvider_RegisterRollbackFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	mem := memory.New()
	provider := local.New(&brokenUserStore{UserStore: mem, failDelete: true}, &failingCredentialStore{})

	_, err := provider.Register(context.Background(), &entity.RegisterRequest{Email: "a@example.com", Password: "SecurePassword123!"})
	require.Error(t, err)
	assert.Contains(t, buf.String(), "rollback of user without credentials failed")
}

// The handler maps service sentinels to Connect codes; this guards the whole chain
// with the real provider, which mock-provider tests in package auth cannot.
func TestProvider_ConnectCodesThroughHandler(t *testing.T) {
	mem := memory.New()
	issuer, err := token.New()
	require.NoError(t, err)
	svc := auth.NewService(mem, mem, issuer, []auth.Provider{local.New(mem, mem)})
	handler := auth.NewHandler(svc)
	ctx := context.Background()

	_, err = handler.Register(ctx, connect.NewRequest(&authv1.RegisterRequest{
		Email: "dup@example.com", Password: "SecurePassword123!",
	}))
	require.NoError(t, err)

	tests := []struct {
		name string
		call func() error
		want connect.Code
	}{
		{"duplicate register", func() error {
			_, err := handler.Register(ctx, connect.NewRequest(&authv1.RegisterRequest{
				Email: "dup@example.com", Password: "AnotherPassword123!",
			}))
			return err
		}, connect.CodeAlreadyExists},
		{"wrong password", func() error {
			_, err := handler.Login(ctx, connect.NewRequest(&authv1.LoginRequest{
				Email: "dup@example.com", Password: "WrongPassword123!",
			}))
			return err
		}, connect.CodeUnauthenticated},
		{"unknown user", func() error {
			_, err := handler.Login(ctx, connect.NewRequest(&authv1.LoginRequest{
				Email: "nobody@example.com", Password: "WrongPassword123!",
			}))
			return err
		}, connect.CodeUnauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, connect.CodeOf(tt.call()))
		})
	}
}

// Each rejection tells the audit log why, and only an account that exists is
// named; the entered identifier is never part of the error.
func TestProvider_AuthenticateFailureReasons(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	provider := local.New(store, store)
	identity, err := provider.Register(ctx, &entity.RegisterRequest{Email: "user@example.com", Password: "SecurePassword123!"})
	require.NoError(t, err)
	require.NoError(t, store.Create(ctx, &entity.User{ID: "wallet-user", Email: "nopass@example.com"}))

	tests := []struct {
		name       string
		email      string
		password   string
		wantReason string
		wantUserID string
	}{
		{"unknown user", "nobody@example.com", "SecurePassword123!", auth.ReasonUnknownUser, ""},
		{"bad password", "user@example.com", "WrongPassword123!", auth.ReasonBadPassword, identity.UserID},
		{"no password", "nopass@example.com", "SecurePassword123!", auth.ReasonNoPassword, "wallet-user"},
		{"empty password", "user@example.com", "", auth.ReasonMalformedCredentials, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.Authenticate(ctx, &entity.AuthRequest{Email: tt.email, Password: tt.password})
			require.ErrorIs(t, err, auth.ErrInvalidCredentials)
			var cerr *auth.CredentialsError
			require.ErrorAs(t, err, &cerr)
			assert.Equal(t, tt.wantReason, cerr.Reason)
			assert.Equal(t, tt.wantUserID, cerr.UserID)
			assert.NotContains(t, err.Error(), tt.email)
		})
	}
}

// Audit events of the password flows, end to end over HTTP with the real
// provider: failed logins carry the reason, never what the user typed.
func TestProvider_AuditEvents(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	issuer, err := token.New()
	require.NoError(t, err)
	var buf syncBuffer
	handler := auth.NewHandler(
		auth.NewService(mem, mem, issuer, []auth.Provider{local.New(mem, mem)}),
		auth.WithAuditLogger(slog.New(slog.NewJSONHandler(&buf, nil))),
	)
	path, rpc := authv1connect.NewAuthServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, rpc)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := authv1connect.NewAuthServiceClient(srv.Client(), srv.URL)

	const email, password = "user@example.com", "SecurePassword123!"
	reg, err := client.Register(ctx, connect.NewRequest(&authv1.RegisterRequest{Email: email, Password: password}))
	require.NoError(t, err)

	// What a user might type: a password in the identifier field, a near miss.
	attempts := []struct{ email, password, reason string }{
		{"Pa55word-in-the-email-field", "AnotherSecret123!", auth.ReasonMalformedCredentials},
		{"typo@example.com", "AnotherSecret123!", auth.ReasonUnknownUser},
		{email, "AnotherSecret123!", auth.ReasonBadPassword},
	}
	for _, a := range attempts {
		_, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{Email: a.email, Password: a.password}))
		require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	}
	login, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{Email: email, Password: password}))
	require.NoError(t, err)

	out := buf.String()
	var recs []map[string]any
	for line := range strings.Lines(out) {
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		recs = append(recs, rec)
	}
	require.Len(t, recs, 5)
	for _, rec := range recs {
		assert.Equal(t, true, rec["audit"])
		assert.Equal(t, "127.0.0.1", rec["ip"])
	}
	assert.Equal(t, "register", recs[0]["event"])
	assert.Equal(t, "success", recs[0]["result"])
	for i, a := range attempts {
		rec := recs[i+1]
		assert.Equal(t, "login", rec["event"])
		assert.Equal(t, "failure", rec["result"])
		assert.Equal(t, a.reason, rec["reason"])
	}
	assert.Equal(t, reg.Msg.UserId, recs[3]["user_id"], "a known account is named")
	assert.Equal(t, "success", recs[4]["result"])

	for _, secret := range []string{
		"Pa55word", "typo@example.com", email, password, "AnotherSecret123!", "argon2",
		reg.Msg.AccessToken, reg.Msg.RefreshToken, login.Msg.AccessToken, login.Msg.RefreshToken,
	} {
		assert.NotContains(t, out, secret)
	}
}

// syncBuffer is written by the server goroutine and read by the test; the
// socket between them is not a synchronisation the race detector sees.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
