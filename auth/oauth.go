package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/oauth"
	"github.com/foxcool/psina/store"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// OAuth service errors.
var (
	ErrOAuthDisabled        = errors.New("oauth sign-in is disabled")
	ErrOAuthProviderUnknown = errors.New("unknown oauth provider")
	// ErrOAuthStateInvalid covers every state failure (unknown, expired,
	// replayed, bound to another provider, redirect URI or browser) so the
	// caller cannot tell them apart.
	ErrOAuthStateInvalid = errors.New("invalid oauth state")
	// ErrOAuthExchangeFailed wraps any failure of the provider code exchange.
	ErrOAuthExchangeFailed = errors.New("oauth code exchange failed")
	// ErrOAuthEmailRequired means the provider reported no usable email.
	ErrOAuthEmailRequired = errors.New("oauth provider returned no valid email")
	// ErrOAuthEmailUnverified means the provider has not verified the email,
	// which is required both to create an account and to link one.
	ErrOAuthEmailUnverified = errors.New("oauth provider email is not verified")
	// ErrOAuthLinkDisabled means an account with the provider's email exists
	// and automatic linking is turned off.
	ErrOAuthLinkDisabled = errors.New("account exists and automatic oauth linking is disabled")
	// ErrOAuthAccountHasPassword means an account with the provider's email
	// exists and holds a password, so it is not linked automatically. Its
	// password holder may link the provider explicitly (personal-usuw).
	ErrOAuthAccountHasPassword = errors.New("an account with this email has a password and is not linked automatically")
)

// DefaultOAuthStateTTL bounds how long a user may spend at the provider.
const DefaultOAuthStateTTL = 15 * time.Minute

// oauthSecretBytes sizes state and browser-binding secrets (256 bits).
const oauthSecretBytes = 32

// OAuthConfig tunes OAuth sign-in.
type OAuthConfig struct {
	// DisableAutoLinkEmail stops a first OAuth sign-in from attaching to an
	// existing account with the same (provider-verified) email. Inverted so the
	// zero value keeps the default: linking enabled. Accounts holding a
	// password are never auto-linked either way.
	DisableAutoLinkEmail bool
	// StateTTL is the lifetime of a flow's state. 0 = DefaultOAuthStateTTL.
	StateTTL time.Duration
}

// WithOAuth enables OAuth sign-in through the given providers, keyed by
// ProviderName(). credentials tells password accounts apart: auto-link skips
// them. All stores are required; a nil store or a duplicate name is a wiring
// bug and panics at startup rather than on the first sign-in.
func WithOAuth(
	providers []oauth.Provider,
	identities OAuthIdentityStore,
	challenges ChallengeStore,
	credentials CredentialStore,
	cfg OAuthConfig,
) ServiceOption {
	if identities == nil || challenges == nil || credentials == nil {
		panic("auth: WithOAuth needs identity, challenge and credential stores")
	}
	if cfg.StateTTL == 0 {
		cfg.StateTTL = DefaultOAuthStateTTL
	}
	registry := make(map[string]oauth.Provider, len(providers))
	for _, p := range providers {
		if _, dup := registry[p.ProviderName()]; dup {
			panic(fmt.Sprintf("auth: duplicate oauth provider %q", p.ProviderName()))
		}
		registry[p.ProviderName()] = p
	}
	return func(s *Service) {
		s.oauthProviders = registry
		s.oauthIdentities = identities
		s.challenges = challenges
		s.credentials = credentials
		s.oauthConfig = cfg
	}
}

// OAuthURLResult starts a flow. Binding is a secret the caller must keep in
// the browser that started the flow (cookie or session storage, never the
// URL) and present to OAuthCallback.
type OAuthURLResult struct {
	URL     string
	State   string
	Binding string
}

// OAuthCallbackRequest completes a flow. Provider and RedirectURI must equal
// the GetOAuthURL arguments; Code and State come from the provider redirect.
type OAuthCallbackRequest struct {
	Provider    string
	Code        string
	State       string
	RedirectURI string
	Binding     string
}

// OAuthCallbackResult contains the signed-in user and a new session.
type OAuthCallbackResult struct {
	UserID    string
	Email     string
	TokenPair *entity.TokenPair
	IsNewUser bool
	// Linked reports that this sign-in attached the provider account to an
	// existing user found by email (auto-link).
	Linked bool
}

// oauthUserOrigin tells how resolveOAuthUser found the user.
type oauthUserOrigin int

const (
	oauthUserExisting oauthUserOrigin = iota // provider account already linked
	oauthUserCreated
	oauthUserLinked // auto-linked to an account with the same email
)

// oauthProvider resolves an enabled provider.
func (s *Service) oauthProvider(name string) (oauth.Provider, error) {
	if s.oauthProviders == nil {
		return nil, ErrOAuthDisabled
	}
	p, ok := s.oauthProviders[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrOAuthProviderUnknown, name)
	}
	return p, nil
}

// GetOAuthURL starts an OAuth flow: it generates the state, PKCE verifier,
// OIDC nonce and browser binding, keeps them server-side, and returns the
// provider URL.
func (s *Service) GetOAuthURL(ctx context.Context, provider, redirectURI string) (*OAuthURLResult, error) {
	p, err := s.oauthProvider(provider)
	if err != nil {
		return nil, err
	}

	state, err := randomSecret()
	if err != nil {
		return nil, err
	}
	nonce, err := randomSecret()
	if err != nil {
		return nil, err
	}
	binding, err := randomSecret()
	if err != nil {
		return nil, err
	}
	params := oauth.AuthParams{
		State:        state,
		RedirectURI:  redirectURI,
		CodeVerifier: oauth2.GenerateVerifier(),
		Nonce:        nonce,
	}

	// Build the URL first: a redirect URI off the whitelist must not leave a
	// challenge row behind.
	url, err := p.AuthCodeURL(params)
	if err != nil {
		return nil, fmt.Errorf("build auth url: %w", err)
	}

	// The challenge type is shared with wallet sign-in: Nonce holds the state
	// and Message the provider/redirect binding; Chain and Address stay empty.
	now := s.now()
	err = s.challenges.SaveChallenge(ctx, &entity.Challenge{
		Nonce:        state,
		Message:      oauthStateBinding(provider, redirectURI),
		CodeVerifier: params.CodeVerifier,
		OAuthNonce:   params.Nonce,
		BindingHash:  hashBinding(binding),
		ExpiresAt:    now.Add(s.oauthConfig.StateTTL),
		CreatedAt:    now,
	})
	if err != nil {
		return nil, fmt.Errorf("save oauth state: %w", err)
	}

	return &OAuthURLResult{URL: url, State: state, Binding: binding}, nil
}

// OAuthCallback completes an OAuth flow and signs the user in, creating or
// linking the account on first sign-in.
func (s *Service) OAuthCallback(ctx context.Context, req OAuthCallbackRequest) (*OAuthCallbackResult, error) {
	p, err := s.oauthProvider(req.Provider)
	if err != nil {
		return nil, err
	}

	ch, err := s.consumeOAuthState(ctx, req)
	if err != nil {
		return nil, err
	}

	// The state is burnt from here on: a failed exchange cannot be retried
	// with it.
	info, err := p.ExchangeCode(ctx, req.Code, oauth.AuthParams{
		State:        req.State,
		RedirectURI:  req.RedirectURI,
		CodeVerifier: ch.CodeVerifier,
		Nonce:        ch.OAuthNonce,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOAuthExchangeFailed, err)
	}
	if info.ExternalID == "" {
		return nil, fmt.Errorf("%w: %w: empty external id", ErrOAuthExchangeFailed, oauth.ErrInvalidToken)
	}

	user, origin, err := s.resolveOAuthUser(ctx, req.Provider, info)
	if err != nil {
		return nil, err
	}

	// Email and roles come from the user store, not the provider: they may differ.
	change := accountChange{userID: user.ID, created: origin == oauthUserCreated, linked: origin == oauthUserLinked}
	pair, err := s.issueTokens(ctx, user.ID, user.Email, user.Roles, "")
	if err != nil {
		return nil, &accountError{change, fmt.Errorf("issue tokens: %w", err)}
	}

	return &OAuthCallbackResult{
		UserID:    user.ID,
		Email:     user.Email,
		TokenPair: pair,
		IsNewUser: change.created,
		Linked:    change.linked,
	}, nil
}

// consumeOAuthState validates the state against the request and deletes it.
// Every check runs before the delete, so a request that fails one (an
// attacker without the binding) cannot burn the victim's state. The delete
// itself is the single-use gate: of concurrent callbacks only one gets past it.
func (s *Service) consumeOAuthState(ctx context.Context, req OAuthCallbackRequest) (*entity.Challenge, error) {
	if req.Code == "" || req.State == "" || req.Binding == "" {
		return nil, ErrOAuthStateInvalid
	}

	ch, err := s.challenges.GetChallenge(ctx, req.State)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrChallengeNotFound), errors.Is(err, store.ErrChallengeExpired):
		return nil, ErrOAuthStateInvalid
	default:
		return nil, fmt.Errorf("get oauth state: %w", err)
	}

	// A wallet challenge has no binding hash; an empty one must never match.
	if !s.now().Before(ch.ExpiresAt) ||
		ch.Message != oauthStateBinding(req.Provider, req.RedirectURI) ||
		ch.BindingHash == "" ||
		subtle.ConstantTimeCompare([]byte(hashBinding(req.Binding)), []byte(ch.BindingHash)) != 1 {
		return nil, ErrOAuthStateInvalid
	}

	if err := s.challenges.DeleteChallenge(ctx, req.State); err != nil {
		if errors.Is(err, store.ErrChallengeNotFound) {
			return nil, ErrOAuthStateInvalid
		}
		return nil, fmt.Errorf("delete oauth state: %w", err)
	}
	return ch, nil
}

// resolveOAuthUser finds the user behind a provider account, linking or
// creating one on first sign-in.
func (s *Service) resolveOAuthUser(ctx context.Context, provider string, info *oauth.UserInfo) (*entity.User, oauthUserOrigin, error) {
	user, err := s.oauthIdentityUser(ctx, provider, info.ExternalID)
	if err == nil {
		return user, oauthUserExisting, nil
	}
	if !errors.Is(err, store.ErrOAuthIdentityNotFound) {
		return nil, oauthUserExisting, err
	}

	email, err := NormalizeEmail(info.Email)
	if err != nil {
		return nil, oauthUserExisting, ErrOAuthEmailRequired
	}
	// Both creating and linking trust the email; an unverified one would let
	// anyone claim an address at the provider and own the account behind it.
	if !info.EmailVerified {
		return nil, oauthUserExisting, ErrOAuthEmailUnverified
	}

	user, isNew, err := s.findOrCreateUser(ctx, email)
	if err != nil {
		return nil, oauthUserExisting, err
	}
	origin := oauthUserCreated
	if !isNew {
		if err := s.checkAutoLink(ctx, user.ID); err != nil {
			return nil, oauthUserExisting, &accountError{accountChange{userID: user.ID}, err}
		}
		origin = oauthUserLinked
	}

	err = s.oauthIdentities.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		Provider:   provider,
		ExternalID: info.ExternalID,
		Email:      email,
		CreatedAt:  s.now(),
	})
	if err == nil {
		return user, origin, nil
	}

	if isNew {
		s.discardUnlinkedUser(ctx, user.ID)
	}
	// A concurrent callback for the same provider account linked it first,
	// often to the very user created here (it found it by email): then this
	// sign-in still created it.
	if errors.Is(err, store.ErrOAuthIdentityExists) {
		winner, err := s.oauthIdentityUser(ctx, provider, info.ExternalID)
		if err == nil && isNew && winner.ID == user.ID {
			return winner, oauthUserCreated, nil
		}
		return winner, oauthUserExisting, err
	}
	return nil, oauthUserExisting, fmt.Errorf("save oauth identity: %w", err)
}

// discardUnlinkedUser undoes a user created for a sign-in whose identity link
// failed. No transaction spans the user and the identity; left behind, the
// user would hold the email with no way to sign in. A user some concurrent
// flow has linked meanwhile is kept: deleting it would cascade to that link.
// Runs detached from ctx so a cancelled request still cleans up.
// shortcut: a link landing between the check and the delete is lost; a
// transactional user+identity store method removes the window (personal-w3zn).
func (s *Service) discardUnlinkedUser(ctx context.Context, userID string) {
	ctx = context.WithoutCancel(ctx)
	linked, err := s.oauthIdentities.ListOAuthIdentities(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "check user links after failed oauth link", "user_id", userID, "error", err)
		return
	}
	if len(linked) > 0 {
		return
	}
	if err := s.userStore.Delete(ctx, userID); err != nil {
		slog.ErrorContext(ctx, "delete user after failed oauth link", "user_id", userID, "error", err)
	}
}

// checkAutoLink decides whether a first OAuth sign-in may attach to an
// existing account found by email. A password account is refused: local
// registration does not verify email, so whoever registered the address
// first may not own it, and linking would hand them the provider's sign-in
// (pre-account takeover). Its owner proves control by signing in instead.
// shortcut: a password saved after this check (a registration racing the
// sign-in) is not seen; closing it needs the transactional link of personal-w3zn.
func (s *Service) checkAutoLink(ctx context.Context, userID string) error {
	if s.oauthConfig.DisableAutoLinkEmail {
		return ErrOAuthLinkDisabled
	}
	_, err := s.credentials.GetPasswordHash(ctx, userID)
	switch {
	case err == nil:
		return ErrOAuthAccountHasPassword
	case errors.Is(err, store.ErrCredentialNotFound):
		return nil
	default:
		return fmt.Errorf("get password hash: %w", err)
	}
}

// oauthIdentityUser loads the user linked to a provider account. Returns
// store.ErrOAuthIdentityNotFound if the account is not linked.
func (s *Service) oauthIdentityUser(ctx context.Context, provider, externalID string) (*entity.User, error) {
	identity, err := s.oauthIdentities.GetOAuthIdentity(ctx, provider, externalID)
	if err != nil {
		if errors.Is(err, store.ErrOAuthIdentityNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("get oauth identity: %w", err)
	}
	user, err := s.userStore.GetByID(ctx, identity.UserID)
	if err != nil {
		return nil, fmt.Errorf("get oauth user: %w", err)
	}
	return user, nil
}

// findOrCreateUser returns the account with this email, or creates one.
// Reports whether the user was created.
func (s *Service) findOrCreateUser(ctx context.Context, email string) (*entity.User, bool, error) {
	user, err := s.userStore.GetByEmail(ctx, email)
	if err == nil {
		return user, false, nil
	}
	if !errors.Is(err, store.ErrUserNotFound) {
		return nil, false, fmt.Errorf("get user by email: %w", err)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, false, fmt.Errorf("generate user id: %w", err)
	}
	now := s.now()
	user = &entity.User{ID: id.String(), Email: email, CreatedAt: now, UpdatedAt: now}
	err = s.userStore.Create(ctx, user)
	if err == nil {
		return user, true, nil
	}
	if !errors.Is(err, store.ErrUserExists) {
		return nil, false, fmt.Errorf("create user: %w", err)
	}

	// Lost a race with a concurrent registration of the same email.
	user, err = s.userStore.GetByEmail(ctx, email)
	if err != nil {
		return nil, false, fmt.Errorf("get user by email: %w", err)
	}
	return user, false, nil
}

// oauthStateBinding is the challenge payload that ties a state to the
// provider and redirect URI it was issued for. Neither contains a newline.
func oauthStateBinding(provider, redirectURI string) string {
	return provider + "\n" + redirectURI
}

// hashBinding is the form of a browser-binding secret kept at rest: hex
// SHA-256, sized for the binding_hash varchar(64) column.
func hashBinding(binding string) string {
	sum := sha256.Sum256([]byte(binding))
	return hex.EncodeToString(sum[:])
}

// randomSecret returns 256 random bits, URL-safe encoded.
func randomSecret() (string, error) {
	b := make([]byte, oauthSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate oauth secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
