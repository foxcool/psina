package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/provider/wallet"
	"github.com/foxcool/psina/store"
	"github.com/google/uuid"
)

// Wallet service errors.
var (
	ErrWalletDisabled         = errors.New("wallet sign-in is disabled")
	ErrWalletChainUnsupported = errors.New("unsupported wallet chain")
	ErrWalletAddressInvalid   = errors.New("invalid wallet address")
	// ErrWalletChallengeInvalid covers every sign-in failure after the address
	// is accepted (unknown, expired or replayed nonce, a challenge issued for
	// another chain or address, a bad signature) so the caller cannot tell
	// them apart.
	ErrWalletChallengeInvalid = errors.New("invalid wallet challenge or signature")
)

// DefaultWalletChallengeTTL bounds how long a user may take to sign.
const DefaultWalletChallengeTTL = 5 * time.Minute

// walletNonceBytes sizes the challenge nonce (128 bits). Hex-encoded, so it
// meets SIWE's alphanumeric, at least 8 characters rule.
const walletNonceBytes = 16

// WalletConfig is the operator's side of the message a wallet signs.
type WalletConfig struct {
	// Domain is the host asking for the sign-in, e.g. "app.example.com".
	// Wallets warn when it differs from the page the user is on.
	Domain string
	// URI is the resource the sign-in is for, e.g. "https://app.example.com".
	URI string
	// Statement is shown to the signer; optional.
	Statement string
	// ChallengeTTL is how long a challenge stays valid. 0 = DefaultWalletChallengeTTL.
	ChallengeTTL time.Duration
}

// WithWallet enables wallet sign-in through the dispatcher's chains. A nil
// store, an empty Domain or URI, or a line break in Domain, URI or Statement
// (they are written into a line-oriented message the wallet displays) is a
// wiring bug and panics at startup rather than on the first sign-in.
func WithWallet(
	providers *wallet.Dispatcher,
	identities WalletIdentityStore,
	challenges ChallengeStore,
	cfg WalletConfig,
) ServiceOption {
	if providers == nil || identities == nil || challenges == nil {
		panic("auth: WithWallet needs a dispatcher, identity and challenge stores")
	}
	if cfg.Domain == "" || cfg.URI == "" {
		panic("auth: WithWallet needs Domain and URI")
	}
	if strings.ContainsAny(cfg.Domain+cfg.URI+cfg.Statement, "\r\n") {
		panic("auth: WithWallet Domain, URI and Statement must be single-line")
	}
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = DefaultWalletChallengeTTL
	}
	return func(s *Service) {
		s.walletProviders = providers
		s.walletIdentities = identities
		s.walletChallenges = challenges
		s.walletConfig = cfg
	}
}

// WalletChallengeResult is the message a wallet must sign.
type WalletChallengeResult struct {
	Nonce     string
	Message   string
	ExpiresAt time.Time
}

// WalletAuthRequest completes a wallet sign-in. Chain and Address must match
// the GetChallenge arguments (Address in any case form the chain accepts).
type WalletAuthRequest struct {
	Chain     string
	Address   string
	Nonce     string
	Signature string
}

// WalletAuthResult contains the signed-in user and a new session.
type WalletAuthResult struct {
	UserID    string
	Email     string // empty for accounts created by wallet sign-in
	TokenPair *entity.TokenPair
	IsNewUser bool
}

// walletProvider resolves the provider for a chain and normalizes the address.
func (s *Service) walletProvider(chain, address string) (wallet.WalletProvider, string, error) {
	if s.walletProviders == nil {
		return nil, "", ErrWalletDisabled
	}
	p, err := s.walletProviders.Provider(chain)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %q", ErrWalletChainUnsupported, chain)
	}
	addr, err := p.NormalizeAddress(address)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrWalletAddressInvalid, err)
	}
	return p, addr, nil
}

// GetChallenge issues a single-use message for the wallet at address to sign.
func (s *Service) GetChallenge(ctx context.Context, chain, address string) (*WalletChallengeResult, error) {
	p, addr, err := s.walletProvider(chain, address)
	if err != nil {
		return nil, err
	}

	b := make([]byte, walletNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate wallet nonce: %w", err)
	}
	nonce := hex.EncodeToString(b)

	now := s.now()
	expiresAt := now.Add(s.walletConfig.ChallengeTTL)
	message := p.BuildMessage(addr, nonce, wallet.MessageOpts{
		Domain:    s.walletConfig.Domain,
		URI:       s.walletConfig.URI,
		Statement: s.walletConfig.Statement,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	})

	err = s.walletChallenges.SaveChallenge(ctx, &entity.Challenge{
		Nonce:     nonce,
		Message:   message,
		Chain:     chain,
		Address:   addr,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("save wallet challenge: %w", err)
	}

	return &WalletChallengeResult{Nonce: nonce, Message: message, ExpiresAt: expiresAt}, nil
}

// AuthenticateWallet verifies a signed challenge and signs the wallet's user
// in, creating the user on first sign-in.
func (s *Service) AuthenticateWallet(ctx context.Context, req WalletAuthRequest) (*WalletAuthResult, error) {
	p, addr, err := s.walletProvider(req.Chain, req.Address)
	if err != nil {
		return nil, err
	}

	if err := s.consumeWalletChallenge(ctx, p, req, addr); err != nil {
		return nil, err
	}

	user, isNew, err := s.resolveWalletUser(ctx, req.Chain, addr)
	if err != nil {
		return nil, err
	}

	pair, err := s.issueTokens(ctx, user.ID, user.Email, user.Roles, "")
	if err != nil {
		return nil, &accountError{accountChange{userID: user.ID, created: isNew}, fmt.Errorf("issue tokens: %w", err)}
	}

	return &WalletAuthResult{
		UserID:    user.ID,
		Email:     user.Email,
		TokenPair: pair,
		IsNewUser: isNew,
	}, nil
}

// consumeWalletChallenge checks the challenge and the signature, then deletes
// the challenge. Every check, the signature included, runs before the delete,
// so whoever sees a nonce cannot burn it with a bogus signature. The delete
// itself is the single-use gate: of concurrent sign-ins with the same
// signature only one gets past it.
func (s *Service) consumeWalletChallenge(ctx context.Context, p wallet.WalletProvider, req WalletAuthRequest, addr string) error {
	if req.Nonce == "" || req.Signature == "" {
		return ErrWalletChallengeInvalid
	}

	ch, err := s.walletChallenges.GetChallenge(ctx, req.Nonce)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrChallengeNotFound), errors.Is(err, store.ErrChallengeExpired):
		return ErrWalletChallengeInvalid
	default:
		return fmt.Errorf("get wallet challenge: %w", err)
	}

	// The store is shared with OAuth state, whose Chain and Address are empty;
	// req.Chain resolved to a provider, so it is never empty here.
	if !s.now().Before(ch.ExpiresAt) || ch.Chain != req.Chain || ch.Address != addr {
		return ErrWalletChallengeInvalid
	}
	if err := p.VerifySignature(addr, ch.Message, req.Signature); err != nil {
		return ErrWalletChallengeInvalid
	}

	if err := s.walletChallenges.DeleteChallenge(ctx, req.Nonce); err != nil {
		if errors.Is(err, store.ErrChallengeNotFound) {
			return ErrWalletChallengeInvalid
		}
		return fmt.Errorf("delete wallet challenge: %w", err)
	}
	return nil
}

// resolveWalletUser finds the user behind a wallet, creating one on first
// sign-in. Reports whether the user was created.
func (s *Service) resolveWalletUser(ctx context.Context, chain, addr string) (*entity.User, bool, error) {
	user, err := s.walletIdentityUser(ctx, chain, addr)
	if err == nil {
		return user, false, nil
	}
	if !errors.Is(err, store.ErrWalletIdentityNotFound) {
		return nil, false, err
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, false, fmt.Errorf("generate user id: %w", err)
	}
	now := s.now()
	user = &entity.User{ID: id.String(), CreatedAt: now, UpdatedAt: now}
	if err := s.userStore.Create(ctx, user); err != nil {
		return nil, false, fmt.Errorf("create user: %w", err)
	}

	err = s.walletIdentities.SaveWalletIdentity(ctx, &entity.WalletIdentity{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		Chain:     chain,
		Address:   addr,
		CreatedAt: now,
	})
	if err == nil {
		return user, true, nil
	}

	s.discardWalletUser(ctx, user.ID)
	// A concurrent first sign-in with the same wallet linked it first.
	if errors.Is(err, store.ErrWalletIdentityExists) {
		user, err := s.walletIdentityUser(ctx, chain, addr)
		return user, false, err
	}
	return nil, false, fmt.Errorf("save wallet identity: %w", err)
}

// discardWalletUser undoes a user created for a sign-in whose wallet link
// failed. Unlike the OAuth case nothing else can have linked it meanwhile:
// the user has no email to be found by. Runs detached from ctx so a
// cancelled request still cleans up.
func (s *Service) discardWalletUser(ctx context.Context, userID string) {
	ctx = context.WithoutCancel(ctx)
	if err := s.userStore.Delete(ctx, userID); err != nil {
		slog.ErrorContext(ctx, "delete user after failed wallet link", "user_id", userID, "error", err)
	}
}

// walletIdentityUser loads the user linked to a wallet. Returns
// store.ErrWalletIdentityNotFound if the wallet is not linked.
func (s *Service) walletIdentityUser(ctx context.Context, chain, addr string) (*entity.User, error) {
	identity, err := s.walletIdentities.GetWalletIdentity(ctx, chain, addr)
	if err != nil {
		if errors.Is(err, store.ErrWalletIdentityNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("get wallet identity: %w", err)
	}
	user, err := s.userStore.GetByID(ctx, identity.UserID)
	if err != nil {
		return nil, fmt.Errorf("get wallet user: %w", err)
	}
	return user, nil
}
