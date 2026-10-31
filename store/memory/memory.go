package memory

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
)

// oauthKey identifies an OAuth identity by its natural unique key.
type oauthKey struct {
	provider   string
	externalID string
}

// walletKey identifies a wallet identity by its natural unique key.
type walletKey struct {
	chain   string
	address string
}

// Store is an in-memory implementation of UserStore, TokenStore,
// CredentialStore, OAuthIdentityStore, WalletIdentityStore, and ChallengeStore.
// Suitable for testing and embedded use cases. NOT for production.
type Store struct {
	mu               sync.RWMutex
	users            map[string]*entity.User                // userID -> User
	usersByEmail     map[string]*entity.User                // email -> User
	refreshTokens    map[string]*entity.RefreshToken        // hash -> RefreshToken
	pats             map[string]*entity.PersonalAccessToken // hash -> PAT
	passwordHashes   map[string]string                      // userID -> passwordHash
	oauthIdentities  map[oauthKey]*entity.OAuthIdentity
	walletIdentities map[walletKey]*entity.WalletIdentity
	challenges       map[string]*entity.Challenge // nonce -> Challenge
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		users:            make(map[string]*entity.User),
		usersByEmail:     make(map[string]*entity.User),
		refreshTokens:    make(map[string]*entity.RefreshToken),
		pats:             make(map[string]*entity.PersonalAccessToken),
		passwordHashes:   make(map[string]string),
		oauthIdentities:  make(map[oauthKey]*entity.OAuthIdentity),
		walletIdentities: make(map[walletKey]*entity.WalletIdentity),
		challenges:       make(map[string]*entity.Challenge),
	}
}

// --- UserStore implementation ---

// Create persists a new user.
func (s *Store) Create(ctx context.Context, user *entity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user already exists
	if _, exists := s.users[user.ID]; exists {
		return fmt.Errorf("%w: %s", store.ErrUserExists, user.ID)
	}
	// Email-less users (wallet sign-in) are not indexed by email, matching
	// the partial unique index in postgres.
	if _, exists := s.usersByEmail[user.Email]; exists && user.Email != "" {
		return fmt.Errorf("%w: %s", store.ErrUserExists, user.Email)
	}

	// Set timestamps if not set
	now := time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}

	stored := copyUser(user)
	s.users[user.ID] = stored
	if user.Email != "" {
		s.usersByEmail[user.Email] = stored
	}

	return nil
}

// GetByID retrieves a user by ID.
func (s *Store) GetByID(ctx context.Context, id string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, id)
	}

	return copyUser(user), nil
}

// GetByEmail retrieves a user by email address.
func (s *Store) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByEmail[email]
	if !exists {
		return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, email)
	}

	return copyUser(user), nil
}

// copyUser keeps callers from mutating a stored user (Roles included)
// outside the mutex.
func copyUser(user *entity.User) *entity.User {
	cp := *user
	cp.Roles = slices.Clone(user.Roles)
	return &cp
}

// requireUser reports store.ErrUserNotFound for a write that references a
// missing user, as the postgres foreign keys do. Callers hold the lock.
func (s *Store) requireUser(userID string) error {
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("%w: %s", store.ErrUserNotFound, userID)
	}
	return nil
}

// Delete removes a user by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists {
		return fmt.Errorf("%w: %s", store.ErrUserNotFound, id)
	}

	delete(s.usersByEmail, user.Email)
	delete(s.users, id)
	delete(s.passwordHashes, id)
	// Mirrors the postgres ON DELETE CASCADE. An orphaned identity link would
	// also lock the account out, since its natural key stays taken.
	maps.DeleteFunc(s.refreshTokens, func(_ string, t *entity.RefreshToken) bool { return t.UserID == id })
	maps.DeleteFunc(s.pats, func(_ string, p *entity.PersonalAccessToken) bool { return p.UserID == id })
	maps.DeleteFunc(s.oauthIdentities, func(_ oauthKey, i *entity.OAuthIdentity) bool { return i.UserID == id })
	maps.DeleteFunc(s.walletIdentities, func(_ walletKey, i *entity.WalletIdentity) bool { return i.UserID == id })

	return nil
}

// --- TokenStore implementation ---

// SaveRefreshToken persists a refresh token.
func (s *Store) SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Set timestamps if not set
	now := time.Now()
	if token.CreatedAt.IsZero() {
		token.CreatedAt = now
	}

	// A successor may not join a family whose session has ended or whose root
	// is gone (same contract as the postgres root lock; here the mutex
	// serialises it).
	if token.Parent != "" {
		root, ok := s.refreshTokens[token.Parent]
		if !ok {
			return fmt.Errorf("%w: family root missing", store.ErrTokenRevoked)
		}
		if root.EndedAt != nil {
			return fmt.Errorf("%w: session ended", store.ErrTokenRevoked)
		}
	}
	if err := s.requireUser(token.UserID); err != nil {
		return err
	}

	s.refreshTokens[token.Hash] = snapshot(token)

	return nil
}

// snapshot copies a stored token: callers must not alias structs that
// revoke and rotate mutate under the lock.
func snapshot(token *entity.RefreshToken) *entity.RefreshToken {
	cp := *token
	return &cp
}

// GetRefreshToken retrieves a refresh token by its hash.
func (s *Store) GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.refreshTokens[hash]
	if !exists {
		return nil, store.ErrTokenNotFound
	}

	return snapshot(token), nil
}

// RotateRefreshToken atomically revokes a live token and stamps RotatedAt.
func (s *Store) RotateRefreshToken(ctx context.Context, hash string, now time.Time) (*entity.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, exists := s.refreshTokens[hash]
	if !exists {
		return nil, store.ErrTokenNotFound
	}
	if token.Revoked {
		return snapshot(token), store.ErrTokenRevoked
	}
	if !token.ExpiresAt.After(now) {
		return snapshot(token), store.ErrTokenExpired
	}

	token.Revoked = true
	token.RotatedAt = &now
	return snapshot(token), nil
}

// GetRefreshFamily summarises the family rooted at root.
func (s *Store) GetRefreshFamily(ctx context.Context, root string) (*entity.RefreshFamily, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	family := &entity.RefreshFamily{}
	for _, token := range s.refreshTokens {
		if token.Hash != root && token.Parent != root {
			continue
		}
		if token.EndedAt != nil {
			family.SessionEnded = true
		}
		if token.RotatedAt != nil && (family.LastRotatedAt == nil || token.RotatedAt.After(*family.LastRotatedAt)) {
			t := *token.RotatedAt
			family.LastRotatedAt = &t
		}
	}
	return family, nil
}

// RevokeTokens revokes a token and all tokens in its family.
func (s *Store) RevokeTokens(ctx context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, token := range s.refreshTokens {
		if token.Hash == hash || token.Parent == hash {
			token.Revoked = true
			if token.EndedAt == nil {
				token.EndedAt = &now
			}
		}
	}

	return nil
}

// --- PATStore implementation ---

// SavePAT persists a personal access token.
func (s *Store) SavePAT(ctx context.Context, pat *entity.PersonalAccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireUser(pat.UserID); err != nil {
		return err
	}
	// Overwriting would hand an existing token to another owner.
	if _, exists := s.pats[pat.Hash]; exists {
		return store.ErrPATExists
	}
	if pat.CreatedAt.IsZero() {
		pat.CreatedAt = time.Now()
	}
	stored := *pat
	s.pats[pat.Hash] = &stored

	return nil
}

// GetPAT retrieves a personal access token by its hash. Returns a copy so
// callers never share memory with the store (TouchPAT mutates in place).
func (s *Store) GetPAT(ctx context.Context, hash string) (*entity.PersonalAccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pat, exists := s.pats[hash]
	if !exists {
		return nil, store.ErrTokenNotFound
	}

	out := *pat
	return &out, nil
}

// ListPATs returns all personal access tokens for a user (as copies), newest
// first like the postgres store.
func (s *Store) ListPATs(ctx context.Context, userID string) ([]*entity.PersonalAccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*entity.PersonalAccessToken
	for _, pat := range s.pats {
		if pat.UserID == userID {
			c := *pat
			out = append(out, &c)
		}
	}
	slices.SortFunc(out, func(a, b *entity.PersonalAccessToken) int { return b.CreatedAt.Compare(a.CreatedAt) })

	return out, nil
}

// DeletePAT removes a token by its UUID, scoped to its owner.
func (s *Store) DeletePAT(ctx context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hash, pat := range s.pats {
		if pat.ID == id && pat.UserID == userID {
			delete(s.pats, hash)
			return nil
		}
	}

	return store.ErrTokenNotFound
}

// TouchPAT records last-used time.
func (s *Store) TouchPAT(ctx context.Context, hash string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pat, exists := s.pats[hash]; exists {
		pat.LastUsedAt = &t
	}

	return nil
}

// --- OAuthIdentityStore implementation ---

// SaveOAuthIdentity persists a new OAuth identity.
func (s *Store) SaveOAuthIdentity(ctx context.Context, identity *entity.OAuthIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireUser(identity.UserID); err != nil {
		return err
	}
	key := oauthKey{identity.Provider, identity.ExternalID}
	if _, exists := s.oauthIdentities[key]; exists {
		return fmt.Errorf("%w: %s/%s", store.ErrOAuthIdentityExists, identity.Provider, identity.ExternalID)
	}
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = time.Now()
	}
	stored := *identity
	s.oauthIdentities[key] = &stored

	return nil
}

// GetOAuthIdentity retrieves an identity by provider and external account id.
func (s *Store) GetOAuthIdentity(ctx context.Context, provider, externalID string) (*entity.OAuthIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identity, exists := s.oauthIdentities[oauthKey{provider, externalID}]
	if !exists {
		return nil, fmt.Errorf("%w: %s/%s", store.ErrOAuthIdentityNotFound, provider, externalID)
	}

	out := *identity
	return &out, nil
}

// ListOAuthIdentities returns all OAuth identities linked to a user (as
// copies), newest first like the postgres store.
func (s *Store) ListOAuthIdentities(ctx context.Context, userID string) ([]*entity.OAuthIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*entity.OAuthIdentity
	for _, identity := range s.oauthIdentities {
		if identity.UserID == userID {
			c := *identity
			out = append(out, &c)
		}
	}
	slices.SortFunc(out, func(a, b *entity.OAuthIdentity) int { return b.CreatedAt.Compare(a.CreatedAt) })

	return out, nil
}

// --- WalletIdentityStore implementation ---

// SaveWalletIdentity persists a new wallet identity.
func (s *Store) SaveWalletIdentity(ctx context.Context, identity *entity.WalletIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireUser(identity.UserID); err != nil {
		return err
	}
	key := walletKey{identity.Chain, identity.Address}
	if _, exists := s.walletIdentities[key]; exists {
		return fmt.Errorf("%w: %s/%s", store.ErrWalletIdentityExists, identity.Chain, identity.Address)
	}
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = time.Now()
	}
	stored := *identity
	s.walletIdentities[key] = &stored

	return nil
}

// GetWalletIdentity retrieves an identity by chain and normalized address.
func (s *Store) GetWalletIdentity(ctx context.Context, chain, address string) (*entity.WalletIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identity, exists := s.walletIdentities[walletKey{chain, address}]
	if !exists {
		return nil, fmt.Errorf("%w: %s/%s", store.ErrWalletIdentityNotFound, chain, address)
	}

	out := *identity
	return &out, nil
}

// ListWalletIdentities returns all wallet identities linked to a user (as
// copies), newest first like the postgres store.
func (s *Store) ListWalletIdentities(ctx context.Context, userID string) ([]*entity.WalletIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*entity.WalletIdentity
	for _, identity := range s.walletIdentities {
		if identity.UserID == userID {
			c := *identity
			out = append(out, &c)
		}
	}
	slices.SortFunc(out, func(a, b *entity.WalletIdentity) int { return b.CreatedAt.Compare(a.CreatedAt) })

	return out, nil
}

// --- ChallengeStore implementation ---

// SaveChallenge persists a challenge keyed by its nonce. Expired challenges
// are swept on every save so the map stays bounded without a background
// goroutine (a Store has no lifecycle to stop one).
func (s *Store) SaveChallenge(ctx context.Context, challenge *entity.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for nonce, c := range s.challenges {
		if c.ExpiresAt.Before(now) {
			delete(s.challenges, nonce)
		}
	}

	if challenge.CreatedAt.IsZero() {
		challenge.CreatedAt = now
	}
	stored := *challenge
	s.challenges[challenge.Nonce] = &stored

	return nil
}

// GetChallenge retrieves a challenge by nonce. An expired challenge is
// deleted and reported as store.ErrChallengeExpired.
func (s *Store) GetChallenge(ctx context.Context, nonce string) (*entity.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	challenge, exists := s.challenges[nonce]
	if !exists {
		return nil, store.ErrChallengeNotFound
	}
	if challenge.ExpiresAt.Before(time.Now()) {
		delete(s.challenges, nonce)
		return nil, store.ErrChallengeExpired
	}

	out := *challenge
	return &out, nil
}

// DeleteChallenge removes a challenge by nonce.
func (s *Store) DeleteChallenge(ctx context.Context, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.challenges[nonce]; !exists {
		return store.ErrChallengeNotFound
	}
	delete(s.challenges, nonce)

	return nil
}

// --- CredentialStore implementation ---

// SavePasswordHash stores a password hash for a user.
func (s *Store) SavePasswordHash(ctx context.Context, userID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireUser(userID); err != nil {
		return err
	}

	s.passwordHashes[userID] = hash

	return nil
}

// GetPasswordHash retrieves a password hash for a user.
func (s *Store) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash, exists := s.passwordHashes[userID]
	if !exists {
		return "", fmt.Errorf("%w: %s", store.ErrCredentialNotFound, userID)
	}

	return hash, nil
}
