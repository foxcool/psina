package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/store"
)

// oauthKey identifies an OAuth identity by its natural unique key.
type oauthKey struct {
	provider   string
	externalID string
}

// Store is an in-memory implementation of UserStore, TokenStore,
// CredentialStore, OAuthIdentityStore, and ChallengeStore.
// Suitable for testing and embedded use cases. NOT for production.
type Store struct {
	mu              sync.RWMutex
	users           map[string]*entity.User                // userID -> User
	usersByEmail    map[string]*entity.User                // email -> User
	refreshTokens   map[string]*entity.RefreshToken        // hash -> RefreshToken
	pats            map[string]*entity.PersonalAccessToken // hash -> PAT
	passwordHashes  map[string]string                      // userID -> passwordHash
	oauthIdentities map[oauthKey]*entity.OAuthIdentity
	challenges      map[string]*entity.Challenge // nonce -> Challenge
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		users:           make(map[string]*entity.User),
		usersByEmail:    make(map[string]*entity.User),
		refreshTokens:   make(map[string]*entity.RefreshToken),
		pats:            make(map[string]*entity.PersonalAccessToken),
		passwordHashes:  make(map[string]string),
		oauthIdentities: make(map[oauthKey]*entity.OAuthIdentity),
		challenges:      make(map[string]*entity.Challenge),
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
	if _, exists := s.usersByEmail[user.Email]; exists {
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

	// Store user
	s.users[user.ID] = user
	s.usersByEmail[user.Email] = user

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

	return user, nil
}

// GetByEmail retrieves a user by email address.
func (s *Store) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByEmail[email]
	if !exists {
		return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, email)
	}

	return user, nil
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

	s.refreshTokens[token.Hash] = token

	return nil
}

// GetRefreshToken retrieves a refresh token by its hash.
func (s *Store) GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.refreshTokens[hash]
	if !exists {
		return nil, store.ErrTokenNotFound
	}

	return token, nil
}

// RevokeTokens revokes a token and all tokens in its family.
func (s *Store) RevokeTokens(ctx context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range s.refreshTokens {
		if token.Hash == hash || token.Parent == hash {
			token.Revoked = true
		}
	}

	return nil
}

// --- PATStore implementation ---

// SavePAT persists a personal access token.
func (s *Store) SavePAT(ctx context.Context, pat *entity.PersonalAccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

// ListPATs returns all personal access tokens for a user (as copies).
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

	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = time.Now()
	}
	stored := *identity
	s.oauthIdentities[oauthKey{identity.Provider, identity.ExternalID}] = &stored

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

// ListOAuthIdentities returns all OAuth identities linked to a user (as copies).
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

	// Verify user exists
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("%w: %s", store.ErrUserNotFound, userID)
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
