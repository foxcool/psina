package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/foxcool/psina/pkg/entity"
)

// Store is an in-memory implementation of UserStore, TokenStore, and CredentialStore.
// Suitable for testing and embedded use cases. NOT for production.
type Store struct {
	mu             sync.RWMutex
	users          map[string]*entity.User         // userID -> User
	usersByEmail   map[string]*entity.User         // email -> User
	refreshTokens  map[string]*entity.RefreshToken // hash -> RefreshToken
	passwordHashes map[string]string               // userID -> passwordHash
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		users:          make(map[string]*entity.User),
		usersByEmail:   make(map[string]*entity.User),
		refreshTokens:  make(map[string]*entity.RefreshToken),
		passwordHashes: make(map[string]string),
	}
}

// --- UserStore implementation ---

// Create persists a new user.
func (s *Store) Create(ctx context.Context, user *entity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user already exists
	if _, exists := s.users[user.ID]; exists {
		return fmt.Errorf("user already exists: %s", user.ID)
	}
	if _, exists := s.usersByEmail[user.Email]; exists {
		return fmt.Errorf("email already registered: %s", user.Email)
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
		return nil, fmt.Errorf("user not found: %s", id)
	}

	return user, nil
}

// GetByEmail retrieves a user by email address.
func (s *Store) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByEmail[email]
	if !exists {
		return nil, fmt.Errorf("user not found: %s", email)
	}

	return user, nil
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
		return nil, fmt.Errorf("refresh token not found")
	}

	return token, nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (s *Store) RevokeRefreshToken(ctx context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, exists := s.refreshTokens[hash]
	if !exists {
		return fmt.Errorf("refresh token not found")
	}

	token.Revoked = true

	return nil
}

// --- CredentialStore implementation ---

// SavePasswordHash stores a password hash for a user.
func (s *Store) SavePasswordHash(ctx context.Context, userID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify user exists
	if _, exists := s.users[userID]; !exists {
		return fmt.Errorf("user not found: %s", userID)
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
		return "", fmt.Errorf("password hash not found for user: %s", userID)
	}

	return hash, nil
}
