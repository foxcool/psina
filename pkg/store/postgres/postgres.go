package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store implements UserStore, TokenStore, and CredentialStore using PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new PostgreSQL store.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// NewWithDSN creates a new PostgreSQL store from a connection string.
func NewWithDSN(ctx context.Context, dsn string) (*Store, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	return &Store{pool: pool}, nil
}

// Close closes the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// --- UserStore implementation ---

// Create persists a new user.
func (s *Store) Create(ctx context.Context, user *entity.User) error {
	now := time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO users (id, email, created_at, updated_at)
		VALUES ($1, $2, $3, $4)
	`, user.ID, user.Email, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		if isDuplicateKeyError(err) {
			return fmt.Errorf("user already exists: %s", user.Email)
		}
		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID.
func (s *Store) GetByID(ctx context.Context, id string) (*entity.User, error) {
	user := &entity.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, created_at, updated_at
		FROM users
		WHERE id = $1
	`, id).Scan(&user.ID, &user.Email, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %s", id)
		}
		return nil, fmt.Errorf("query user: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by email address.
func (s *Store) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	user := &entity.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, created_at, updated_at
		FROM users
		WHERE email = $1
	`, email).Scan(&user.ID, &user.Email, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %s", email)
		}
		return nil, fmt.Errorf("query user: %w", err)
	}

	return user, nil
}

// --- TokenStore implementation ---

// SaveRefreshToken persists a refresh token.
func (s *Store) SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	now := time.Now()
	if token.CreatedAt.IsZero() {
		token.CreatedAt = now
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (hash, user_id, expires_at, created_at, revoked)
		VALUES ($1, $2, $3, $4, $5)
	`, token.Hash, token.UserID, token.ExpiresAt, token.CreatedAt, token.Revoked)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves a refresh token by its hash.
func (s *Store) GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error) {
	token := &entity.RefreshToken{}
	err := s.pool.QueryRow(ctx, `
		SELECT hash, user_id, expires_at, created_at, revoked
		FROM refresh_tokens
		WHERE hash = $1
	`, hash).Scan(&token.Hash, &token.UserID, &token.ExpiresAt, &token.CreatedAt, &token.Revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("refresh token not found")
		}
		return nil, fmt.Errorf("query refresh token: %w", err)
	}

	return token, nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (s *Store) RevokeRefreshToken(ctx context.Context, hash string) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE hash = $1
	`, hash)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("refresh token not found")
	}

	return nil
}

// --- CredentialStore implementation ---

// SavePasswordHash stores a password hash for a user.
func (s *Store) SavePasswordHash(ctx context.Context, userID, hash string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO local_credentials (user_id, password_hash, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (user_id) DO UPDATE SET password_hash = $2, updated_at = NOW()
	`, userID, hash)
	if err != nil {
		return fmt.Errorf("save password hash: %w", err)
	}

	return nil
}

// GetPasswordHash retrieves a password hash for a user.
func (s *Store) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	var hash string
	err := s.pool.QueryRow(ctx, `
		SELECT password_hash
		FROM local_credentials
		WHERE user_id = $1
	`, userID).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("password hash not found for user: %s", userID)
		}
		return "", fmt.Errorf("query password hash: %w", err)
	}

	return hash, nil
}

// isDuplicateKeyError checks if error is a unique constraint violation.
func isDuplicateKeyError(err error) bool {
	// PostgreSQL error code 23505 = unique_violation
	return err != nil && (contains(err.Error(), "23505") || contains(err.Error(), "duplicate key"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
