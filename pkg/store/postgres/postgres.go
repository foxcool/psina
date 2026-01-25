package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/foxcool/psina/pkg/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL error codes.
// See: https://www.postgresql.org/docs/current/errcodes-appendix.html
const (
	pqUniqueViolation     = "23505" // unique_violation
	pqForeignKeyViolation = "23503" // foreign_key_violation
	pqNotNullViolation    = "23502" // not_null_violation
	pqCheckViolation      = "23514" // check_violation
)

// DefaultQueryTimeout is the default timeout for database queries.
// Can be overridden via DSN parameter: ?statement_timeout=5000
const DefaultQueryTimeout = "5000" // 5 seconds in milliseconds

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

	// Set default query timeout if not specified in DSN
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	if _, ok := config.ConnConfig.RuntimeParams["statement_timeout"]; !ok {
		config.ConnConfig.RuntimeParams["statement_timeout"] = DefaultQueryTimeout
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

// Ping checks the database connection.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
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
			return fmt.Errorf("%w: %s", store.ErrUserExists, user.Email)
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
			return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, id)
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
			return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, email)
		}
		return nil, fmt.Errorf("query user: %w", err)
	}

	return user, nil
}

// Delete removes a user by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", store.ErrUserNotFound, id)
	}
	return nil
}

// --- TokenStore implementation ---

// SaveRefreshToken persists a refresh token.
func (s *Store) SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	now := time.Now()
	if token.CreatedAt.IsZero() {
		token.CreatedAt = now
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (hash, user_id, parent, expires_at, created_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, token.Hash, token.UserID, token.Parent, token.ExpiresAt, token.CreatedAt, token.Revoked)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves a refresh token by its hash.
func (s *Store) GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error) {
	token := &entity.RefreshToken{}
	err := s.pool.QueryRow(ctx, `
		SELECT hash, user_id, parent, expires_at, created_at, revoked
		FROM refresh_tokens
		WHERE hash = $1
	`, hash).Scan(&token.Hash, &token.UserID, &token.Parent, &token.ExpiresAt, &token.CreatedAt, &token.Revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrTokenNotFound
		}
		return nil, fmt.Errorf("query refresh token: %w", err)
	}

	return token, nil
}

// RevokeTokens revokes a token and all tokens in its family.
func (s *Store) RevokeTokens(ctx context.Context, hash string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE hash = $1 OR parent = $1
	`, hash)
	if err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
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
			return "", fmt.Errorf("%w: %s", store.ErrCredentialNotFound, userID)
		}
		return "", fmt.Errorf("query password hash: %w", err)
	}

	return hash, nil
}

// isDuplicateKeyError checks if error is a unique constraint violation.
func isDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == pqUniqueViolation
	}
	return false
}
