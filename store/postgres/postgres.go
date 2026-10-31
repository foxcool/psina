package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL error codes.
// See: https://www.postgresql.org/docs/current/errcodes-appendix.html
const (
	pqUniqueViolation     = "23505" // unique_violation
	pqForeignKeyViolation = "23503" // foreign_key_violation
)

// DefaultQueryTimeout is the default timeout for database queries.
// Can be overridden via DSN parameter: ?statement_timeout=5000
const DefaultQueryTimeout = "5000" // 5 seconds in milliseconds

// Store implements UserStore, TokenStore, CredentialStore, OAuthIdentityStore,
// WalletIdentityStore, and ChallengeStore using PostgreSQL.
type Store struct {
	pool        *pgxpool.Pool
	tablePrefix string

	// Table names (with prefix applied)
	tableUsers            string
	tableLocalCredentials string
	tableRefreshTokens    string
	tablePATs             string
	tableOAuthIdentities  string
	tableWalletIdentities string
	tableChallenges       string
}

// Option configures the Store.
type Option func(*Store)

// WithTablePrefix sets the table name prefix.
func WithTablePrefix(prefix string) Option {
	return func(s *Store) {
		s.tablePrefix = prefix
	}
}

// New creates a new PostgreSQL store.
func New(pool *pgxpool.Pool, opts ...Option) *Store {
	s := &Store{
		pool: pool,
	}

	for _, opt := range opts {
		opt(s)
	}

	s.initTableNames()
	return s
}

// NewWithDSN creates a new PostgreSQL store from a connection string.
func NewWithDSN(ctx context.Context, dsn string, opts ...Option) (*Store, error) {
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

	return New(pool, opts...), nil
}

// initTableNames initializes table names with the configured prefix.
func (s *Store) initTableNames() {
	s.tableUsers = s.tablePrefix + "users"
	s.tableLocalCredentials = s.tablePrefix + "local_credentials"
	s.tableRefreshTokens = s.tablePrefix + "refresh_tokens"
	s.tablePATs = s.tablePrefix + "personal_access_tokens"
	s.tableOAuthIdentities = s.tablePrefix + "oauth_identities"
	s.tableWalletIdentities = s.tablePrefix + "wallet_identities"
	s.tableChallenges = s.tablePrefix + "auth_challenges"
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

	// pgx encodes a nil slice as SQL NULL, which violates the NOT NULL roles
	// column (the '{}' default only applies when the column is omitted).
	roles := user.Roles
	if roles == nil {
		roles = []string{}
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (id, email, roles, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`, s.tableUsers)

	// An empty email is stored as NULL so the partial unique index lets many
	// email-less users (wallet sign-in) coexist.
	var email *string
	if user.Email != "" {
		email = &user.Email
	}

	_, err := s.pool.Exec(ctx, query, user.ID, email, roles, user.CreatedAt, user.UpdatedAt)
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
	query := fmt.Sprintf(`
		SELECT id, email, roles, created_at, updated_at
		FROM %s
		WHERE id = $1
	`, s.tableUsers)

	user, err := scanUser(s.pool.QueryRow(ctx, query, id))
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
	// Email-less users are stored as NULL; an empty lookup must never match one.
	if email == "" {
		return nil, fmt.Errorf("%w: empty email", store.ErrUserNotFound)
	}

	query := fmt.Sprintf(`
		SELECT id, email, roles, created_at, updated_at
		FROM %s
		WHERE email = $1
	`, s.tableUsers)

	user, err := scanUser(s.pool.QueryRow(ctx, query, email))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, email)
		}
		return nil, fmt.Errorf("query user: %w", err)
	}

	return user, nil
}

// scanUser reads id, email, roles, created_at, updated_at; a NULL email
// becomes "".
func scanUser(row pgx.Row) (*entity.User, error) {
	user := &entity.User{}
	var email *string
	if err := row.Scan(&user.ID, &email, &user.Roles, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return nil, err
	}
	if email != nil {
		user.Email = *email
	}
	return user, nil
}

// Delete removes a user by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.tableUsers)

	result, err := s.pool.Exec(ctx, query, id)
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

	insert := fmt.Sprintf(`
		INSERT INTO %s (hash, user_id, parent, expires_at, created_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, s.tableRefreshTokens)
	args := []any{token.Hash, token.UserID, token.Parent, token.ExpiresAt, token.CreatedAt, token.Revoked}

	if token.Parent == "" {
		if _, err := s.pool.Exec(ctx, insert, args...); err != nil {
			return insertError("insert refresh token", token.UserID, err)
		}
		return nil
	}

	// A successor joins its family under a share lock on the root row, which
	// RevokeTokens locks exclusively: the two serialise, so the successor is
	// either refused here or seen by the revoking UPDATE. Without a root row
	// there is nothing to serialise on, so that is refused too.
	lockRoot := fmt.Sprintf(`SELECT ended_at FROM %s WHERE hash = $1 FOR SHARE`, s.tableRefreshTokens)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var endedAt *time.Time
		err := tx.QueryRow(ctx, lockRoot, token.Parent).Scan(&endedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: family root missing", store.ErrTokenRevoked)
		}
		if err != nil {
			return fmt.Errorf("lock refresh family root: %w", err)
		}
		if endedAt != nil {
			return fmt.Errorf("%w: session ended", store.ErrTokenRevoked)
		}
		if _, err := tx.Exec(ctx, insert, args...); err != nil {
			return insertError("insert refresh token", token.UserID, err)
		}
		return nil
	})
}

// GetRefreshToken retrieves a refresh token by its hash.
func (s *Store) GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error) {
	query := fmt.Sprintf(`
		SELECT %s
		FROM %s
		WHERE hash = $1
	`, refreshRowColumns, s.tableRefreshTokens)

	token, err := scanRefreshToken(s.pool.QueryRow(ctx, query, hash))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrTokenNotFound
		}
		return nil, fmt.Errorf("query refresh token: %w", err)
	}

	return token, nil
}

const refreshRowColumns = "hash, user_id, parent, expires_at, created_at, revoked, rotated_at, ended_at"

func scanRefreshToken(row pgx.Row) (*entity.RefreshToken, error) {
	token := &entity.RefreshToken{}
	err := row.Scan(&token.Hash, &token.UserID, &token.Parent, &token.ExpiresAt, &token.CreatedAt, &token.Revoked, &token.RotatedAt, &token.EndedAt)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// RotateRefreshToken atomically revokes a live token and stamps rotated_at.
// The conditional UPDATE is the serialization point: of concurrent callers
// only one matches the row.
func (s *Store) RotateRefreshToken(ctx context.Context, hash string, now time.Time) (*entity.RefreshToken, error) {
	query := fmt.Sprintf(`
		UPDATE %s
		SET revoked = true, rotated_at = $2
		WHERE hash = $1 AND NOT revoked AND expires_at > $2
		RETURNING %s
	`, s.tableRefreshTokens, refreshRowColumns)

	token, err := scanRefreshToken(s.pool.QueryRow(ctx, query, hash, now))
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	// Nothing matched: tell missing, revoked and expired apart. revoked only
	// ever goes false -> true, so this read cannot contradict the UPDATE.
	token, err = s.GetRefreshToken(ctx, hash)
	if err != nil {
		return nil, err
	}
	if token.Revoked {
		return token, store.ErrTokenRevoked
	}
	return token, store.ErrTokenExpired
}

// GetRefreshFamily summarises the family rooted at root.
func (s *Store) GetRefreshFamily(ctx context.Context, root string) (*entity.RefreshFamily, error) {
	query := fmt.Sprintf(`
		SELECT COALESCE(bool_or(ended_at IS NOT NULL), false), max(rotated_at)
		FROM %s
		WHERE hash = $1 OR parent = $1
	`, s.tableRefreshTokens)

	family := &entity.RefreshFamily{}
	if err := s.pool.QueryRow(ctx, query, root).Scan(&family.SessionEnded, &family.LastRotatedAt); err != nil {
		return nil, fmt.Errorf("query refresh family: %w", err)
	}
	return family, nil
}

// RevokeTokens revokes a token and all tokens in its family.
func (s *Store) RevokeTokens(ctx context.Context, hash string) error {
	// Lock the root first, in its own statement: under READ COMMITTED the
	// UPDATE below then takes its snapshot after any successor that held the
	// share lock (SaveRefreshToken) has committed, so it cannot miss it.
	lockRoot := fmt.Sprintf(`SELECT 1 FROM %s WHERE hash = $1 FOR UPDATE`, s.tableRefreshTokens)
	revoke := fmt.Sprintf(`
		UPDATE %s
		SET revoked = true, ended_at = COALESCE(ended_at, now())
		WHERE hash = $1 OR parent = $1
	`, s.tableRefreshTokens)

	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, lockRoot, hash); err != nil {
			return fmt.Errorf("lock refresh family root: %w", err)
		}
		if _, err := tx.Exec(ctx, revoke, hash); err != nil {
			return fmt.Errorf("revoke tokens: %w", err)
		}
		return nil
	})
}

// --- PATStore implementation ---

// SavePAT persists a personal access token.
func (s *Store) SavePAT(ctx context.Context, pat *entity.PersonalAccessToken) error {
	if pat.CreatedAt.IsZero() {
		pat.CreatedAt = time.Now()
	}

	// pgx encodes a nil slice as SQL NULL, which violates the NOT NULL scopes
	// column (the '{}' default only applies when the column is omitted). Coalesce
	// to an empty array so PATs created without scopes persist cleanly.
	scopes := pat.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (id, hash, user_id, name, scopes, expires_at, last_used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, s.tablePATs)

	_, err := s.pool.Exec(ctx, query,
		pat.ID, pat.Hash, pat.UserID, pat.Name, scopes, pat.ExpiresAt, pat.LastUsedAt, pat.CreatedAt)
	return patSaveError(pat, err)
}

// SavePATLimited persists a token unless the user already holds limit that have
// not expired at now; the user's expired ones are deleted first. A conditional
// INSERT alone is not enough: under READ COMMITTED two transactions both count
// before either commits. The user row is locked first to serialise creates per
// user; FOR NO KEY UPDATE does not block the foreign-key checks of other
// writers (they take FOR KEY SHARE). A missing user matches no row to lock and
// is reported as store.ErrUserNotFound.
func (s *Store) SavePATLimited(ctx context.Context, pat *entity.PersonalAccessToken, limit int, now time.Time) error {
	if pat.CreatedAt.IsZero() {
		pat.CreatedAt = time.Now()
	}
	scopes := pat.Scopes // nil would be NULL; see SavePAT
	if scopes == nil {
		scopes = []string{}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		// Rollback after a commit is a no-op; a failed one is superseded by
		// the error already being returned.
		_ = tx.Rollback(ctx)
	}()

	if err := s.lockUser(ctx, tx, pat.UserID); err != nil {
		return err
	}

	prune := fmt.Sprintf(`DELETE FROM %s WHERE user_id = $1 AND expires_at < $2`, s.tablePATs)
	if _, err := tx.Exec(ctx, prune, pat.UserID, now); err != nil {
		return fmt.Errorf("prune expired pats: %w", err)
	}

	insert := fmt.Sprintf(`
		INSERT INTO %[1]s (id, hash, user_id, name, scopes, expires_at, last_used_at, created_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8
		WHERE (SELECT count(*) FROM %[1]s WHERE user_id = $3) < $9
	`, s.tablePATs)
	tag, err := tx.Exec(ctx, insert,
		pat.ID, pat.Hash, pat.UserID, pat.Name, scopes, pat.ExpiresAt, pat.LastUsedAt, pat.CreatedAt, limit)
	if err != nil {
		return patSaveError(pat, err)
	}
	// Commit also on a refusal: the prune is worth keeping.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrPATLimitReached
	}
	return nil
}

// lockUser takes the user row lock that serialises PAT creates for the user.
func (s *Store) lockUser(ctx context.Context, tx pgx.Tx, userID string) error {
	var locked string
	query := fmt.Sprintf(`SELECT id::text FROM %s WHERE id = $1 FOR NO KEY UPDATE`, s.tableUsers)
	if err := tx.QueryRow(ctx, query, userID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", store.ErrUserNotFound, userID)
		}
		return fmt.Errorf("lock user: %w", err)
	}
	return nil
}

// patSaveError maps a failed PAT insert to the store's typed errors.
func patSaveError(pat *entity.PersonalAccessToken, err error) error {
	if err == nil {
		return nil
	}
	if isDuplicateKeyError(err) {
		return fmt.Errorf("%w: %s", store.ErrPATExists, pat.ID)
	}
	return insertError("insert pat", pat.UserID, err)
}

// GetPAT retrieves a personal access token by its hash.
func (s *Store) GetPAT(ctx context.Context, hash string) (*entity.PersonalAccessToken, error) {
	query := fmt.Sprintf(`
		SELECT id, hash, user_id, name, scopes, expires_at, last_used_at, created_at
		FROM %s
		WHERE hash = $1
	`, s.tablePATs)

	pat := &entity.PersonalAccessToken{}
	err := s.pool.QueryRow(ctx, query, hash).Scan(
		&pat.ID, &pat.Hash, &pat.UserID, &pat.Name, &pat.Scopes, &pat.ExpiresAt, &pat.LastUsedAt, &pat.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrTokenNotFound
		}
		return nil, fmt.Errorf("query pat: %w", err)
	}

	return pat, nil
}

// ListPATs returns all personal access tokens for a user.
func (s *Store) ListPATs(ctx context.Context, userID string) ([]*entity.PersonalAccessToken, error) {
	query := fmt.Sprintf(`
		SELECT id, hash, user_id, name, scopes, expires_at, last_used_at, created_at
		FROM %s
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, s.tablePATs)

	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query pats: %w", err)
	}
	defer rows.Close()

	var out []*entity.PersonalAccessToken
	for rows.Next() {
		pat := &entity.PersonalAccessToken{}
		if err := rows.Scan(
			&pat.ID, &pat.Hash, &pat.UserID, &pat.Name, &pat.Scopes, &pat.ExpiresAt, &pat.LastUsedAt, &pat.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan pat: %w", err)
		}
		out = append(out, pat)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pats: %w", err)
	}

	return out, nil
}

// DeletePAT removes a token by its UUID, scoped to its owner.
func (s *Store) DeletePAT(ctx context.Context, userID, id string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE id = $1 AND user_id = $2`, s.tablePATs)

	result, err := s.pool.Exec(ctx, query, id, userID)
	if err != nil {
		return fmt.Errorf("delete pat: %w", err)
	}
	if result.RowsAffected() == 0 {
		return store.ErrTokenNotFound
	}

	return nil
}

// TouchPAT records last-used time.
func (s *Store) TouchPAT(ctx context.Context, hash string, t time.Time) error {
	query := fmt.Sprintf(`UPDATE %s SET last_used_at = $2 WHERE hash = $1`, s.tablePATs)

	_, err := s.pool.Exec(ctx, query, hash, t)
	if err != nil {
		return fmt.Errorf("touch pat: %w", err)
	}

	return nil
}

// --- OAuthIdentityStore implementation ---

// SaveOAuthIdentity persists a new OAuth identity.
func (s *Store) SaveOAuthIdentity(ctx context.Context, identity *entity.OAuthIdentity) error {
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = time.Now()
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (id, user_id, provider, external_id, email, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, s.tableOAuthIdentities)

	_, err := s.pool.Exec(ctx, query,
		identity.ID, identity.UserID, identity.Provider, identity.ExternalID, identity.Email, identity.CreatedAt)
	if err != nil {
		if isDuplicateKeyError(err) {
			return fmt.Errorf("%w: %s/%s", store.ErrOAuthIdentityExists, identity.Provider, identity.ExternalID)
		}
		return insertError("insert oauth identity", identity.UserID, err)
	}

	return nil
}

// GetOAuthIdentity retrieves an identity by provider and external account id.
func (s *Store) GetOAuthIdentity(ctx context.Context, provider, externalID string) (*entity.OAuthIdentity, error) {
	query := fmt.Sprintf(`
		SELECT id, user_id, provider, external_id, email, created_at
		FROM %s
		WHERE provider = $1 AND external_id = $2
	`, s.tableOAuthIdentities)

	identity := &entity.OAuthIdentity{}
	err := s.pool.QueryRow(ctx, query, provider, externalID).Scan(
		&identity.ID, &identity.UserID, &identity.Provider, &identity.ExternalID, &identity.Email, &identity.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s/%s", store.ErrOAuthIdentityNotFound, provider, externalID)
		}
		return nil, fmt.Errorf("query oauth identity: %w", err)
	}

	return identity, nil
}

// ListOAuthIdentities returns all OAuth identities linked to a user.
func (s *Store) ListOAuthIdentities(ctx context.Context, userID string) ([]*entity.OAuthIdentity, error) {
	query := fmt.Sprintf(`
		SELECT id, user_id, provider, external_id, email, created_at
		FROM %s
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, s.tableOAuthIdentities)

	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query oauth identities: %w", err)
	}
	defer rows.Close()

	var out []*entity.OAuthIdentity
	for rows.Next() {
		identity := &entity.OAuthIdentity{}
		if err := rows.Scan(
			&identity.ID, &identity.UserID, &identity.Provider, &identity.ExternalID, &identity.Email, &identity.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan oauth identity: %w", err)
		}
		out = append(out, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate oauth identities: %w", err)
	}

	return out, nil
}

// --- WalletIdentityStore implementation ---

// SaveWalletIdentity persists a new wallet identity.
func (s *Store) SaveWalletIdentity(ctx context.Context, identity *entity.WalletIdentity) error {
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = time.Now()
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (id, user_id, chain, address, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, s.tableWalletIdentities)

	_, err := s.pool.Exec(ctx, query,
		identity.ID, identity.UserID, identity.Chain, identity.Address, identity.CreatedAt)
	if err != nil {
		if isDuplicateKeyError(err) {
			return fmt.Errorf("%w: %s/%s", store.ErrWalletIdentityExists, identity.Chain, identity.Address)
		}
		return insertError("insert wallet identity", identity.UserID, err)
	}

	return nil
}

// GetWalletIdentity retrieves an identity by chain and normalized address.
func (s *Store) GetWalletIdentity(ctx context.Context, chain, address string) (*entity.WalletIdentity, error) {
	query := fmt.Sprintf(`
		SELECT id, user_id, chain, address, created_at
		FROM %s
		WHERE chain = $1 AND address = $2
	`, s.tableWalletIdentities)

	identity := &entity.WalletIdentity{}
	err := s.pool.QueryRow(ctx, query, chain, address).Scan(
		&identity.ID, &identity.UserID, &identity.Chain, &identity.Address, &identity.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s/%s", store.ErrWalletIdentityNotFound, chain, address)
		}
		return nil, fmt.Errorf("query wallet identity: %w", err)
	}

	return identity, nil
}

// ListWalletIdentities returns all wallet identities linked to a user.
func (s *Store) ListWalletIdentities(ctx context.Context, userID string) ([]*entity.WalletIdentity, error) {
	query := fmt.Sprintf(`
		SELECT id, user_id, chain, address, created_at
		FROM %s
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, s.tableWalletIdentities)

	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query wallet identities: %w", err)
	}
	defer rows.Close()

	var out []*entity.WalletIdentity
	for rows.Next() {
		identity := &entity.WalletIdentity{}
		if err := rows.Scan(
			&identity.ID, &identity.UserID, &identity.Chain, &identity.Address, &identity.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan wallet identity: %w", err)
		}
		out = append(out, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate wallet identities: %w", err)
	}

	return out, nil
}

// --- ChallengeStore implementation ---

// SaveChallenge persists a challenge keyed by its nonce. Expired rows are
// swept opportunistically on every save so the table stays bounded without
// a scheduled job (the expires_at index keeps the sweep cheap).
func (s *Store) SaveChallenge(ctx context.Context, challenge *entity.Challenge) error {
	if challenge.CreatedAt.IsZero() {
		challenge.CreatedAt = time.Now()
	}

	sweep := fmt.Sprintf(`DELETE FROM %s WHERE expires_at < now()`, s.tableChallenges)
	if _, err := s.pool.Exec(ctx, sweep); err != nil {
		return fmt.Errorf("sweep expired challenges: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (nonce, message, chain, address, code_verifier, oauth_nonce, binding_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, s.tableChallenges)

	_, err := s.pool.Exec(ctx, query,
		challenge.Nonce, challenge.Message, challenge.Chain, challenge.Address,
		challenge.CodeVerifier, challenge.OAuthNonce, challenge.BindingHash,
		challenge.ExpiresAt, challenge.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert challenge: %w", err)
	}

	return nil
}

// GetChallenge retrieves a challenge by nonce. An expired challenge is
// reported as store.ErrChallengeExpired (removal is left to the sweep).
func (s *Store) GetChallenge(ctx context.Context, nonce string) (*entity.Challenge, error) {
	query := fmt.Sprintf(`
		SELECT nonce, message, chain, address, code_verifier, oauth_nonce, binding_hash, expires_at, created_at
		FROM %s
		WHERE nonce = $1
	`, s.tableChallenges)

	challenge := &entity.Challenge{}
	err := s.pool.QueryRow(ctx, query, nonce).Scan(
		&challenge.Nonce, &challenge.Message, &challenge.Chain, &challenge.Address,
		&challenge.CodeVerifier, &challenge.OAuthNonce, &challenge.BindingHash,
		&challenge.ExpiresAt, &challenge.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrChallengeNotFound
		}
		return nil, fmt.Errorf("query challenge: %w", err)
	}

	if challenge.ExpiresAt.Before(time.Now()) {
		return nil, store.ErrChallengeExpired
	}

	return challenge, nil
}

// DeleteChallenge removes a challenge by nonce.
func (s *Store) DeleteChallenge(ctx context.Context, nonce string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE nonce = $1`, s.tableChallenges)

	result, err := s.pool.Exec(ctx, query, nonce)
	if err != nil {
		return fmt.Errorf("delete challenge: %w", err)
	}
	if result.RowsAffected() == 0 {
		return store.ErrChallengeNotFound
	}

	return nil
}

// --- CredentialStore implementation ---

// SavePasswordHash stores a password hash for a user.
func (s *Store) SavePasswordHash(ctx context.Context, userID, hash string) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (user_id, password_hash, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (user_id) DO UPDATE SET password_hash = $2, updated_at = NOW()
	`, s.tableLocalCredentials)

	_, err := s.pool.Exec(ctx, query, userID, hash)
	if err != nil {
		return insertError("save password hash", userID, err)
	}

	return nil
}

// GetPasswordHash retrieves a password hash for a user.
func (s *Store) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	query := fmt.Sprintf(`
		SELECT password_hash
		FROM %s
		WHERE user_id = $1
	`, s.tableLocalCredentials)

	var hash string
	err := s.pool.QueryRow(ctx, query, userID).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("%w: %s", store.ErrCredentialNotFound, userID)
		}
		return "", fmt.Errorf("query password hash: %w", err)
	}

	return hash, nil
}

// insertError wraps a failed write of a user-owned row. Every such table has
// a foreign key to users, so a violation means the user does not exist.
func insertError(op, userID string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pqForeignKeyViolation {
		return fmt.Errorf("%w: %s", store.ErrUserNotFound, userID)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// isDuplicateKeyError checks if error is a unique constraint violation.
func isDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == pqUniqueViolation
	}
	return false
}
