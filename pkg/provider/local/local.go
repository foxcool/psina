package local

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/foxcool/psina/pkg/psina"
	"golang.org/x/crypto/argon2"
)

const (
	ProviderType = "local"
)

// Argon2 parameters following OWASP recommendations
const (
	argon2Memory      = 64 * 1024 // 64 MB
	argon2Iterations  = 3
	argon2Parallelism = 2
	argon2SaltLength  = 16
	argon2KeyLength   = 32
)

// Provider implements psina.Provider for username/password authentication.
type Provider struct {
	userStore       psina.UserStore
	credentialStore psina.CredentialStore
}

// New creates a new local authentication provider.
func New(userStore psina.UserStore, credentialStore psina.CredentialStore) *Provider {
	return &Provider{
		userStore:       userStore,
		credentialStore: credentialStore,
	}
}

// Type returns the provider type identifier.
func (p *Provider) Type() string {
	return ProviderType
}

// Register creates a new user account with password.
func (p *Provider) Register(ctx context.Context, req *psina.RegisterRequest) (*psina.Identity, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email required")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("password required")
	}

	// Check if user already exists
	existing, err := p.userStore.GetByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("user already exists")
	}

	// Hash password
	passwordHash, err := hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Create user (using email as ID for MVP, should use UUID in production)
	user := &psina.User{
		ID:    generateUserID(),
		Email: req.Email,
	}

	// Store password hash in metadata (MVP approach)
	// TODO: Move to separate credentials table in production
	if err := p.userStore.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	// Store password hash
	if err := p.credentialStore.SavePasswordHash(ctx, user.ID, passwordHash); err != nil {
		return nil, fmt.Errorf("store password: %w", err)
	}

	return &psina.Identity{
		UserID:   user.ID,
		Email:    user.Email,
		Provider: ProviderType,
		Metadata: map[string]string{},
	}, nil
}

// Authenticate verifies email and password credentials.
func (p *Provider) Authenticate(ctx context.Context, req *psina.AuthRequest) (*psina.Identity, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email required")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("password required")
	}

	// Retrieve user
	user, err := p.userStore.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Get stored password hash
	storedHash, err := p.credentialStore.GetPasswordHash(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	if !verifyPassword(req.Password, storedHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return &psina.Identity{
		UserID:   user.ID,
		Email:    user.Email,
		Provider: ProviderType,
		Metadata: map[string]string{},
	}, nil
}

// hashPassword creates an Argon2id hash of the password.
func hashPassword(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Hash password with Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLength,
	)

	// Encode as: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory,
		argon2Iterations,
		argon2Parallelism,
		encodedSalt,
		encodedHash,
	), nil
}

// verifyPassword checks if a password matches the hash.
func verifyPassword(password, encodedHash string) bool {
	// Parse encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	// Extract salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	// Hash provided password with same parameters
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLength,
	)

	// Constant-time comparison
	return subtle.ConstantTimeCompare(storedHash, computedHash) == 1
}

// generateUserID creates a simple user ID for MVP.
// TODO: Use UUID in production.
func generateUserID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
