# Contributing to psina

Thanks for your interest in contributing! 🐕

## Development Setup

See [docs/development.md](development.md) for detailed setup instructions.

### Quick start

```bash
git clone https://github.com/foxcool/psina.git
cd psina

# Start dev environment
make up

# Run tests
make test

# Stop
make down
```

## Code Style

- Standard Go conventions (`gofmt`, `go vet`, `golangci-lint`)
- Meaningful variable names
- Table-driven tests
- Godoc comments for exported types/functions
- Errors with context: `fmt.Errorf("operation: %w", err)`
- Interfaces in `ports.go`, implementations in separate packages

## Project Structure

```text
pkg/                    # Library code (public API)
├── auth/               # Service layer + interfaces (ports.go)
├── entity/             # Domain types (User, Token, Claims)
├── provider/           # Auth providers (local, passkey, wallet)
├── store/              # Storage backends (postgres, memory)
└── token/              # JWT issuer

cmd/psina/              # Standalone binary
api/auth/v1/            # Proto definitions
deploy/                 # Docker, compose, examples
docs/                   # Documentation
```

## Making Changes

### 1. Create an issue first

For non-trivial changes, open an issue to discuss the approach.

### 2. Fork and branch

```bash
git checkout -b feature/your-feature
# or
git checkout -b fix/your-fix
```

### 3. Write tests

- Unit tests for new logic
- Integration tests for store implementations (use testcontainers)
- Table-driven tests preferred

```bash
make test-unit          # Fast feedback
make test-integration   # With real PostgreSQL
```

### 4. Run linter

```bash
golangci-lint run
```

### 5. Update documentation

- Update README.md if adding features
- Add godoc comments for exported symbols

### 6. Submit PR

- Clear description of changes
- Reference related issues (`Fixes #123`)
- Ensure CI passes (lint + tests + docker build)

## Adding a New Provider

Providers implement the `Provider` interface in `pkg/auth/ports.go`:

```go
type Provider interface {
    Type() string
    Authenticate(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error)
    Register(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error)
}
```

Steps:

1. Create `pkg/provider/yourprovider/` directory
2. Implement the interface
3. Add unit tests (`yourprovider_test.go`)
4. Update README roadmap table
5. Add integration example if needed

Example: see `pkg/provider/local/` for reference.

## Adding a New Store

Stores implement interfaces in `pkg/auth/ports.go`:

```go
type UserStore interface {
    Create(ctx context.Context, user *entity.User) error
    GetByID(ctx context.Context, id string) (*entity.User, error)
    GetByEmail(ctx context.Context, email string) (*entity.User, error)
    Delete(ctx context.Context, id string) error
}

type TokenStore interface {
    SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error
    GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error)
    RevokeTokens(ctx context.Context, hash string) error
}

type CredentialStore interface {
    SavePasswordHash(ctx context.Context, userID, hash string) error
    GetPasswordHash(ctx context.Context, userID string) (string, error)
}
```

Steps:

1. Create `pkg/store/yourstore/` directory
2. Implement all three interfaces (or subset if applicable)
3. Use typed errors from `pkg/store/errors.go`
4. Add integration tests with real database
5. Update documentation

Example: see `pkg/store/postgres/` and `pkg/store/memory/` for reference.

## Commit Messages

Format: `type: description`

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding/fixing tests
- `refactor`: Code change that doesn't fix bug or add feature
- `chore`: Maintenance (deps, CI, etc.)

Examples:

```text
feat: add passkey provider
fix: handle expired refresh tokens correctly
docs: update Traefik integration example
test: add token reuse detection tests
refactor: extract TokenIssuer interface
chore: update Go to 1.24
```

## Error Handling

Use typed errors for matching:

```go
// In pkg/store/errors.go
var ErrUserNotFound = errors.New("user not found")

// In store implementation
return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, id)

// In service/handler
if errors.Is(err, store.ErrUserNotFound) {
    return nil, connect.NewError(connect.CodeNotFound, err)
}
```

## Security Considerations

- Never log passwords or tokens (only hashes)
- Use constant-time comparison for secrets
- Validate all inputs
- Follow OWASP guidelines for auth

## Questions?

Open an issue or discussion. We're happy to help!
