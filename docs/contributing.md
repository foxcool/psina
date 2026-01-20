# Contributing to psina

Thanks for your interest in contributing! 🐕

## Development Setup

### Prerequisites

- Go 1.24+
- PostgreSQL 16+ (or Docker)
- buf (for protobuf)
- make

### Clone and setup

```bash
git clone https://github.com/foxcool/psina.git
cd psina

# Start dev environment (postgres + psina with live reload)
make up

# Or run tests only
make test-unit           # unit tests
make test-integration    # with postgres

# Stop environment
make down
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable names
- Write table-driven tests
- Add godoc comments for exported types/functions
- Errors with context: `fmt.Errorf("doing X: %w", err)`

## Project Structure

```text
pkg/           # Public API (maintain backward compatibility!)
├── psina/     # Main package (service, handler, interfaces)
├── provider/  # Auth providers (local, passkey, wallet)
├── store/     # Storage backends (postgres, memory)
└── token/     # JWT handling

cmd/psina/     # Standalone binary
api/           # Proto definitions
migrations/    # SQL migrations
deploy/        # Docker, compose, examples
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
- Integration tests for store implementations
- Table-driven tests preferred

### 4. Update documentation

- Update README if adding features
- Update ROADMAP if relevant
- Add godoc comments

### 5. Submit PR

- Clear description of changes
- Reference related issues
- Ensure CI passes

## Adding a New Provider

Providers implement the `Provider` interface defined in `pkg/psina/provider.go`:

```go
type Provider interface {
    Type() string
    Authenticate(ctx context.Context, req *AuthRequest) (*Identity, error)
    Register(ctx context.Context, req *RegisterRequest) (*Identity, error)
}
```

Steps:

1. Create `pkg/provider/yourprovider/` directory
2. Implement the interface
3. Add tests
4. Update documentation

## Adding a New Store

Stores implement interfaces defined in `pkg/psina/store.go`:

```go
type UserStore interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id string) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
}

type TokenStore interface {
    SaveRefreshToken(ctx context.Context, token *RefreshToken) error
    GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error)
    RevokeRefreshToken(ctx context.Context, hash string) error
}
```

Steps:

1. Create `pkg/store/yourstore/` directory
2. Implement interfaces
3. Add integration tests

## Commit Messages

Format: `type: description`

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `chore`: Maintenance

Examples:

```text
feat: add passkey provider
fix: handle expired refresh tokens
docs: update Traefik integration guide
test: add local provider tests
```

## Questions?

Open an issue or discussion. We're happy to help!
