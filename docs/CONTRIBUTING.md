# Contributing to psina

Thanks for your interest in contributing! 🐕

## Development Setup

### Prerequisites

- Go 1.22+
- PostgreSQL 14+ (or Docker)
- buf (for protobuf)
- golang-migrate

### Clone and setup

```bash
git clone https://github.com/foxcool/psina.git
cd psina

# Install dependencies
go mod download

# Start PostgreSQL (Docker)
docker run -d --name psina-db \
  -e POSTGRES_USER=psina \
  -e POSTGRES_PASSWORD=psina \
  -e POSTGRES_DB=psina \
  -p 5432:5432 \
  postgres:16

# Run migrations
export DATABASE_URL="postgres://psina:psina@localhost:5432/psina?sslmode=disable"
migrate -path migrations -database $DATABASE_URL up

# Run tests
go test ./...
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
├── psina/     # Main package
├── provider/  # Auth providers
├── store/     # Storage backends
├── token/     # JWT handling
└── gateway/   # Gateway integrations

internal/      # Private implementation (can change freely)
cmd/psina/     # Standalone binary
api/           # Proto definitions
migrations/    # SQL migrations
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

Providers implement the `Provider` interface:

```go
// pkg/provider/provider.go
type Provider interface {
    Type() string
    Authenticate(ctx context.Context, req AuthRequest) (*Identity, error)
    Register(ctx context.Context, req RegisterRequest) (*Identity, error)
}
```

Steps:

1. Create `pkg/provider/yourprovider/` directory
2. Implement the interface
3. Add tests
4. Add registration in `pkg/psina/options.go`
5. Update documentation

## Adding a New Store

Stores implement `UserStore` and `TokenStore` interfaces:

```go
// pkg/store/store.go
type UserStore interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id string) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
    Update(ctx context.Context, user *User) error
}
```

Steps:

1. Create `pkg/store/yourstore/` directory
2. Implement interfaces
3. Add integration tests
4. Add option in `pkg/psina/options.go`

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
