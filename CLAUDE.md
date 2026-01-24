# CLAUDE.md — psina project instructions

## Project Overview

**psina** — embeddable Go authentication service. Works as library (import into your app) or standalone microservice.

Name origin: "psina" (рус. "псина") = "doggy" — a guard dog that knows pack from strangers.

## Current Status

**v0.1 MVP** — Local auth working, needs polish before public release.

See `docs/ROADMAP.md` for detailed task list.

## Directory Structure

```
psina/
├── cmd/psina/           # Standalone binary
│   ├── main.go          # Server entrypoint (koanf + slog + graceful shutdown)
│   └── config.go        # Configuration loading
├── pkg/
│   ├── api/auth/v1/     # Generated Connect RPC code (DO NOT EDIT)
│   ├── auth/            # Service layer (orchestration + handler)
│   │   ├── service.go   # Business logic orchestration
│   │   ├── handler.go   # Connect RPC handler
│   │   ├── ports.go     # Interface definitions (Provider, Stores)
│   │   └── validation.go
│   ├── entity/          # Domain types (User, Identity, TokenPair, etc.)
│   ├── token/           # JWT issuer (pure cryptography, no storage)
│   ├── provider/        # Auth provider implementations
│   │   └── local/       # Username/password (Argon2id)
│   ├── store/           # Storage backends
│   │   ├── postgres/    # Production store
│   │   └── memory/      # Testing/dev store
│   └── testutil/        # Test helpers (testcontainers)
├── api/auth/v1/         # Proto definitions
│   └── auth.proto
├── deploy/              # Docker, compose, examples
├── docs/                # Documentation
└── schema.hcl           # Database schema (Atlas)
```

## Architecture

**Hexagonal (Ports & Adapters)**:
- `pkg/auth/ports.go` — interfaces (Provider, UserStore, TokenStore, CredentialStore)
- `pkg/auth/service.go` — orchestration (implements business flows)
- `pkg/provider/`, `pkg/store/` — adapters

**Key principle**: Domain logic in `pkg/auth/` and `pkg/entity/`, adapters are replaceable.

## Core Interfaces

```go
// Provider authenticates users via specific method
type Provider interface {
    Type() string  // "local", "passkey", "wallet"
    Authenticate(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error)
    Register(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error)
}

// UserStore persists users
type UserStore interface {
    Create(ctx context.Context, user *entity.User) error
    GetByID(ctx context.Context, id string) (*entity.User, error)
    GetByEmail(ctx context.Context, email string) (*entity.User, error)
}

// TokenStore handles refresh tokens
type TokenStore interface {
    SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error
    GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error)
    RevokeTokens(ctx context.Context, hash string) error  // revokes token and its family
}

// CredentialStore handles password hashes (separated from UserStore)
type CredentialStore interface {
    SavePasswordHash(ctx context.Context, userID, hash string) error
    GetPasswordHash(ctx context.Context, userID string) (string, error)
}
```

## Tech Stack

- **Go 1.24+**
- **Connect RPC** — gRPC + HTTP/JSON on same port
- **PostgreSQL** — production storage
- **Atlas** — declarative schema management
- **buf** — protobuf generation (local plugins)
- **koanf** — configuration
- **slog** — structured logging
- **testcontainers** — integration tests

## Development Commands

```bash
# Run standalone (dev mode, in-memory store)
go run ./cmd/psina/...

# Run with postgres
PSINA_DB_URL="postgres://user:pass@localhost:5432/psina?sslmode=disable" go run ./cmd/psina/...

# Generate proto
buf generate

# Apply schema to database
atlas schema apply --env local --auto-approve

# Tests
make test-unit              # Unit tests only
make test-integration       # Integration tests (requires Atlas CLI + Docker)

# Docker
make up                     # Start dev environment
make down                   # Stop
make logs                   # Follow logs
```

## Configuration

Priority: defaults → config file → environment variables

```yaml
# config.yaml
logger:
  level: info      # debug, info, warn, error
  format: json     # json, text
server:
  port: 8080
db:
  url: ""          # Empty = in-memory store
jwt:
  privateKeyPath: "" # Empty = ephemeral key (dev only!)
```

Environment: `PSINA_SERVER_PORT`, `PSINA_DB_URL`, `PSINA_JWT_PRIVATEKEYPATH`

## HTTP Endpoints

```
POST /auth.v1.AuthService/Register     - Create account + return tokens
POST /auth.v1.AuthService/Login        - Authenticate + return tokens
POST /auth.v1.AuthService/Refresh      - Refresh access token
POST /auth.v1.AuthService/Logout       - Revoke refresh token
POST /auth.v1.AuthService/Verify       - Validate token (ForwardAuth)
GET  /.well-known/jwks.json            - Public keys for gateway validation
GET  /health                           - Health check
```

## Security Parameters

```go
// JWT
AccessTokenTTL  = 15 * time.Minute
RefreshTokenTTL = 7 * 24 * time.Hour
Algorithm       = RS256

// Argon2id (OWASP recommendations)
Memory      = 64 * 1024  // 64 MB
Iterations  = 3
Parallelism = 2
SaltLength  = 16
KeyLength   = 32
```

## Known Issues (v0.1)

Track in ROADMAP.md. Key items:
- [ ] Token family revocation not implemented (Parent field missing)
- [ ] Postgres error handling uses string matching
- [ ] No rate limiting
- [ ] Health check doesn't verify DB connection

## Code Style

- Standard Go conventions
- Errors with context: `fmt.Errorf("operation: %w", err)`
- Table-driven tests
- Interfaces in `ports.go`, implementations in separate packages

## Integration Examples

**Embedded in greedy-eye:**
```go
import (
    "github.com/foxcool/psina/pkg/auth"
    "github.com/foxcool/psina/pkg/provider/local"
    "github.com/foxcool/psina/pkg/store/postgres"
    "github.com/foxcool/psina/pkg/token"
)

func main() {
    store, _ := postgres.NewWithDSN(ctx, dbURL)
    issuer, _ := token.NewWithKey(privateKey)
    provider := local.New(store, store)
    service := auth.NewService(provider, store, store, issuer)
    handler := auth.NewHandler(service)
    
    // Mount on your mux
    path, rpcHandler := authv1connect.NewAuthServiceHandler(handler)
    mux.Handle(path, rpcHandler)
}
```

**Traefik ForwardAuth:**
```yaml
http:
  middlewares:
    auth:
      forwardAuth:
        address: "http://psina:8080/auth.v1.AuthService/Verify"
        authResponseHeaders:
          - "X-User-Id"
          - "X-User-Email"
```

**KrakenD JWKS:**
```json
{
  "extra_config": {
    "auth/validator": {
      "alg": "RS256",
      "jwk_url": "http://psina:8080/.well-known/jwks.json",
      "cache": true
    }
  }
}
```
