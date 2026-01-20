# CLAUDE.md - Project Instructions for Claude Code

## Project Overview

**psina** — embeddable Go authentication service. Works as library
(import into your app) or standalone microservice.

Name origin: "psina" (rus. "псина") = "doggy" — a guard dog that
knows pack from strangers.

## Architecture

- **Hexagonal architecture**: domain isolated from adapters
- **Plugin system**: authentication providers as pluggable modules
- **Dual deployment**: `pkg/` for embedding, `cmd/psina/` for standalone

## Directory Structure

```text
psina/
├── cmd/psina/          # Standalone binary entrypoint
├── pkg/                # Public API (importable by other projects)
│   ├── api/            # Generated proto code (pb.go, connect.go)
│   ├── psina/          # Main package: Service, Handler, interfaces
│   ├── provider/       # Auth provider implementations
│   │   └── local/      # Username/password (Argon2id)
│   ├── token/          # JWT issuance, validation, JWKS
│   └── store/          # Storage backends
│       ├── postgres/   # Production store
│       └── memory/     # For testing/dev
├── api/                # Proto definitions (Connect RPC)
├── migrations/         # SQL migrations (golang-migrate format)
├── deploy/             # Docker, compose, examples
└── docs/               # Architecture documentation
```

## Key Design Decisions

1. **pkg/ over internal/**: Public API for embedding in other Go projects
2. **Provider interface**: All auth methods implement same contract
3. **Store interface**: Pluggable storage backends
4. **Stateless JWT**: RS256 with JWKS endpoint for gateway validation

## Tech Stack

- Go 1.24+
- Connect RPC (gRPC + HTTP/JSON on same port)
- PostgreSQL (primary) / Memory store (dev/testing)
- buf for protobuf management (local plugins only)
- golang-migrate for migrations
- koanf for configuration
- slog for structured logging

## Go Dependencies

```go
// Core
connectrpc.com/connect              // Connect RPC framework
google.golang.org/protobuf          // Protobuf runtime

// JWT & Crypto
github.com/go-jose/go-jose/v4       // JOSE/JWT/JWK
golang.org/x/crypto                 // Argon2id

// Database
github.com/jackc/pgx/v5             // PostgreSQL driver

// Configuration
github.com/knadh/koanf/v2           // Config management

// HTTP
golang.org/x/net/http2/h2c          // HTTP/2 cleartext (for Connect)

// Testing
github.com/stretchr/testify         // Assertions
```

## Development Commands

```bash
# Run standalone
go run cmd/psina/main.go

# Run tests
go test ./...

# Generate proto (Connect RPC + OpenAPI 3.1)
buf generate

# Run migrations
migrate -path migrations -database $DATABASE_URL up

# Build binary
go build -o bin/psina cmd/psina/main.go
```

## buf.gen.yaml

```yaml
version: v2
plugins:
  # Go code
  - local: protoc-gen-go
    out: gen/go
    opt: paths=source_relative

  # Connect RPC (replaces grpc + grpc-gateway)
  - local: protoc-gen-connect-go
    out: gen/go
    opt: paths=source_relative

  # OpenAPI 3.1 spec (optional, install protoc-gen-connect-openapi)
  # - local: protoc-gen-connect-openapi
  #   out: gen/openapi
```

## Current Status: v0.1 Complete ✅

**Implemented:**

- Local auth (email/password with Argon2id)
- JWT tokens (RS256, 15min access, 7d refresh)
- JWKS endpoint (/.well-known/jwks.json)
- Connect RPC API (HTTP/JSON + gRPC on same port)
- PostgreSQL store (production)
- Memory store (dev/testing)
- Traefik ForwardAuth integration
- Docker support + CI/CD

**Next phase (v0.2):** Passkeys/WebAuthn — see docs/ROADMAP.md

## Core Interfaces

```go
// Provider authenticates users via specific method
type Provider interface {
    Type() string  // "local", "passkey", "wallet"
    Authenticate(ctx context.Context, req *AuthRequest) (*Identity, error)
    Register(ctx context.Context, req *RegisterRequest) (*Identity, error)
}

type Identity struct {
    UserID   string
    Email    string
    Provider string
    Metadata map[string]string
}

// Store persists users and tokens
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

// TokenIssuer handles JWT lifecycle
type TokenIssuer interface {
    Issue(ctx context.Context, identity *Identity) (*TokenPair, error)
    Validate(ctx context.Context, accessToken string) (*Claims, error)
    Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)
    JWKS() *jose.JSONWebKeySet
}
```

## Proto API (api/auth/v1/auth.proto)

```protobuf
syntax = "proto3";
package auth.v1;

service AuthService {
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc Login(LoginRequest) returns (LoginResponse);
  rpc Refresh(RefreshRequest) returns (RefreshResponse);
  rpc Logout(LogoutRequest) returns (LogoutResponse);
  rpc Verify(VerifyRequest) returns (VerifyResponse);  // For ForwardAuth
}

message RegisterRequest {
  string email = 1;
  string password = 2;
}

message LoginRequest {
  string email = 1;
  string password = 2;
}

message LoginResponse {
  string access_token = 1;
  string refresh_token = 2;
  int64 expires_in = 3;  // seconds
}

message RefreshRequest {
  string refresh_token = 1;
}

message VerifyRequest {
  // Token from Authorization header, extracted by Connect interceptor
}

message VerifyResponse {
  string user_id = 1;
  string email = 2;
  // Headers for gateway: X-User-Id, X-User-Email
}
```

## Security Parameters

```go
// JWT
const (
    AccessTokenTTL  = 15 * time.Minute
    RefreshTokenTTL = 7 * 24 * time.Hour
    JWTAlgorithm    = "RS256"
    JWTIssuer       = "psina"
)

// Argon2id (OWASP recommendations)
var Argon2Params = argon2.Params{
    Memory:      64 * 1024,  // 64 MB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
}
```

## HTTP Endpoints (Connect RPC)

```http
POST /auth.v1.AuthService/Register     - Create account
POST /auth.v1.AuthService/Login        - Get tokens
POST /auth.v1.AuthService/Refresh      - Refresh access token
POST /auth.v1.AuthService/Logout       - Revoke refresh token
POST /auth.v1.AuthService/Verify       - Validate token (ForwardAuth)
GET  /.well-known/jwks.json            - Public keys (standard HTTP)
```

## Key Files

| File | Purpose |
|------|---------|
| `pkg/psina/service.go` | Orchestration layer |
| `pkg/psina/handler.go` | Connect RPC handler |
| `pkg/psina/types.go` | Domain types (User, Identity, TokenPair) |
| `pkg/psina/provider.go` | Provider interface |
| `pkg/psina/store.go` | Store interfaces (User, Token, Credential) |
| `pkg/token/issuer.go` | JWT issuance, validation, JWKS |
| `pkg/provider/local/local.go` | Local auth (Argon2id) |
| `pkg/store/postgres/postgres.go` | PostgreSQL store |
| `pkg/store/memory/memory.go` | In-memory store (testing) |
| `cmd/psina/main.go` | Server entrypoint |
| `cmd/psina/config.go` | Configuration (koanf) |

## Code Style

- Follow standard Go conventions
- Interfaces in separate files (`provider.go`, `store.go`)
- Table-driven tests
- Structured logging (slog)
- Errors with context: `fmt.Errorf("operation: %w", err)`

## Integration with greedy-eye

psina is designed to be imported:

```go
import "github.com/foxcool/psina/pkg/psina"

func main() {
    auth := psina.New(
        psina.WithPostgres(dbURL),
        psina.WithProvider(local.New()),
        psina.WithJWTKey(privateKey),
    )
    
    // Mount on your http.ServeMux
    // Works with gRPC, gRPC-Web, and HTTP/JSON on same port
    mux := http.NewServeMux()
    auth.Mount(mux)
    
    // Add your app routes
    mux.Handle("/api/", apiHandler)
    
    http.ListenAndServe(":8080", h2c.NewHandler(mux, &http2.Server{}))
}
```

## Gateway Integration

### Traefik (ForwardAuth)

Traefik calls psina on each request to validate:

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

### KrakenD (JWKS)

KrakenD fetches public keys once, validates JWT itself:

```json
{
  "endpoint": "/api/portfolio",
  "extra_config": {
    "auth/validator": {
      "alg": "RS256",
      "jwk_url": "http://psina:8080/.well-known/jwks.json",
      "cache": true,
      "propagate_claims": [
        ["sub", "X-User-Id"],
        ["email", "X-User-Email"]
      ]
    }
  }
}
```

## Testing Strategy

- Unit tests: providers, token logic
- Integration tests: store implementations
- E2E tests: full auth flows with test containers

## References

- Architecture: `docs/architecture.md`
- Roadmap: `docs/ROADMAP.md`
- Original research: Perplexity analysis in project context
