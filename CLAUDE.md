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
│   ├── psina/          # Main package: Service, Config, Options
│   ├── provider/       # Auth provider interfaces + implementations
│   │   ├── local/      # Username/password
│   │   ├── passkey/    # WebAuthn/Passkeys
│   │   └── wallet/     # Web3 wallet signatures (ETH, etc.)
│   ├── token/          # JWT issuance, validation, JWKS
│   ├── store/          # User/session storage interfaces
│   │   ├── postgres/
│   │   └── memory/     # For testing/embedded use
│   └── gateway/        # API gateway integrations
│       └── traefik/    # ForwardAuth middleware
├── internal/           # Private implementation details
├── api/                # Proto definitions (gRPC + gRPC-Gateway)
├── migrations/         # SQL migrations (golang-migrate format)
└── docs/               # Architecture documentation
```

## Key Design Decisions

1. **pkg/ over internal/**: Public API for embedding in other Go projects
2. **Provider interface**: All auth methods implement same contract
3. **Store interface**: Pluggable storage backends
4. **Stateless JWT**: RS256 with JWKS endpoint for gateway validation

## Tech Stack

- Go 1.22+
- Connect RPC (gRPC + HTTP/JSON on same port)
- PostgreSQL (primary) / SQLite (dev/embedded)
- buf for protobuf management (local plugins only)
- golang-migrate for migrations

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
github.com/golang-migrate/migrate/v4 // Migrations

// HTTP
golang.org/x/net/http2/h2c          // HTTP/2 cleartext (for gRPC)

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
  
  # OpenAPI 3.1 spec
  - local: protoc-gen-connect-openapi
    out: gen/openapi
```

## Current Phase: MVP (v0.1)

Focus:

- Local auth (username/password)
- JWT issuance (RS256)
- JWKS endpoint
- Traefik ForwardAuth
- PostgreSQL store
- Memory store (testing)

NOT in scope for v0.1:

- OAuth providers
- Passkeys/WebAuthn
- Web3 wallet auth
- TOTP 2FA
- Admin UI

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

## MVP Implementation Order

1. **Setup**: buf.yaml, buf.gen.yaml, go.mod dependencies
2. **Proto**: api/auth/v1/auth.proto → buf generate
3. **Domain**: pkg/psina/types.go (User, Identity, TokenPair)
4. **Interfaces**: pkg/psina/provider.go, store.go, token.go
5. **Token Issuer**: pkg/token/issuer.go (RS256, JWKS)
6. **Local Provider**: pkg/provider/local/local.go (Argon2id)
7. **Memory Store**: pkg/store/memory/memory.go
8. **Service**: pkg/psina/service.go (orchestrates everything)
9. **Connect Handler**: pkg/psina/handler.go
10. **JWKS Handler**: pkg/psina/jwks.go (/.well-known/jwks.json)
11. **Standalone**: cmd/psina/main.go
12. **PostgreSQL Store**: pkg/store/postgres/
13. **Migrations**: migrations/

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
