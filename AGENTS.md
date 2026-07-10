# Agent Instructions

## Project Overview

**psina** — embeddable Go authentication service. Use as library or standalone microservice.

Name origin: "psina" (рус. "псина") = "doggy" — a guard dog that knows pack from strangers.

- Connect RPC on :8080 (gRPC + HTTP/JSON on same port), PostgreSQL 17+, JWT RS256/ES256
- Hexagonal architecture: domain logic in `pkg/auth/` + `pkg/entity/`, adapters are replaceable

## Current Status

**v0.2.0** — Local auth, personal access tokens, standalone deploy (cookies, ES256, health probes, table prefix), gateway e2e tests, security CI. Next: rate limiting, metrics, audit logging.

## Directory Map

```text
cmd/psina/           # binary entrypoint + config (koanf, slog, graceful shutdown)
pkg/
  api/auth/v1/       # generated Connect RPC code — DO NOT EDIT
  auth/              # service layer: service.go, handler.go, ports.go, validation.go
  entity/            # domain types (User, Identity, TokenPair, PersonalAccessToken, etc.)
  token/             # JWT issuer + PAT generation — pure crypto, no storage
  provider/local/    # username/password provider (Argon2id)
  provider/wallet/   # chain-agnostic WalletProvider iface + Dispatcher (per-chain impls pending)
  store/
    errors.go        # typed store errors: ErrUserNotFound, ErrTokenNotFound, etc.
    postgres/        # production store
    memory/          # dev/test in-memory store
  testutil/          # testcontainers helpers for integration tests
api/auth/v1/         # auth.proto — edit here, then make gen
schema.hcl           # Atlas declarative schema — edit here, then make schema-apply
deploy/              # Docker Compose files
docs/                # architecture, development, contributing
```

## Core Interfaces (`pkg/auth/ports.go`)

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
    Delete(ctx context.Context, id string) error
}

// TokenStore handles refresh tokens
type TokenStore interface {
    SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error
    GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error)
    RevokeTokens(ctx context.Context, hash string) error  // revokes token and its family
}

// PATStore handles personal access tokens (opaque psn_ tokens)
type PATStore interface {
    SavePAT(ctx context.Context, pat *entity.PersonalAccessToken) error
    GetPAT(ctx context.Context, hash string) (*entity.PersonalAccessToken, error)
    ListPATs(ctx context.Context, userID string) ([]*entity.PersonalAccessToken, error)
    DeletePAT(ctx context.Context, userID, id string) error  // by UUID, owner-scoped
    TouchPAT(ctx context.Context, hash string, t time.Time) error
}

// CredentialStore handles password hashes (separated from UserStore)
type CredentialStore interface {
    SavePasswordHash(ctx context.Context, userID, hash string) error
    GetPasswordHash(ctx context.Context, userID string) (string, error)
}

// TokenIssuer handles JWT operations (extracted for testability)
type TokenIssuer interface {
    GenerateTokens(userID, email string, roles []string) (*entity.TokenPair, string, error)
    ParseToken(accessToken string) (*entity.Claims, error)
    JWKS() *jose.JSONWebKeySet
}
```

PAT support is optional: pass `auth.WithPAT(store, auth.PATConfig{...})` to
`auth.NewService`; without the option the feature is disabled. PAT management
RPCs require a session JWT — PATs cannot manage PATs.

## Commands

```bash
make help              # list all targets

make test-unit         # unit tests, no Docker needed
make test-integration  # integration tests, requires Docker
make test-e2e          # gateway e2e stand (Traefik + KrakenD), requires Docker

make gen               # buf generate + go generate
make schema-apply      # Atlas declarative apply (via Docker Compose)
make schema-diff       # show diff without applying

make up                # start dev environment
make down              # stop containers
make logs              # follow psina-dev service logs
```

Direct equivalents (when `make` isn't available):

```bash
go test -v -race ./...                   # unit tests
go test -v -tags=integration ./pkg/...  # integration tests
buf generate --template buf.gen.yaml    # proto generation
go run ./cmd/psina/...                  # run dev server (in-memory store)
```

## Configuration

Priority: defaults → config file (`-c config.yaml`) → environment variables (`PSINA_` prefix).

```yaml
logger:
  level: info        # debug, info, warn, error
  format: json       # json, text
server:
  port: 8080
db:
  url: ""            # empty = in-memory store
  tablePrefix: ""    # for shared databases
jwt:
  privateKeyPath: "" # empty = ephemeral key (dev only!)
  algorithm: RS256   # RS256 or ES256
pat:
  enabled: true
  maxPerUser: 50     # -1 = unlimited
  maxTTL: 0s         # 0s = unlimited
  touchInterval: 1m  # last-used update throttle; -1ns = every verify
```

## HTTP Endpoints

```text
POST /auth.v1.AuthService/Register                   - Create account + return tokens
POST /auth.v1.AuthService/Login                      - Authenticate + return tokens
POST /auth.v1.AuthService/Refresh                    - Refresh access token (with rotation)
POST /auth.v1.AuthService/Logout                     - Revoke refresh token family
POST /auth.v1.AuthService/Verify                     - Validate JWT or PAT (ForwardAuth)
POST /auth.v1.AuthService/CreatePersonalAccessToken  - Mint PAT (session JWT only)
POST /auth.v1.AuthService/ListPersonalAccessTokens   - List PATs (session JWT only)
POST /auth.v1.AuthService/RevokePersonalAccessToken  - Revoke PAT by UUID (session JWT only)
GET  /.well-known/jwks.json                          - Public keys for gateway validation
GET  /health                                         - Health check with DB status
```

## Security Parameters

```go
// JWT
AccessTokenTTL     = 15 * time.Minute
RefreshTokenTTL    = 7 * 24 * time.Hour
ClockSkewTolerance = 30 * time.Second  // for nbf claim
Algorithm          = RS256

// Personal access tokens (opaque, SHA256-hashed at rest)
PATPrefix               = "psn_"
DefaultPATMaxPerUser    = 50
DefaultPATTouchInterval = time.Minute

// Argon2id (OWASP recommendations)
Memory      = 64 * 1024  // 64 MB
Iterations  = 3
Parallelism = 2
SaltLength  = 16
KeyLength   = 32

// Database
DefaultQueryTimeout = 5000  // milliseconds
```

## Architecture Rules

- **New auth method** → implement `Provider` interface from `pkg/auth/ports.go`, place in `pkg/provider/<name>/`
- **New wallet chain** → implement `wallet.WalletProvider` (`pkg/provider/wallet/provider.go`), register it with a `wallet.Dispatcher`, place in `pkg/provider/wallet/<chain>/`
- **New storage backend** → implement `UserStore`/`TokenStore`/`CredentialStore`/`PATStore`, place in `pkg/store/<name>/`. Optional stores for the wallet/OAuth track (interfaces declared, backends pending): `OAuthIdentityStore`, `WalletIdentityStore`, `ChallengeStore`.
- **Store errors** → return typed errors from `pkg/store/errors.go`; handler maps them to Connect codes via `errors.Is()`
- **Schema changes** → edit `schema.hcl`, then `make schema-apply` — never write raw SQL migrations
- **Proto changes** → edit `api/auth/v1/auth.proto`, then `make gen` — never edit `pkg/api/auth/v1/` directly
- **Roles** → opaque strings on `users.roles`, emitted in the JWT `roles` claim and
  `VerifyResponse`/`X-User-Roles`; psina never interprets them (authorization is the
  app's job). psina has no role-management API and does not derive roles from email —
  assign them directly in the DB (`UPDATE users SET roles = '{admin}' WHERE email = ...`).
  Bootstrap the first admin this way.

## Error Handling

```go
// Store returns typed errors
return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, id)

// Service/handler matches with errors.Is()
if errors.Is(err, store.ErrUserNotFound) {
    return nil, connect.NewError(connect.CodeNotFound, err)
}
```

Store errors: `ErrUserNotFound`, `ErrUserExists`, `ErrTokenNotFound`, `ErrCredentialNotFound`.
Service errors: `ErrInvalidCredentials`, `ErrTokenExpired`, `ErrPATDisabled`,
`ErrPATLimitReached`, `ErrPATNameRequired`, `ErrPATNameTooLong`, `ErrPATExpiryInvalid`, etc.

## Code Style

- Standard Go conventions
- Errors with context: `fmt.Errorf("operation: %w", err)`
- Table-driven tests
- Interfaces in `ports.go`, implementations in separate packages
- Typed errors for matching with `errors.Is()`

## Integration Example

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
    service := auth.NewService(store, store, issuer,
        []auth.Provider{provider}, // registry, keyed by Type()
        auth.WithPAT(store, auth.PATConfig{}), // optional
    )
    handler := auth.NewHandler(service)

    // Mount on your mux
    path, rpcHandler := authv1connect.NewAuthServiceHandler(handler)
    mux.Handle(path, rpcHandler)
}
```

## Non-Interactive Shell

`cp`, `mv`, `rm` may be aliased to interactive mode on some systems — use `-f` to avoid hanging:

```bash
cp -f src dst    mv -f src dst    rm -f file    rm -rf dir
```

Other: `scp`/`ssh` use `-o BatchMode=yes`; `apt-get` use `-y`; `brew` use `HOMEBREW_NO_AUTO_UPDATE=1`.

## Session End

```bash
git pull --rebase && git push
```

Work is not done until pushed.
