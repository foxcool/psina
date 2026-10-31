# Agent Instructions

## Project Overview

**psina** — embeddable Go authentication service. Use as library or standalone microservice.

Name origin: "psina" (рус. "псина") = "doggy" — a guard dog that knows pack from strangers.

- Connect RPC on :8080 (gRPC + HTTP/JSON on same port), PostgreSQL 17+, JWT RS256/ES256
- Hexagonal architecture: domain logic in `auth/` + `entity/`, adapters are replaceable

## Current Status

**v0.7 next** — released: v0.2 local auth, personal access tokens, standalone deploy (cookies, ES256, health probes, table prefix), gateway e2e tests, security CI, user roles; v0.3 packages moved to the module root; v0.4 atomic refresh rotation with reuse leeway; v0.5 OAuth sign-in (Google OIDC and GitHub, PKCE S256, browser-bound state); v0.6 wallet sign-in (SIWE / EIP-4361 for EVM chains, email-less users). Next: rate limiting, metrics, audit logging.

## Directory Map

```text
cmd/psina/           # binary entrypoint + config (koanf, slog, graceful shutdown)
api/auth/v1/         # auth.proto — edit here, then make gen
                     # alongside it: generated Connect RPC code — DO NOT EDIT
auth/                # service layer: service.go, handler.go, ports.go, validation.go
entity/              # domain types (User, Identity, TokenPair, PersonalAccessToken, etc.)
token/               # JWT issuer + PAT generation — pure crypto, no storage
provider/local/      # username/password provider (Argon2id)
provider/oauth/      # oauth.Provider iface + UserInfo; google/ — OIDC, github/ — REST API
provider/wallet/     # chain-agnostic WalletProvider iface + Dispatcher; evm/ — SIWE (EIP-4361), one per chain
store/
  errors.go          # typed store errors: ErrUserNotFound, ErrTokenNotFound, etc.
  postgres/          # production store
  memory/            # dev/test in-memory store
  storetest/         # behavioural contract tests every backend runs
testutil/            # testcontainers helpers for integration tests
schema.hcl           # Atlas schema — edit here, then make migrate-diff
migrations/          # generated versioned migrations + atlas.sum — what instances run
deploy/              # Docker Compose files
docs/                # architecture, development, contributing, audit event catalog
```

## Core Interfaces (`auth/ports.go`)

```go
// Provider authenticates users via specific method
type Provider interface {
    Type() string  // entity.ProviderType*: "local", "google", "github", "wallet"
    Authenticate(ctx context.Context, req *entity.AuthRequest) (*entity.Identity, error)
    Register(ctx context.Context, req *entity.RegisterRequest) (*entity.Identity, error)
}

// UserStore persists users
type UserStore interface {
    Create(ctx context.Context, user *entity.User) error
    GetByID(ctx context.Context, id string) (*entity.User, error)
    GetByEmail(ctx context.Context, email string) (*entity.User, error)
    Delete(ctx context.Context, id string) error  // also drops everything the user owns
}
// Every user-owned write (token, PAT, password, identity) for a missing user → ErrUserNotFound

// TokenStore handles refresh tokens
type TokenStore interface {
    SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error // refuses (ErrTokenRevoked) a child of an ended or missing root
    GetRefreshToken(ctx context.Context, hash string) (*entity.RefreshToken, error)
    RevokeTokens(ctx context.Context, hash string) error  // pass the family root to end a session
    RotateRefreshToken(ctx context.Context, hash string, now time.Time) (*entity.RefreshToken, error) // atomic; one winner
    GetRefreshFamily(ctx context.Context, root string) (*entity.RefreshFamily, error) // reuse-leeway decisions
}

// PATStore handles personal access tokens (opaque psn_ tokens)
type PATStore interface {
    SavePAT(ctx context.Context, pat *entity.PersonalAccessToken) error  // ErrPATExists on a duplicate hash
    GetPAT(ctx context.Context, hash string) (*entity.PersonalAccessToken, error)
    ListPATs(ctx context.Context, userID string) ([]*entity.PersonalAccessToken, error)  // newest first
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

make lint              # golangci-lint in Docker (matches CI; do not install locally)
make sec               # gosec in Docker (matches CI); run with lint before pushing
make test-unit         # unit tests, no Docker needed
make test-integration  # integration tests, requires Docker
make test-e2e          # gateway e2e stand (Traefik + KrakenD), requires Docker

make gen               # buf generate + go generate
make migrate-diff name=<what_changed>  # generate a migration from schema.hcl
make migrate-apply     # apply pending migrations to the dev database
make migrate-status    # applied / pending migrations
make migrate-drift     # read-only: dev database vs schema.hcl
make migrate-baseline version=<v>  # once per pre-existing database, see Database

make up                # start dev environment
make down              # stop containers
make logs              # follow psina-dev service logs
```

Direct equivalents (when `make` isn't available):

```bash
go test -v -race ./...                   # unit tests
go test -v -tags=integration ./...      # integration tests
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
  trustedProxies: [] # CIDRs/IPs whose X-Forwarded-For is believed; empty = peer address
db:
  url: ""            # empty = in-memory store
  tablePrefix: ""    # for shared databases
jwt:
  privateKeyPath: "" # empty = ephemeral key (dev only!)
  algorithm: RS256   # RS256 or ES256
token:
  refreshReuseLeeway: 10s # duplicate-refresh grace; 0s = strict reuse detection
pat:
  enabled: true
  maxPerUser: 50     # -1 = unlimited
  maxTTL: 0s         # 0s = unlimited
  touchInterval: 1m  # last-used update throttle; -1ns = every verify
oauth:
  autoLinkEmail: true # link to a passwordless account with the same verified email
  google:            # enabled when clientID is set; all three required together
    clientID: ""
    clientSecret: ""
    redirectURIs: [] # exact-match whitelist; comma-separated in env
  github:            # same shape and rules as google
    clientID: ""
    clientSecret: ""
    redirectURIs: []
wallet:
  domain: ""         # SIWE domain; wallet sign-in is enabled when set
  uri: ""            # SIWE URI; required with domain
  statement: ""      # optional; domain, uri and statement must be single-line
  challengeTTL: 5m
  evmChains: [ethereum=1] # name=chainID; comma-separated in env
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
POST /auth.v1.AuthService/GetOAuthURL                - Start OAuth sign-in (state + browser binding)
POST /auth.v1.AuthService/OAuthCallback              - Finish OAuth sign-in + return tokens
POST /auth.v1.AuthService/GetChallenge               - Start wallet sign-in (SIWE message to sign)
POST /auth.v1.AuthService/AuthenticateWallet         - Finish wallet sign-in + return tokens
GET  /.well-known/jwks.json                          - Public keys for gateway validation
GET  /verify                                         - HTTP ForwardAuth endpoint
GET  /healthz, /readyz                               - Liveness / readiness (checks DB)
GET  /health                                         - Health check with DB status
```

## Security Parameters

```go
// JWT
AccessTokenTTL     = 15 * time.Minute
RefreshTokenTTL    = 7 * 24 * time.Hour
ClockSkewTolerance = 30 * time.Second  // for nbf claim
Algorithm          = RS256

// Refresh rotation (atomic; a duplicate within the leeway gets a sibling pair)
DefaultRefreshReuseLeeway = 10 * time.Second  // auth.WithRefreshReuseLeeway; 0 = strict

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

- **New auth method** → implement `Provider` interface from `auth/ports.go`, place in `provider/<name>/`
- **New wallet chain** → implement `wallet.WalletProvider` (`provider/wallet/provider.go`), register it with a `wallet.Dispatcher`, place in `provider/wallet/<chain>/`
- **New storage backend** → implement `UserStore`/`TokenStore`/`CredentialStore`/`PATStore`, place in `store/<name>/`, run the `store/storetest` contracts against it. Optional stores: `OAuthIdentityStore` and `ChallengeStore` (OAuth; both backends implement them), `WalletIdentityStore` (wallet sign-in via `auth.WithWallet`; both backends implement it).
- **Store errors** → return typed errors from `store/errors.go`; handler maps them to Connect codes via `errors.Is()`
- **Schema changes** → edit `schema.hcl`, then `make migrate-diff name=<what_changed>` and commit both — see Database
- **Proto changes** → edit `api/auth/v1/auth.proto`, then `make gen` — never edit the generated files in `api/auth/v1/` directly
- **Audit events** → emitted by `Handler` (it has the client IP), one slog record each with
  `audit=true`; catalog and field contract in `docs/audit.md` — update it with any new event,
  field or reason. Never log credentials, tokens, hashes or a typed identifier.
- **Roles** → opaque strings on `users.roles`, emitted in the JWT `roles` claim and
  `VerifyResponse`/`X-User-Roles`; psina never interprets them (authorization is the
  app's job). psina has no role-management API and does not derive roles from email —
  assign them directly in the DB (`UPDATE users SET roles = '{admin}' WHERE email = ...`).
  Bootstrap the first admin this way.

## Database

- `schema.hcl` is the authoring surface; `migrations/` is what instances run
  (`atlas migrate apply --revisions-schema atlas`, in the compose `migrate` service
  and the release image). Revisions live in the separate `atlas` schema so `public`
  stays comparable with `schema.hcl`.
- Change the schema: edit `schema.hcl`, `make migrate-diff name=<what_changed>`,
  commit the new file and `atlas.sum` together. `TestMigrationsMatchSchema`
  (integration) fails when the two disagree.
- Never hand-write or edit a migration (atlas.sum rejects it), and never apply
  `schema.hcl` to a database (`atlas schema apply`): a declarative apply diffs both
  ways, so an older image would drop columns a newer one added, with their data.
- A database created before `migrations/` existed is baselined once — procedure in
  `docs/development.md`, Database Schema.

## Error Handling

```go
// Store returns typed errors
return nil, fmt.Errorf("%w: %s", store.ErrUserNotFound, id)

// Service/handler matches with errors.Is()
if errors.Is(err, store.ErrUserNotFound) {
    return nil, connect.NewError(connect.CodeNotFound, err)
}
```

Store errors: `ErrUserNotFound`, `ErrUserExists`, `ErrTokenNotFound`, `ErrTokenRevoked`,
`ErrTokenExpired`, `ErrPATExists`, `ErrCredentialNotFound`.
Service errors: `ErrInvalidCredentials`, `ErrTokenExpired`, `ErrPATDisabled`, `ErrWalletChallengeInvalid`,
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
    "github.com/foxcool/psina/auth"
    "github.com/foxcool/psina/provider/local"
    "github.com/foxcool/psina/store/postgres"
    "github.com/foxcool/psina/token"
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
