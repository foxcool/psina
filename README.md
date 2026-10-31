# 🐕 psina

[![CI](https://github.com/foxcool/psina/actions/workflows/ci.yml/badge.svg)](https://github.com/foxcool/psina/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/foxcool/psina)](https://goreportcard.com/report/github.com/foxcool/psina)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Lightweight, embeddable authentication service for Go microservices.

> **psina** (рус. "псина") — a guard dog that knows pack from strangers.

## Features

- **Dual deployment** — embed as Go library or run as standalone microservice
- **Connect RPC** — gRPC + HTTP/JSON on same port, curl-friendly
- **Stateless JWT** — RS256 with JWKS endpoint for gateway validation
- **Refresh token rotation** — automatic token family revocation on reuse detection
- **Personal access tokens** — opaque, revocable `psn_` tokens for machine clients
- **Gateway-ready** — Traefik ForwardAuth, KrakenD JWKS, any OIDC-compatible gateway

## Quick Start

### Run with Docker

```bash
# Development (in-memory store, ephemeral JWT key)
docker run -p 8080:8080 -e PSINA_DEV=true ghcr.io/foxcool/psina:latest

# Production (PostgreSQL + persistent JWT key)
docker run -p 8080:8080 \
  -e PSINA_DB_URL="postgres://user:pass@host:5432/psina?sslmode=disable" \
  -e PSINA_JWT_PRIVATEKEYPATH="/keys/jwt.pem" \
  -v /path/to/keys:/keys:ro \
  ghcr.io/foxcool/psina:latest
```

### Run locally

```bash
git clone https://github.com/foxcool/psina.git
cd psina
go build -o psina ./cmd/psina/...

# Development (in-memory store, ephemeral JWT key)
PSINA_DEV=true ./psina

# With PostgreSQL and a persistent key
PSINA_DB_URL="postgres://user:pass@localhost:5432/psina?sslmode=disable" \
PSINA_JWT_PRIVATEKEYPATH=jwt.pem ./psina
```

Without `PSINA_DEV=true`, an empty `PSINA_DB_URL` or a missing JWT key is a
startup error: either fallback loses every account and session on restart.

### Embed in your application

```go
import (
    "github.com/foxcool/psina/auth"
    "github.com/foxcool/psina/provider/local"
    "github.com/foxcool/psina/store/postgres"
    "github.com/foxcool/psina/token"
)

func main() {
    // Initialize components
    store, _ := postgres.NewWithDSN(ctx, dbURL)
    issuer, _ := token.NewWithKey(privateKey)
    provider := local.New(store, store)
    service := auth.NewService(provider, store, store, issuer,
        auth.WithPAT(store, auth.PATConfig{}), // optional: personal access tokens
    )
    handler := auth.NewHandler(service)
    
    // Mount on your HTTP mux
    path, rpcHandler := authv1connect.NewAuthServiceHandler(handler)
    mux.Handle(path, rpcHandler)
}
```

### Test the API

```bash
# Register
curl -X POST http://localhost:8080/auth.v1.AuthService/Register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass123"}'

# Login
curl -X POST http://localhost:8080/auth.v1.AuthService/Login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass123"}'

# Verify token (ForwardAuth style)
curl -X POST http://localhost:8080/auth.v1.AuthService/Verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{}'

# Refresh tokens
curl -X POST http://localhost:8080/auth.v1.AuthService/Refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# Get JWKS for gateway validation
curl http://localhost:8080/.well-known/jwks.json
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /auth.v1.AuthService/Register` | Create account, returns tokens |
| `POST /auth.v1.AuthService/Login` | Authenticate, returns tokens |
| `POST /auth.v1.AuthService/Refresh` | Refresh access token (with rotation) |
| `POST /auth.v1.AuthService/Logout` | Revoke refresh token family |
| `POST /auth.v1.AuthService/Verify` | Validate token — access JWT or PAT (ForwardAuth) |
| `POST /auth.v1.AuthService/CreatePersonalAccessToken` | Mint a PAT (session JWT required) |
| `POST /auth.v1.AuthService/ListPersonalAccessTokens` | List caller's PATs (session JWT required) |
| `POST /auth.v1.AuthService/RevokePersonalAccessToken` | Revoke a PAT by id (session JWT required) |
| `POST /auth.v1.AuthService/GetOAuthURL` | Start OAuth sign-in: provider URL, state, browser binding |
| `POST /auth.v1.AuthService/OAuthCallback` | Finish OAuth sign-in, returns tokens |
| `POST /auth.v1.AuthService/GetChallenge` | Start wallet sign-in: SIWE message to sign |
| `POST /auth.v1.AuthService/AuthenticateWallet` | Finish wallet sign-in with the signature, returns tokens |
| `GET /.well-known/jwks.json` | Public keys for JWT validation |
| `GET /verify` | HTTP ForwardAuth endpoint (Traefik) |
| `GET /healthz` | Liveness probe |
| `GET /readyz` | Readiness probe (checks DB) |
| `GET /health` | Detailed health with version |

## Configuration

Environment variables (prefix `PSINA_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PSINA_DEV` | `false` | Dev mode: allows the in-memory store and an ephemeral JWT key; otherwise either is a startup error |
| `PSINA_SERVER_PORT` | `8080` | Server port |
| `PSINA_SERVER_TRUSTEDPROXIES` | _(empty)_ | Proxies (CIDRs or IPs, comma-separated) whose `X-Forwarded-For` is believed; empty = the client IP is the connection peer. Set to the subnet of a network only the reverse proxy and psina join; a shared subnet lets every host on it forge the client IP |
| `PSINA_DB_URL` | _(empty)_ | PostgreSQL DSN (empty = in-memory, dev mode only) |
| `PSINA_DB_TABLEPREFIX` | _(empty)_ | Table name prefix for shared DB |
| `PSINA_JWT_PRIVATEKEYPATH` | _(empty)_ | Private key file path (no key = ephemeral, dev mode only) |
| `PSINA_JWT_PRIVATEKEY` | _(empty)_ | Private key PEM (alternative to path) |
| `PSINA_JWT_ALGORITHM` | `RS256` | JWT algorithm: `RS256` or `ES256` |
| `PSINA_TOKEN_REFRESHREUSELEEWAY` | `10s` | Grace for duplicate refreshes of a just-rotated token; `0s` = strict |
| `PSINA_COOKIE_ENABLED` | `false` | Enable HttpOnly refresh token cookies |
| `PSINA_COOKIE_DOMAIN` | _(required if enabled)_ | Cookie domain |
| `PSINA_COOKIE_SECURE` | `true` | HTTPS-only cookies |
| `PSINA_COOKIE_SAMESITE` | `strict` | Cookie SameSite: strict, lax, none |
| `PSINA_COOKIE_PATH` | `/` | Cookie path |
| `PSINA_PAT_ENABLED` | `true` | Enable personal access tokens |
| `PSINA_PAT_MAXPERUSER` | `50` | Max PATs per user; `-1` = unlimited |
| `PSINA_PAT_MAXTTL` | `0s` | Max PAT lifetime; `0s` = unlimited |
| `PSINA_PAT_TOUCHINTERVAL` | `1m` | Min interval between last-used updates; `-1ns` = every verify |
| `PSINA_OAUTH_GOOGLE_CLIENTID` | _(empty)_ | Google OAuth client id; set to enable Google sign-in |
| `PSINA_OAUTH_GOOGLE_CLIENTSECRET` | _(empty)_ | Google OAuth client secret |
| `PSINA_OAUTH_GOOGLE_REDIRECTURIS` | _(empty)_ | Allowed redirect URIs, comma-separated (exact match) |
| `PSINA_OAUTH_GITHUB_CLIENTID` | _(empty)_ | GitHub OAuth app client id; set to enable GitHub sign-in |
| `PSINA_OAUTH_GITHUB_CLIENTSECRET` | _(empty)_ | GitHub OAuth app client secret |
| `PSINA_OAUTH_GITHUB_REDIRECTURIS` | _(empty)_ | Allowed redirect URIs, comma-separated (exact match) |
| `PSINA_OAUTH_AUTOLINKEMAIL` | `true` | Link a first OAuth sign-in to an existing passwordless account with the same verified email; accounts with a password are never linked |
| `PSINA_WALLET_DOMAIN` | _(empty)_ | SIWE domain (e.g. `app.example.com`); set to enable wallet sign-in |
| `PSINA_WALLET_URI` | _(empty)_ | SIWE URI (e.g. `https://app.example.com`); required with the domain |
| `PSINA_WALLET_STATEMENT` | _(empty)_ | Text shown to the signer; optional, single line |
| `PSINA_WALLET_CHALLENGETTL` | `5m` | Time the user has to sign |
| `PSINA_WALLET_EVMCHAINS` | `ethereum=1` | EVM chains as `name=chainID`, comma-separated; the name is the `chain` request field |
| `PSINA_LOGGER_LEVEL` | `info` | Log level: debug, info, warn, error (anything else is a startup error) |
| `PSINA_LOGGER_FORMAT` | `json` | Log format: json, text (anything else is a startup error) |

Or use config file (`-c config.yaml`). Keys are case-insensitive, and two
spellings of one key are an error; a key with no value (YAML null) or an empty
section (`{}`) keeps its defaults — an empty string `""` does not:

```yaml
server:
  port: 8080
  trustedProxies: [172.30.250.0/29]  # network only the reverse proxy and psina join; empty = ignore X-Forwarded-For
db:
  url: "postgres://user:pass@localhost:5432/psina?sslmode=disable"
  tablePrefix: "auth_"  # optional, for shared databases
jwt:
  privateKeyPath: "/etc/psina/jwt.pem"
  algorithm: ES256  # or RS256
token:
  refreshReuseLeeway: 10s  # 0s = strict reuse detection
cookie:
  enabled: true
  domain: "example.com"
  secure: true
  sameSite: strict
pat:
  enabled: true
  maxPerUser: 50
  maxTTL: 0s        # 0s = unlimited
  touchInterval: 1m
oauth:
  autoLinkEmail: true
  google:
    clientID: "...apps.googleusercontent.com"
    clientSecret: "..."
    redirectURIs: ["https://app.example.com/oauth/callback"]
  github:
    clientID: "..."
    clientSecret: "..."
    redirectURIs: ["https://app.example.com/oauth/callback"]
wallet:
  domain: "app.example.com"
  uri: "https://app.example.com"
  statement: "Sign in to Example."
  challengeTTL: 5m
  evmChains: ["ethereum=1", "polygon=137"]
logger:
  level: info
  format: json
```

## Security

### Token Security

| Parameter | Value | Notes |
|-----------|-------|-------|
| Access Token TTL | 15 min | Short-lived, stateless validation |
| Refresh Token TTL | 7 days | Stored hashed (SHA256) |
| JWT Algorithm | RS256/ES256 | Configurable, ES256 = smaller tokens |
| Password Hash | Argon2id | OWASP recommended: 64MB memory, 3 iterations |
| Personal Access Tokens | opaque `psn_` | Stored hashed (SHA256), revocable, optional expiry |

### Personal Access Tokens

Long-lived opaque tokens for machine clients (CI, MCP servers, scripts). The
plaintext is shown exactly once at creation; only its SHA256 hash is stored.
`Verify` accepts PATs alongside access JWTs, so ForwardAuth works for both.

Management RPCs (create/list/revoke) require a session JWT — a PAT cannot
mint, list, or revoke PATs, so a leaked token cannot escalate. Scopes are
stored for forward compatibility but not enforced yet.

### Refresh Token Rotation

psina implements [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) refresh token rotation:

1. Each refresh returns a new token pair
2. Old refresh token is revoked atomically: of concurrent refreshes with one token, exactly one rotates it
3. If a revoked token is reused → entire token family is revoked
4. Security event logged with user context

Duplicate refreshes from one client (two tabs, a retried request) would trip
step 3 and log the user out. Within `PSINA_TOKEN_REFRESHREUSELEEWAY` (default
`10s`) of a rotation, the same token yields another pair in the same family
instead — but only while it is the family's latest rotation, the token is not
expired and the session has not ended (logout or reuse detection). The
price: a stolen token replayed inside that window is not detected (it is
logged at info level). Set `0s` for strict detection.

Logout ends the whole session: it revokes every token of the family, including
siblings minted within the leeway.

### Production Checklist

- [ ] Use persistent RSA key (`PSINA_JWT_PRIVATEKEYPATH`)
- [ ] Use PostgreSQL (`PSINA_DB_URL`)
- [ ] Enable TLS termination (reverse proxy)
- [ ] Set up rate limiting at the gateway (built-in limits are on the roadmap)
- [ ] Ship audit events (`audit=true` records on stdout) to a log collector — see [docs/audit.md](docs/audit.md)

## Gateway Integration

### Traefik ForwardAuth

```yaml
http:
  middlewares:
    psina-auth:
      forwardAuth:
        address: "http://psina:8080/verify"
        authRequestHeaders:
          - "Authorization"
          - "Cookie"  # if cookies enabled
        authResponseHeaders:
          - "X-User-Id"
          - "X-User-Email"
```

### KrakenD JWKS

```json
{
  "extra_config": {
    "auth/validator": {
      "alg": "RS256",
      "jwk_url": "http://psina:8080/.well-known/jwks.json",
      "issuer": "psina",
      "cache": true,
      "disable_jwk_security": true
    }
  }
}
```

`disable_jwk_security: true` is required when KrakenD fetches the JWKS over
plain HTTP (in-cluster service-to-service). Drop it when the JWKS is served over
HTTPS.

See [deploy/examples/](deploy/examples/) for complete configurations, and
[deploy/e2e/](deploy/e2e/) for a runnable Traefik + KrakenD test stand
(`make test-e2e`).

## Development

```bash
# Prerequisites: Go 1.24+, Docker, make

# Start dev environment (postgres + hot reload)
make up

# Run tests
make test-unit           # unit tests
make test-integration    # requires Docker (testcontainers)
make test-e2e            # gateway e2e stand (Traefik + KrakenD), requires Docker

# Generate protobuf
make gen

# Generate a migration after editing schema.hcl
make migrate-diff name=<what_changed>
```

## Architecture

Hexagonal architecture with pluggable providers and stores:

```text
auth/        # Service layer (orchestration + ports)
entity/      # Domain types
token/       # JWT issuer (pure crypto)
provider/    # Auth providers (local, oauth, wallet)
store/       # Storage backends (postgres, memory)
```

See [docs/architecture.md](docs/architecture.md) for details.

## Roadmap

| Version | Features | Status |
|---------|----------|--------|
| v0.1 | Local auth, JWT, PostgreSQL | ✅ Released |
| v0.2 | Personal access tokens, standalone (cookies, ES256, health probes, table prefix), gateway e2e, security CI, user roles | ✅ Released |
| v0.3 | Packages moved to the module root (breaking import paths), typed provider errors | ✅ Released |
| v0.4 | Atomic refresh rotation with a duplicate-refresh leeway | ✅ Released |
| v0.5 | OAuth sign-in: Google (PKCE, OIDC nonce, browser-bound state), GitHub | ✅ Released |
| v0.6 | Web3 wallet auth: SIWE (EIP-4361) for EVM chains | ✅ Released |
| v0.7 | Rate limiting, Prometheus metrics, audit logging | 📋 Planned |
| v0.8 | Passkeys (WebAuthn), TOTP 2FA | 📋 Planned |
| v1.0 | Stable API | 📋 Planned |

## License

MIT — see [LICENSE](LICENSE)
