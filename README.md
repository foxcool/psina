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
- **Gateway-ready** — Traefik ForwardAuth, KrakenD JWKS, any OIDC-compatible gateway

## Quick Start

### Run with Docker

```bash
# Development (in-memory store, ephemeral JWT key)
docker run -p 8080:8080 ghcr.io/foxcool/psina:latest

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

# Development (in-memory store)
./psina

# With PostgreSQL
PSINA_DB_URL="postgres://user:pass@localhost:5432/psina?sslmode=disable" ./psina
```

### Embed in your application

```go
import (
    "github.com/foxcool/psina/pkg/auth"
    "github.com/foxcool/psina/pkg/provider/local"
    "github.com/foxcool/psina/pkg/store/postgres"
    "github.com/foxcool/psina/pkg/token"
)

func main() {
    // Initialize components
    store, _ := postgres.NewWithDSN(ctx, dbURL)
    issuer, _ := token.NewWithKey(privateKey)
    provider := local.New(store, store)
    service := auth.NewService(provider, store, store, issuer)
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
| `POST /auth.v1.AuthService/Verify` | Validate token (ForwardAuth) |
| `GET /.well-known/jwks.json` | Public keys for JWT validation |
| `GET /verify` | HTTP ForwardAuth endpoint (Traefik) |
| `GET /healthz` | Liveness probe |
| `GET /readyz` | Readiness probe (checks DB) |
| `GET /health` | Detailed health with version |

## Configuration

Environment variables (prefix `PSINA_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PSINA_SERVER_PORT` | `8080` | Server port |
| `PSINA_DB_URL` | _(empty)_ | PostgreSQL DSN (empty = in-memory) |
| `PSINA_DB_TABLE_PREFIX` | _(empty)_ | Table name prefix for shared DB |
| `PSINA_JWT_PRIVATEKEYPATH` | _(empty)_ | Private key file path |
| `PSINA_JWT_PRIVATEKEY` | _(empty)_ | Private key PEM (alternative to path) |
| `PSINA_JWT_ALGORITHM` | `RS256` | JWT algorithm: `RS256` or `ES256` |
| `PSINA_COOKIE_ENABLED` | `false` | Enable HttpOnly refresh token cookies |
| `PSINA_COOKIE_DOMAIN` | _(required if enabled)_ | Cookie domain |
| `PSINA_COOKIE_SECURE` | `true` | HTTPS-only cookies |
| `PSINA_COOKIE_SAMESITE` | `strict` | Cookie SameSite: strict, lax, none |
| `PSINA_COOKIE_PATH` | `/` | Cookie path |
| `PSINA_LOGGER_LEVEL` | `info` | Log level: debug, info, warn, error |
| `PSINA_LOGGER_FORMAT` | `json` | Log format: json, text |

Or use config file (`-c config.yaml`):

```yaml
server:
  port: 8080
db:
  url: "postgres://user:pass@localhost:5432/psina?sslmode=disable"
  tablePrefix: "auth_"  # optional, for shared databases
jwt:
  privateKeyPath: "/etc/psina/jwt.pem"
  algorithm: ES256  # or RS256
cookie:
  enabled: true
  domain: "example.com"
  secure: true
  sameSite: strict
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

### Refresh Token Rotation

psina implements [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) refresh token rotation:

1. Each refresh returns a new token pair
2. Old refresh token is immediately revoked  
3. If revoked token is reused → entire token family is revoked
4. Security event logged with user context

### Production Checklist

- [ ] Use persistent RSA key (`PSINA_JWT_PRIVATEKEYPATH`)
- [ ] Use PostgreSQL (`PSINA_DB_URL`)
- [ ] Enable TLS termination (reverse proxy)
- [ ] Set up rate limiting (v0.2)
- [ ] Configure audit logging

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
      "cache": true
    }
  }
}
```

See [deploy/examples/](deploy/examples/) for complete configurations.

## Development

```bash
# Prerequisites: Go 1.24+, Docker, make

# Start dev environment (postgres + hot reload)
make up

# Run tests
make test-unit           # unit tests
make test-integration    # requires Docker (testcontainers)

# Generate protobuf
make gen

# Apply database schema
make schema-apply
```

## Architecture

Hexagonal architecture with pluggable providers and stores:

```
pkg/
├── auth/           # Service layer (orchestration + ports)
├── entity/         # Domain types
├── token/          # JWT issuer (pure crypto)
├── provider/       # Auth providers (local, passkey, wallet)
└── store/          # Storage backends (postgres, memory)
```

See [docs/architecture.md](docs/architecture.md) for details.

## Roadmap

| Version | Features | Status |
|---------|----------|--------|
| v0.1 | Local auth, JWT, PostgreSQL | ✅ Released |
| v0.1.1 | Standalone: cookies, ES256, health probes, table prefix | ✅ Ready |
| v0.2 | Rate limiting, Prometheus metrics, audit logging | 🚧 Next |
| v0.3 | Passkeys (WebAuthn) | 📋 Planned |
| v0.4 | Web3 wallet auth (SIWE) | 📋 Planned |
| v0.5 | TOTP 2FA | 📋 Planned |
| v1.0 | OAuth providers, stable API | 📋 Planned |

See [docs/ROADMAP.md](docs/ROADMAP.md) for detailed plans.

## License

MIT — see [LICENSE](LICENSE)
