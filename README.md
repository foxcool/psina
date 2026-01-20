# 🐕 psina

Lightweight authentication service for Go microservices.

> **psina** (рус. "псина") — a guard dog that knows pack from strangers.

## Features

- **Standalone microservice** — deploy with Docker, integrate via API
- **Connect RPC** — gRPC + HTTP/JSON on same port, curl-friendly
- **Stateless JWT** — RS256 with JWKS endpoint
- **Gateway-ready** — Traefik ForwardAuth, KrakenD JWKS

## Quick Start

### Run with Docker

```bash
# Development (in-memory store)
docker run -p 8080:8080 ghcr.io/foxcool/psina:latest

# Production (PostgreSQL)
docker run -p 8080:8080 \
  -e PSINA_DB_URL="postgres://user:pass@host:5432/psina?sslmode=disable" \
  ghcr.io/foxcool/psina:latest
```

### Run locally

```bash
# Clone and build
git clone https://github.com/foxcool/psina.git
cd psina
go build -o psina ./cmd/psina/...

# Run (in-memory for dev)
./psina

# Or with PostgreSQL
PSINA_DB_URL="postgres://..." ./psina
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

# Verify token
curl -X POST http://localhost:8080/auth.v1.AuthService/Verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{}'

# Get JWKS
curl http://localhost:8080/.well-known/jwks.json
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /auth.v1.AuthService/Register` | Create account, returns tokens |
| `POST /auth.v1.AuthService/Login` | Authenticate, returns tokens |
| `POST /auth.v1.AuthService/Refresh` | Refresh access token |
| `POST /auth.v1.AuthService/Logout` | Revoke refresh token |
| `POST /auth.v1.AuthService/Verify` | Validate token (ForwardAuth) |
| `GET /.well-known/jwks.json` | Public keys for JWT validation |
| `GET /health` | Health check |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PSINA_SERVER_PORT` | `8080` | Server port |
| `PSINA_DB_URL` | _(empty)_ | PostgreSQL DSN (if empty, uses in-memory) |
| `PSINA_LOGGER_LEVEL` | `info` | Log level: debug, info, warn, error |
| `PSINA_LOGGER_FORMAT` | `json` | Log format: json, text |

Or use config file:

```bash
./psina -c config.yaml
```

## Gateway Integration

### Traefik ForwardAuth

```yaml
http:
  middlewares:
    psina-auth:
      forwardAuth:
        address: "http://psina:8080/auth.v1.AuthService/Verify"
        authRequestHeaders:
          - "Authorization"
        authResponseHeaders:
          - "X-User-Id"
          - "X-User-Email"
```

See [deploy/examples/](deploy/examples/) for complete examples.

### KrakenD (JWKS)

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

## Development

```bash
# Prerequisites: Go 1.22+, Docker, make

# Start dev environment (postgres + live reload)
make up

# Run tests
make test-unit           # unit tests
make test-integration    # with postgres

# Generate proto
make gen
```

## Authentication Providers

| Provider | Status | Description |
|----------|--------|-------------|
| Local | ✅ v0.1 | Email/password with Argon2id |
| Passkey | 🚧 v0.2 | WebAuthn/FIDO2 passwordless |
| Wallet | 🚧 v0.3 | Ethereum signature auth |

## License

MIT — see [LICENSE](LICENSE)
