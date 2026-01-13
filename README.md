# 🐕 psina

Lightweight embeddable authentication service for Go microservices.

> **psina** (рус. "псина") — a guard dog that knows pack from strangers.

## Features

- **Embeddable or standalone** — import as library or deploy as microservice
- **Pluggable providers** — local auth, passkeys, Web3 wallets
- **Gateway-ready** — Traefik ForwardAuth, KrakenD JWKS, Envoy
- **Connect RPC** — gRPC + HTTP/JSON on same port, curl-friendly
- **Stateless JWT** — RS256 with JWKS endpoint

## Quick Start

### As embedded library

```go
import (
    "github.com/foxcool/psina/pkg/psina"
    "golang.org/x/net/http2"
    "golang.org/x/net/http2/h2c"
)

auth := psina.New(
    psina.WithPostgres(os.Getenv("DATABASE_URL")),
    psina.WithJWTKeyFile("jwt.key"),
)

mux := http.NewServeMux()
auth.Mount(mux)  // gRPC + HTTP/JSON on same port

// Single server for everything
http.ListenAndServe(":8080", h2c.NewHandler(mux, &http2.Server{}))
```

### As standalone service

```bash
docker run -d \
  -e DATABASE_URL=postgres://... \
  -e JWT_PRIVATE_KEY_FILE=/secrets/jwt.key \
  -p 8080:8080 \
  ghcr.io/foxcool/psina
```

## Authentication Providers

| Provider | Status     | Description                      |
| -------- | ---------- | -------------------------------- |
| Local    | ✅ v0.1    | Username/password with Argon2id  |
| Passkey  | 🚧 v0.2    | WebAuthn/FIDO2 passwordless      |
| Wallet   | 🚧 v0.3    | Ethereum signature auth          |
| OAuth    | 📋 planned | GitHub, Google, OIDC             |

## API Gateway Integration

### Traefik ForwardAuth

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
  "extra_config": {
    "auth/validator": {
      "alg": "RS256",
      "jwk_url": "http://psina:8080/.well-known/jwks.json",
      "cache": true
    }
  }
}
```

### JWKS Endpoint

```http
GET /.well-known/jwks.json
```

Use with any gateway that supports JWT validation (KrakenD, Kong, Envoy).

## Documentation

- [Architecture](docs/architecture.md) — design decisions, C4 diagrams
- [Roadmap](docs/ROADMAP.md) — version plans
- [Development Guide](docs/DEVELOPMENT.md) — setup, testing, workflows
- [Contributing](docs/CONTRIBUTING.md) — how to contribute

## Development

### Prerequisites

- Go 1.24+
- Docker & Docker Compose
- make
- buf (for protobuf generation)

### Quick Start

```bash
# 1. Copy environment template
cp deploy/secrets.env.example deploy/secrets.env

# 2. Generate code from proto
make gen

# 3. Start development environment (postgres + psina with live reload)
make up

# 4. Watch logs
make logs

# 5. Run tests
make test
```

### Available Commands

```bash
make help              # Show all available commands
make gen               # Generate code from proto
make test-unit         # Run unit tests
make test-integration  # Run integration tests with postgres
make up                # Start dev environment
make down              # Stop dev environment
make clean             # Stop and remove volumes
make logs              # Follow logs
```

See [Development Guide](docs/DEVELOPMENT.md) for detailed instructions.

### Project Status

**Current version**: v0.1-dev (MVP in progress)

Infrastructure ready:
- ✅ Docker Compose for local development
- ✅ Makefile with build automation
- ✅ CI/CD pipeline (GitHub Actions)
- ✅ Air live reload for development
- ⏳ Core implementation in progress

See [Roadmap](docs/ROADMAP.md) for details.

## License

MIT — see [LICENSE](LICENSE)
