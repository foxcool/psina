# Development Guide

## Prerequisites

- Go 1.24+
- Docker & Docker Compose
- Atlas CLI (for schema management)
- buf (for protobuf generation)
- make

## Quick Start

### 1. Setup environment

```bash
# Copy secrets template
cp deploy/secrets.env.example deploy/secrets.env

# Edit secrets.env if needed (default values work for local dev)
```

### 2. Generate code

```bash
make gen
```

This will:
- Generate Go code from proto files (Connect RPC)
- Run `go generate ./...`

### 3. Run development environment

```bash
make up
```

This starts:
- PostgreSQL database (port 5432)
- psina-dev with Air live reload (port 8080)

Watch logs:
```bash
make logs
```

### 4. Apply database schema

```bash
make schema-apply
```

### 5. Stop environment

```bash
make down        # Stop containers
make clean       # Stop + remove volumes
```

## Testing

### Unit tests

```bash
make test-unit
```

Runs all unit tests with race detector and coverage.

### Integration tests

```bash
make test-integration
```

Requires:
- Atlas CLI (`curl -sSf https://atlasgo.sh | sh`)
- Docker (for testcontainers)

Automatically:
- Spins up PostgreSQL via testcontainers
- Applies schema
- Runs integration tests
- Cleans up

### All tests

```bash
make test
```

Runs unit + integration tests.

## Project Structure

```
psina/
├── api/auth/v1/            # Proto definitions
│   └── auth.proto
├── build/                  # Docker images
│   ├── Dockerfile          # Production (multi-stage)
│   └── dev.Dockerfile      # Development (Air)
├── cmd/psina/              # Server entrypoint
│   ├── main.go             # Server setup, graceful shutdown
│   └── config.go           # Configuration loading (koanf)
├── deploy/                 # Deployment configs
│   ├── compose.yaml        # Docker Compose
│   ├── examples/           # Gateway integration examples
│   └── secrets.env         # Local secrets (gitignored)
├── docs/                   # Documentation
│   ├── architecture.md     # System design (C4, hexagonal)
│   ├── development.md      # This file
│   └── ROADMAP.md          # Feature roadmap
├── pkg/                    # Library code
│   ├── api/auth/v1/        # Generated Connect RPC code
│   ├── auth/               # Service layer
│   │   ├── service.go      # Business logic orchestration
│   │   ├── handler.go      # Connect RPC handler
│   │   ├── ports.go        # Interface definitions
│   │   └── validation.go   # Input validation
│   ├── entity/             # Domain types (User, Token, etc.)
│   ├── provider/           # Auth providers
│   │   └── local/          # Email/password (Argon2id)
│   ├── store/              # Storage backends
│   │   ├── errors.go       # Typed storage errors
│   │   ├── postgres/       # Production store
│   │   └── memory/         # Testing/dev store
│   ├── testutil/           # Test helpers (testcontainers)
│   └── token/              # JWT issuer (RS256, JWKS)
└── schema.hcl              # Database schema (Atlas)
```

## Architecture

Hexagonal (Ports & Adapters):

- **Ports** (`pkg/auth/ports.go`): interfaces for Provider, UserStore, TokenStore, CredentialStore, TokenIssuer
- **Adapters**: `pkg/provider/*`, `pkg/store/*`, `pkg/token/`
- **Core**: `pkg/auth/service.go` orchestrates business logic

Key principle: domain logic in `pkg/auth/` and `pkg/entity/`, adapters are replaceable.

## Development Workflow

1. Make changes to code
2. Air automatically rebuilds and restarts (if using `make up`)
3. Test your changes manually or with tests
4. Run full test suite: `make test`
5. Commit

## Code Generation

### Protobuf

```bash
make buf-gen
```

Generates:
- Go structs from proto (`pkg/api/auth/v1/*.pb.go`)
- Connect RPC handlers (`pkg/api/auth/v1/authv1connect/`)

### Go generate

```bash
make go-gen
```

Runs `go generate ./...` for any code generation directives.

## Database Schema

Using [Atlas](https://atlasgo.io/) for declarative schema management.

Schema defined in `schema.hcl`:

```hcl
table "users" {
  column "id" { type = varchar(255) }
  column "email" { type = varchar(255) }
  // ...
}
```

Commands:
```bash
make schema-apply   # Apply schema to database
make schema-diff    # Show pending changes without applying
```

## Docker Compose Profiles

- `default` — development with live reload

Example:
```bash
# Start dev environment
make up

# Or manually
docker compose -f deploy/compose.yaml --profile default up -d
```

## Environment Variables

See `deploy/secrets.env.example` for all available variables.

Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PSINA_DB_URL` | _(empty)_ | PostgreSQL DSN (empty = in-memory) |
| `PSINA_SERVER_PORT` | `8080` | Server port |
| `PSINA_JWT_PRIVATEKEYPATH` | _(empty)_ | RSA key path (empty = ephemeral) |
| `PSINA_LOGGER_LEVEL` | `info` | debug, info, warn, error |
| `PSINA_LOGGER_FORMAT` | `json` | json, text |

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`):

1. **golangci-lint** — static analysis
2. **unit-tests** — fast feedback
3. **integration-tests** — with real PostgreSQL
4. **docker-build** — verify image builds (PR only)
5. **docker-publish** — push to ghcr.io (tags only)

### Publishing a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

Image published to: `ghcr.io/foxcool/psina:0.1.0`

## Debugging

### View logs
```bash
make logs
```

### Check health
```bash
curl http://localhost:8080/health
```

### Test token flow
```bash
# Register
curl -X POST http://localhost:8080/auth.v1.AuthService/Register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8080/auth.v1.AuthService/Login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

## Tips

- Use `make help` to see all available commands
- Air config in `.air.toml`
- Coverage reports: `coverage-unit.out`, `coverage-integration.out`
- Build production image: `make build`
- Database queries have 5s timeout by default (configurable via DSN)

## Next Steps

See [ROADMAP.md](ROADMAP.md) for upcoming features.
