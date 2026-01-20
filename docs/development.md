# Development Guide

## Prerequisites

- Go 1.24+
- Docker & Docker Compose
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

### 4. Stop environment

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

Starts postgres, runs integration tests, stops postgres.

### E2E tests

```bash
make test-e2e
```

Runs E2E tests in isolated docker environment.

### All tests

```bash
make test
```

Runs unit + integration tests.

## Project Structure

```
psina/
├── api/                    # Proto definitions
│   └── auth/v1/
│       └── auth.proto
├── build/                  # Docker images
│   ├── Dockerfile          # Production
│   └── dev.Dockerfile      # Development
├── cmd/psina/              # Server entrypoint
├── deploy/                 # Deployment configs
│   ├── compose.yaml        # Docker Compose
│   ├── examples/           # Gateway integration examples
│   └── secrets.env         # Local secrets (gitignored)
├── docs/                   # Documentation
├── gen/                    # Generated code (proto + connect)
├── migrations/             # SQL migrations
└── pkg/                    # Public API
    ├── psina/              # Core (service, handler, interfaces)
    ├── provider/           # Auth providers (local)
    ├── store/              # Storage backends (postgres, memory)
    └── token/              # JWT management
```

## Development Workflow

1. Make changes to code
2. Air automatically rebuilds and restarts
3. Test your changes
4. Run tests: `make test`
5. Commit

## Code Generation

### Protobuf

```bash
make buf-gen
```

Generates:
- Go structs from proto
- Connect RPC client/server
- OpenAPI 3.1 spec

### Go generate

```bash
make go-gen
```

Runs `go generate ./...` for code generation directives.

## Docker Compose Profiles

- `default` / `dev` — development with live reload
- `test` — isolated testing environment

Example:
```bash
# Start dev environment
docker compose -f deploy/compose.yaml --profile dev up

# Run tests
docker compose -f deploy/compose.yaml --profile test run psina-test go test ./...
```

## Environment Variables

See `deploy/secrets.env.example` for all available variables.

Key variables:
- `PSINA_DB_URL` — PostgreSQL connection string (if empty, uses in-memory store)
- `PSINA_SERVER_PORT` — Server port (default: 8080)
- `PSINA_LOGGER_LEVEL` — Log level: debug, info, warn, error
- `PSINA_LOGGER_FORMAT` — Log format: json, text

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`):

- **On PR**: lint + unit tests + integration tests + docker build
- **On tag**: all checks + publish to ghcr.io

Push a tag to publish:
```bash
git tag v0.1.0
git push origin v0.1.0
```

Image will be published to: `ghcr.io/foxcool/psina:0.1.0`

## Tips

- Use `make help` to see all available commands
- Air config in `.air.toml`
- Coverage reports: `coverage-unit.out`, `coverage-integration.out`
- Build production image: `make build`

## Next Steps

See [ROADMAP.md](ROADMAP.md) for upcoming features and [SESSION_LOG.md](SESSION_LOG.md) for current progress.
