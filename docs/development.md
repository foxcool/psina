# Development Guide

## Prerequisites

- Go 1.25+
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

- PostgreSQL database
- Atlas migrations (`migrations/` applied automatically)
- psina-dev with Air live reload

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

Requires:

- Docker (for testcontainers)

Automatically:

- Spins up PostgreSQL via testcontainers
- Applies schema.hcl (store tests) and replays migrations/ (`TestMigrationsMatchSchema`)
- Runs integration tests
- Cleans up

### All tests

```bash
make test
```

Runs unit + integration tests.

### E2E gateway tests

```bash
make test-e2e
```

Requires:

- Docker (gateway stand via Docker Compose)

Verifies psina behind both supported gateway integrations end to end:

- **Traefik ForwardAuth** — gateway calls `/verify`; psina injects
  `X-User-Id`/`X-User-Email`/`X-User-Roles` into the backend request.
- **KrakenD JWKS** — gateway validates the RS256 token against
  `/.well-known/jwks.json` (psina not called per request).

Automatically:

- Builds psina and brings up the stand (`deploy/e2e/compose.yaml`,
  profiles `traefik` + `krakend`, fronting a `traefik/whoami` backend)
- Runs the Go driver (`test/e2e`, build tag `e2e`): no token → 401,
  bad token → 401, expired (valid-signature) token → 401, valid token →
  200 with identity/claims propagated to the backend, plus cookie-based
  auth through Traefik ForwardAuth
- Tears the stand down (even on failure)

The stand mounts a fixed RSA signing key (generated on first run,
gitignored) so the driver can forge an expired-but-valid token and so
KrakenD's JWKS cache stays stable.

## Project Structure

```text
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
│   └── development.md      # This file
├── auth/                   # Service layer
│   ├── service.go          # Business logic orchestration
│   ├── handler.go          # Connect RPC handler
│   ├── ports.go            # Interface definitions
│   └── validation.go       # Input validation
├── entity/                 # Domain types (User, Token, etc.)
├── provider/               # Auth providers
│   └── local/              # Email/password (Argon2id)
├── store/                  # Storage backends
│   ├── errors.go           # Typed storage errors
│   ├── postgres/           # Production store
│   └── memory/             # Testing/dev store
├── testutil/               # Test helpers (testcontainers)
├── token/                  # JWT issuer (RS256, JWKS)
├── migrations/             # Generated versioned migrations (Atlas)
└── schema.hcl              # Database schema source (Atlas)
```

## Architecture

Hexagonal (Ports & Adapters):

- **Ports** (`auth/ports.go`): interfaces for Provider, UserStore, TokenStore, CredentialStore, PATStore, TokenIssuer
- **Adapters**: `provider/*`, `store/*`, `token/`
- **Core**: `auth/service.go` orchestrates business logic

Key principle: domain logic in `auth/` and `entity/`, adapters are replaceable.

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

- Go structs from proto (`api/auth/v1/*.pb.go`)
- Connect RPC handlers (`api/auth/v1/authv1connect/`)

### Go generate

```bash
make go-gen
```

Runs `go generate ./...` for any code generation directives.

## Database Schema

[Atlas](https://atlasgo.io/), versioned. `schema.hcl` is the authoring
surface; `migrations/` (SQL generated from it, plus `atlas.sum`) is what every
instance runs. Never hand-write a migration and never apply `schema.hcl` to a
database: a declarative apply diffs both ways, so deploying an older image
would drop columns a newer one added, with their data.

Change the schema:

```bash
# 1. edit schema.hcl
make migrate-diff name=add_users_locale   # writes migrations/<ts>_add_users_locale.sql
make migrate-apply                        # apply to the dev database
# 2. commit schema.hcl, the new file and atlas.sum together
```

`TestMigrationsMatchSchema` (`make test-integration`) replays `migrations/`
into an empty database and fails unless it matches `schema.hcl`.

Other targets (all run atlas in the compose `migrate` service):

```bash
make migrate-status   # applied / pending
make migrate-drift    # read-only: database vs schema.hcl
```

Revisions are recorded in the `atlas` schema, apart from `public`, so
`public` stays comparable with `schema.hcl`.

### One-time baseline of an existing instance

A database created by the old `atlas schema apply` already has the tables but
no revision history, so `migrate apply` refuses it ("connected database is not
clean"). Baseline it once, with the first release that ships `migrations/`
(its `schema.hcl` equals the baseline migration). The database must be at the
v0.6.0 schema: an older one shows drift in step 1, so deploy v0.6.0 with its old
`schema apply` step first. Never pass `--allow-dirty` to skip this.

1. Check that the database matches the baseline. The output must be
   `Schemas are synced, no changes to be made.`; anything else is drift to
   resolve first.

   ```bash
   make migrate-drift
   # elsewhere, from the release image; dev-url is any empty scratch database:
   atlas schema diff \
     --from "postgres://USER:PASS@HOST:5432/DB?sslmode=disable&search_path=public" \
     --to file:///schema.hcl \
     --dev-url "postgres://USER:PASS@HOST:5432/atlas_dev?sslmode=disable&search_path=public"
   ```

2. Record the baseline as applied without running it:

   ```bash
   make migrate-baseline version=20261031173145
   # elsewhere:
   atlas migrate apply --url "postgres://USER:PASS@HOST:5432/DB?sslmode=disable" \
     --dir file:///migrations --revisions-schema atlas --baseline 20261031173145
   ```

3. From now on deploy only with `migrate apply` (below). Do not run the old
   `schema apply` against a baselined database: it drops the `atlas` schema,
   and the next `migrate apply` refuses the database again (repeat 1–2).

The migrate step every deploy runs:

```bash
atlas migrate apply \
  --url "postgres://USER:PASS@HOST:5432/DB?sslmode=disable" \
  --dir file:///migrations \
  --revisions-schema atlas
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
| `PSINA_SERVER_TRUSTEDPROXIES` | _(empty)_ | Proxies (CIDRs or IPs, comma-separated) whose `X-Forwarded-For` is believed; empty = the client IP is the connection peer. Set to the subnet of a network only the reverse proxy and psina join; a shared subnet lets every host on it forge the client IP |
| `PSINA_JWT_PRIVATEKEYPATH` | _(empty)_ | RSA key path (empty = ephemeral) |
| `PSINA_LOGGER_LEVEL` | `info` | debug, info, warn, error |
| `PSINA_LOGGER_FORMAT` | `json` | json, text |

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`):

1. **golangci-lint** — static analysis (config: `.golangci.yml`)
2. **unit-tests** — fast feedback
3. **integration-tests** — with real PostgreSQL
4. **docker-build** — verify image builds (PR only)
5. **docker-publish** — push to ghcr.io (tags only)

### Lint tooling versions

`GOLANGCI_LINT_VERSION` and `GOSEC_VERSION` in the `Makefile` are the only
place to bump: `make lint` / `make sec` use them, the CI lint job reads the
golangci-lint pin from there, and the CI gosec job runs `make sec`.

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

# Create a personal access token (requires session JWT, not a PAT)
curl -X POST http://localhost:8080/auth.v1.AuthService/CreatePersonalAccessToken \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{"name":"ci"}'

# Verify accepts the PAT like an access token
curl -X POST http://localhost:8080/auth.v1.AuthService/Verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer psn_..." \
  -d '{}'
```

## Tips

- Use `make help` to see all available commands
- Air config in `.air.toml`
- Coverage reports: `coverage-unit.out`, `coverage-integration.out`
- Build production image: `make build`
- Database queries have 5s timeout by default (configurable via DSN)
