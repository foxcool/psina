# Agent Instructions

## Project Overview

**psina** — embeddable Go authentication service. Use as library or standalone microservice.

- Connect RPC on :8080 (gRPC + HTTP/JSON on same port), PostgreSQL 17+, JWT RS256
- Hexagonal architecture: domain logic in `pkg/auth/` + `pkg/entity/`, adapters are replaceable

## Directory Map

```
cmd/psina/           # binary entrypoint + config (koanf, slog, graceful shutdown)
pkg/
  api/auth/v1/       # generated Connect RPC code — DO NOT EDIT
  auth/              # service layer: service.go, handler.go, ports.go, validation.go
  entity/            # domain types (User, Identity, TokenPair, etc.)
  token/             # JWT issuer — pure crypto, no storage
  provider/local/    # username/password provider (Argon2id)
  store/
    errors.go        # typed store errors: ErrUserNotFound, ErrUserExists, etc.
    postgres/        # production store
    memory/          # dev/test in-memory store
  testutil/          # testcontainers helpers for integration tests
api/auth/v1/         # auth.proto — edit here, then make gen
schema.hcl           # Atlas declarative schema — edit here, then make schema-apply
deploy/              # Docker Compose files
```

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

## Architecture Rules

- **New auth method** → implement `Provider` interface from `pkg/auth/ports.go`, place in `pkg/provider/<name>/`
- **New storage backend** → implement `UserStore`/`TokenStore`/`CredentialStore`, place in `pkg/store/<name>/`
- **Store errors** → return typed errors from `pkg/store/errors.go`; handler maps them to Connect codes via `errors.Is()`
- **Schema changes** → edit `schema.hcl`, then `make schema-apply` — never write raw SQL migrations
- **Proto changes** → edit `api/auth/v1/auth.proto`, then `make gen` — never edit `pkg/api/auth/v1/` directly

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
