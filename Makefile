# Define makefile variables for frequently used commands
BUF=$(shell which buf)
# Use docker compose instead of docker-compose
COMPOSE=docker compose -p psina
# Path to the compose file
COMPOSE_FILE=deploy/compose.yaml
# Path to the e2e gateway stand compose file
E2E_COMPOSE=deploy/e2e/compose.yaml
# Pinned lint tooling: the single place to bump. CI reads these two lines
# (the lint job greps GOLANGCI_LINT_VERSION) and runs `make sec`.
GOLANGCI_LINT_VERSION=v2.15.0
GOSEC_VERSION=2.30.0

.PHONY: gen buf-gen go-gen lint sec test test-unit test-integration test-e2e up down clean logs help migrate-diff migrate-apply migrate-status migrate-baseline migrate-drift

# Default target
help:
	@echo "Available targets:"
	@echo "  gen               - Generate all code (buf + go generate)"
	@echo "  buf-gen           - Generate protobuf files with buf"
	@echo "  go-gen            - Generate go code (go generate)"
	@echo "  lint              - Run golangci-lint via Docker (matches CI)"
	@echo "  sec               - Run gosec via Docker (matches CI static security analysis)"
	@echo "  test              - Run all tests"
	@echo "  test-unit         - Run unit tests only"
	@echo "  test-integration  - Run integration tests (requires Atlas CLI)"
	@echo "  test-e2e          - Run e2e gateway tests (Traefik + KrakenD stand)"
	@echo "  migrate-diff      - Generate a migration from schema.hcl (name=<what_changed>)"
	@echo "  migrate-apply     - Apply pending migrations to the dev database"
	@echo "  migrate-status    - Show applied and pending migrations"
	@echo "  migrate-baseline  - Mark an existing database as at a version (version=<v>)"
	@echo "  migrate-drift     - Show how the dev database differs from schema.hcl (read-only)"
	@echo "  up                - Start development environment"
	@echo "  down              - Stop and remove containers"
	@echo "  clean             - Stop and remove containers + volumes"
	@echo "  logs              - Follow logs for psina-dev service"

# Generate all code
gen: buf-gen go-gen

# Generate all files from .proto sources using buf
buf-gen:
ifndef BUF
	@echo "Installing buf..."
	go install github.com/bufbuild/buf/cmd/buf@latest
endif
	@echo "Generating protobuf files with buf..."
	buf generate --template buf.gen.yaml
	@echo "Protobuf files generated"

# Generate go code
go-gen:
	@echo "Generating go code..."
	go generate ./...

# Run golangci-lint via Docker (matches CI, no local install needed)
lint:
	docker run --rm -v $(PWD):/app -w /app golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) golangci-lint run

# Run gosec exactly as the CI job does (CI calls this target): golangci-lint
# does not cover it, and a #nosec it cannot see only fails in CI.
sec:
	docker run --rm -v $(PWD):/app -w /app ghcr.io/securego/gosec:$(GOSEC_VERSION) -quiet -exclude-generated ./...

# Run all tests
test: test-unit test-integration

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	go test -v -race -coverprofile=coverage-unit.out -covermode=atomic ./...

# Run integration tests (requires Docker)
test-integration:
	@echo "Running integration tests..."
	go test -v -tags=integration -coverprofile=coverage-integration.out ./...

# Run e2e gateway tests against a docker compose stand (Traefik + KrakenD).
# Uses a dedicated project name so it never clobbers the dev stack (make up).
# Brings the stand up, runs the Go driver, then always tears it down.
E2E_PROJECT=docker compose -p psina-e2e -f $(E2E_COMPOSE) --profile traefik --profile krakend
E2E_JWT_KEY=deploy/e2e/jwt-test-key.pem
test-e2e:
	@test -f $(E2E_JWT_KEY) || (echo "Generating e2e JWT signing key..."; \
		openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $(E2E_JWT_KEY))
	@echo "Starting e2e gateway stand..."
	$(E2E_PROJECT) up --build -d --wait
	@echo "Running e2e tests..."
	E2E_TRAEFIK_URL=http://localhost:8085 \
	E2E_KRAKEND_URL=http://localhost:8090 \
	E2E_PSINA_URL=http://localhost:8088 \
	E2E_JWT_KEY_PATH=$(CURDIR)/$(E2E_JWT_KEY) \
	go test -v -tags=e2e -count=1 ./test/e2e/... ; \
	status=$$? ; \
	echo "Tearing down e2e stand..." ; \
	$(E2E_PROJECT) down -v --remove-orphans ; \
	exit $$status

# Atlas: schema.hcl is the authoring surface, migrations/ is what instances
# run (see AGENTS.md, Database). Every target runs atlas in the compose
# migrate service against the compose postgres. Revisions live in the
# separate "atlas" schema so public stays comparable with schema.hcl.
MIGRATE=$(COMPOSE) -f $(COMPOSE_FILE) --profile default run --rm migrate
MIGRATE_DB_URL=postgres://psina:password@postgres:5432/psina?sslmode=disable
MIGRATE_DEV_URL=postgres://psina:password@postgres:5432/atlas_dev?sslmode=disable

# Generate the next migration from schema.hcl: make migrate-diff name=add_x
migrate-diff:
	@test -n "$(name)" || (echo "usage: make migrate-diff name=<what_changed>"; exit 1)
	$(MIGRATE) migrate diff $(name) \
		--dir "file:///migrations" \
		--to "file:///schema.hcl" \
		--dev-url "$(MIGRATE_DEV_URL)"

migrate-apply:
	$(MIGRATE) migrate apply \
		--url "$(MIGRATE_DB_URL)" \
		--dir "file:///migrations" \
		--revisions-schema atlas

migrate-status:
	$(MIGRATE) migrate status \
		--url "$(MIGRATE_DB_URL)" \
		--dir "file:///migrations" \
		--revisions-schema atlas

# Once per database that predates migrations/, after migrate-drift is empty:
# records <version> as applied without running it.
migrate-baseline:
	@test -n "$(version)" || (echo "usage: make migrate-baseline version=<v>"; exit 1)
	$(MIGRATE) migrate apply \
		--url "$(MIGRATE_DB_URL)" \
		--dir "file:///migrations" \
		--revisions-schema atlas \
		--baseline $(version)

# Read-only: what the database lacks or has beyond schema.hcl.
migrate-drift:
	$(MIGRATE) schema diff \
		--from "$(MIGRATE_DB_URL)&search_path=public" \
		--to "file:///schema.hcl" \
		--dev-url "$(MIGRATE_DEV_URL)&search_path=public"

# Run default/development profile services in detached mode
up:
	@echo "Starting Docker Compose (default profile)..."
	$(COMPOSE) -f $(COMPOSE_FILE) --profile default up --build -d --remove-orphans

# Stop containers
stop:
	@echo "Stopping services..."
	$(COMPOSE) -f $(COMPOSE_FILE) --profile default stop

# Stop and remove containers, networks
down: stop
	$(COMPOSE) -f $(COMPOSE_FILE) down --remove-orphans

# Stop and remove containers, networks, AND remove volumes (use with caution!)
clean: down
	@echo "Cleaning up Docker Compose (removing volumes)..."
	$(COMPOSE) -f $(COMPOSE_FILE) down -v --remove-orphans

# Follow logs for psina-dev service
logs:
	@echo "Following logs for psina-dev service..."
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f psina-dev

# Build production image
build:
	@echo "Building production image..."
	docker build -f build/Dockerfile -t psina:latest --build-arg _path=cmd/psina .
