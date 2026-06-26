# Define makefile variables for frequently used commands
BUF=$(shell which buf)
# Use docker compose instead of docker-compose
COMPOSE=docker compose -p psina
# Path to the compose file
COMPOSE_FILE=deploy/compose.yaml
# Path to the e2e gateway stand compose file
E2E_COMPOSE=deploy/e2e/compose.yaml

.PHONY: gen buf-gen go-gen test test-unit test-integration test-e2e up down clean logs help schema-apply schema-diff

# Default target
help:
	@echo "Available targets:"
	@echo "  gen               - Generate all code (buf + go generate)"
	@echo "  buf-gen           - Generate protobuf files with buf"
	@echo "  go-gen            - Generate go code (go generate)"
	@echo "  test              - Run all tests"
	@echo "  test-unit         - Run unit tests only"
	@echo "  test-integration  - Run integration tests (requires Atlas CLI)"
	@echo "  test-e2e          - Run e2e gateway tests (Traefik + KrakenD stand)"
	@echo "  schema-apply      - Apply schema to database (declarative)"
	@echo "  schema-diff       - Show schema diff without applying"
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

# Run all tests
test: test-unit test-integration

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	go test -v -race -coverprofile=coverage-unit.out -covermode=atomic ./...

# Run integration tests (requires Docker)
test-integration:
	@echo "Running integration tests..."
	go test -v -tags=integration -coverprofile=coverage-integration.out ./pkg/...

# Run e2e gateway tests against a docker compose stand (Traefik + KrakenD).
# Uses a dedicated project name so it never clobbers the dev stack (make up).
# Brings the stand up, runs the Go driver, then always tears it down.
E2E_PROJECT=docker compose -p psina-e2e -f $(E2E_COMPOSE) --profile traefik --profile krakend
test-e2e:
	@echo "Starting e2e gateway stand..."
	$(E2E_PROJECT) up --build -d --wait
	@echo "Running e2e tests..."
	E2E_TRAEFIK_URL=http://localhost:8085 \
	E2E_KRAKEND_URL=http://localhost:8090 \
	E2E_PSINA_URL=http://localhost:8088 \
	go test -v -tags=e2e -count=1 ./test/e2e/... ; \
	status=$$? ; \
	echo "Tearing down e2e stand..." ; \
	$(E2E_PROJECT) down -v --remove-orphans ; \
	exit $$status

# Atlas: apply schema declaratively (runs inside compose network)
schema-apply:
	@echo "Applying schema to database..."
	$(COMPOSE) -f $(COMPOSE_FILE) --profile default run --rm migrate

# Atlas: show schema diff (runs inside compose network)
schema-diff:
	@echo "Showing schema diff..."
	$(COMPOSE) -f $(COMPOSE_FILE) --profile default run --rm migrate \
		schema diff \
		--from "postgres://psina:password@postgres:5432/psina?sslmode=disable" \
		--to "file:///schema.hcl" \
		--dev-url "postgres://psina:password@postgres:5432/atlas_dev?sslmode=disable"

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
