# Define makefile variables for frequently used commands
BUF=$(shell which buf)
# Use docker compose instead of docker-compose
COMPOSE=docker compose -p psina
# Path to the compose file
COMPOSE_FILE=deploy/compose.yaml

.PHONY: gen buf-gen go-gen test test-unit test-integration test-e2e up down clean logs help

# Default target
help:
	@echo "Available targets:"
	@echo "  gen               - Generate all code (buf + go generate)"
	@echo "  buf-gen           - Generate protobuf files with buf"
	@echo "  go-gen            - Generate go code (go generate)"
	@echo "  test              - Run all tests"
	@echo "  test-unit         - Run unit tests only"
	@echo "  test-integration  - Run integration tests with postgres"
	@echo "  test-e2e          - Run e2e tests in docker"
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

# Run integration tests with postgres
test-integration:
	@echo "Running integration tests..."
	@echo "Starting postgres..."
	$(COMPOSE) -f $(COMPOSE_FILE) up -d postgres
	@echo "Waiting for postgres to be ready..."
	@sleep 5
	@echo "Running tests..."
	PSINA_DB_URL="postgres://psina:password@localhost:5432/psina?sslmode=disable" \
		go test -v -tags=integration -coverprofile=coverage-integration.out ./...
	@echo "Stopping postgres..."
	$(COMPOSE) -f $(COMPOSE_FILE) down

# Run e2e tests in docker
test-e2e:
	@echo "Running e2e tests in docker..."
	$(COMPOSE) -f $(COMPOSE_FILE) --profile test run --rm \
		-e DOCKER_COMPOSE_TEST=true \
		psina-test go test -v -tags=e2e ./...

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
