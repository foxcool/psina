FROM golang:1.24-alpine AS builder

ENV PROJECT_PATH=github.com/foxcool/psina

# Get CMD path argument (default: cmd/psina)
ARG _path="cmd/psina"

# Set environment variable for Go
ENV GOPATH=/go \
    PATH="/go/bin:$PATH"

# Copy project files
WORKDIR ${GOPATH}/src/${PROJECT_PATH}

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build from project root, specifying the cmd path
RUN CGO_ENABLED=0 GOOS=linux go build -o ${GOPATH}/bin/app ./${_path}

# Init new lightweight container
FROM alpine:latest
RUN apk --no-cache add ca-certificates curl

# Copy migrations if they exist
COPY --from=builder /go/src/github.com/foxcool/psina/deploy/migrations /migrations

# Copy the binary
COPY --from=builder /go/bin/app /app

# Run the compiled bin by default when the container starts
CMD ["/app"]
