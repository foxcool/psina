FROM golang:1.26-alpine

ENV PROJECT_PATH=github.com/foxcool/psina

# Get CMD path argument (default: cmd/psina)
ARG _path="cmd/psina"

# Set environment variable for Go
ENV GOPATH=/go \
    PATH="/go/bin:$PATH"

# Install build dependencies
RUN apk add --no-cache git

# Copy project files
WORKDIR ${GOPATH}/src/${PROJECT_PATH}
COPY go.mod go.sum ./

# Install air for live reload (pinned: @latest silently raises the Go floor)
RUN go install github.com/air-verse/air@v1.67.2
