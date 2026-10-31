# Dockerfile for goreleaser
# This dockerfile expects the binary to be already built and copied by goreleaser
FROM alpine:latest

RUN apk --no-cache add ca-certificates curl

# Install Atlas CLI for migrations
RUN curl -sSf https://atlasgo.sh | sh

# Migrations are what instances run (atlas migrate apply); schema.hcl ships
# for read-only drift checks only.
COPY migrations /migrations
COPY schema.hcl /schema.hcl

# Copy the pre-built binary from goreleaser
COPY psina /psina

EXPOSE 8080

ENTRYPOINT ["/psina"]
