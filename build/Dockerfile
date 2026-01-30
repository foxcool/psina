# Dockerfile for goreleaser
# This dockerfile expects the binary to be already built and copied by goreleaser
FROM alpine:latest

RUN apk --no-cache add ca-certificates curl

# Install Atlas CLI for migrations
RUN curl -sSf https://atlasgo.sh | sh

# Copy schema for Atlas
COPY schema.hcl /schema.hcl

# Copy the pre-built binary from goreleaser
COPY psina /psina

EXPOSE 8080

ENTRYPOINT ["/psina"]
