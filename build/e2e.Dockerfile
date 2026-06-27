# Self-contained image for the e2e stand: builds psina from source.
# Unlike build/Dockerfile (goreleaser, expects a prebuilt binary), this compiles
# inside the image so CI can run the gateway stand without a separate build step.
FROM golang:1.25-alpine AS build

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /psina ./cmd/psina

FROM alpine:latest
RUN apk --no-cache add ca-certificates wget

COPY --from=build /psina /psina

EXPOSE 8080

ENTRYPOINT ["/psina"]
