# Local/dev image. Releases use Dockerfile.goreleaser via GoReleaser.
FROM golang:1.24-alpine AS builder
WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
  -o /out/thalassa-observability-workspace-proxy ./cmd/proxy

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /out/thalassa-observability-workspace-proxy /thalassa-observability-workspace-proxy
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/thalassa-observability-workspace-proxy"]
