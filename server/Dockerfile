# syntax=docker/dockerfile:1.7
FROM golang:1.24 AS builder
WORKDIR /src

COPY go.work go.work.sum ./
COPY pkg ./pkg
COPY server ./server
COPY cli ./cli

WORKDIR /src/server
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /out/aporto-server ./cmd/aporto-server

FROM gcr.io/distroless/base-debian12 AS runtime
WORKDIR /app
COPY --from=builder /out/aporto-server /usr/local/bin/aporto-server

EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/aporto-server"]
CMD ["--config", "/etc/aporto/config.yaml"]
