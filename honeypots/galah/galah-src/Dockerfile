# Multi-stage build for Galah honeypot
# Stage 1: build the Go binary with CGO enabled (go-sqlite3 needs C bindings)
FROM golang:1.23-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=1
RUN go build -o /out/galah-bin ./cmd/galah

# Stage 2: minimal runtime image
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/galah-bin ./galah-bin
COPY config ./config
EXPOSE 8080 8888
ENTRYPOINT ["./galah-bin"]
