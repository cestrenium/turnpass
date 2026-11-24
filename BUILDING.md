# Building

## Prerequisites

- Go 1.27 or newer.
- Git (for fetching dependencies).

## Build both executables

```bash
go build -o turnpass ./cmd/turnpass
go build -o turnpass-x ./cmd/turnpass-x
```
## Build from a specific branch

```bash
git clone -b dev https://github.com/cestrenium/turnpass.git
cd turnpass
go build ./cmd/turnpass
go build ./cmd/turnpass-x
```

## Cross-compile

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o turnpass-linux-amd64 ./cmd/turnpass
GOOS=linux GOARCH=amd64 go build -o turnpass-x-linux-amd64 ./cmd/turnpass-x

# Linux arm64
GOOS=linux GOARCH=arm64 go build -o turnpass-linux-arm64 ./cmd/turnpass
GOOS=linux GOARCH=arm64 go build -o turnpass-x-linux-arm64 ./cmd/turnpass-x
```

## Verify the build

```bash
go vet ./...
gofmt -l .
go test ./...
```

All three should pass with no output (or `ok` for tests).

## Dependencies

The project uses three direct dependencies:

- `github.com/spf13/pflag` v1.1.0 (CLI flags, mandatory)
- `github.com/refraction-networking/utls` v1.6.6 (TLS fingerprinting)
- `golang.org/x/net` v0.33.0 (SOCKS5 proxy support)

Indirect dependencies are managed by `go mod` and recorded in `go.sum`.
