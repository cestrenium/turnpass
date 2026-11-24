# Testing

## Running tests

```bash
go test ./...
```
## Verbose output

```bash
go test -v ./...
```

## With coverage

```bash
go test -cover ./...
go test -coverprofile=coverage.txt ./...
go tool cover -html=coverage.txt -o coverage.html
```

## Test packages

| Package | Tests |
| --- | --- |
| `internal/errors` | Category strings, retryable semantics, Display, Classify. |
| `internal/fingerprint` | JSON parsing, unknown keys ignored, validation, missing fields. |
| `internal/browserprofile` | Read from disk, FromJSON, String. |
| `internal/cookies` | Set/retrieve, domain matching, path matching, replace, Secure, Clear, defaultPath. |
| `internal/transport` | New requires fingerprint, builds client, Do against test server, proxy validation, ClientHelloID mapping. |
| `internal/protocol` | Title extraction, challenge detection (5s/10s/Turnstile/managed), widget discovery, render call parsing, deduplication, meta refresh, balanced brace. |
| `internal/solver` | URL required, blank requires widget, no widget returns Unsupported, Clear requires URL. |
| `api/types` | Request roundtrip, NewOK, NewError. |
| `api/sessions` | Create/Get, duplicate, missing, List/Destroy, expiration. |
| `api/handlers` | Unknown cmd, session create/list/destroy, request.get requires URL, proxy URL resolution. |
| `api/middleware` | Recovery, Timeout, Logging. |

## CI checks

The GitHub Actions CI workflow runs:

```bash
gofmt -l .
go vet ./...
go test ./...
go build ./cmd/turnpass
go build ./cmd/turnpass-x
GOOS=linux GOARCH=amd64 go build ./...
GOOS=linux GOARCH=arm64 go build ./...
```

## Integration testing

The target integration test page is
`https://nopecha.com/captcha/cloudflare`.

### What can be tested today

Without the challenge-program VM:

1. **Page retrieval**: Navigate to the target URL via uTLS transport.
2. **Challenge detection**: Verify the page is correctly classified.
3. **Widget discovery**: Verify Turnstile sitekeys are extracted.
4. **Proxy compatibility**: Test with HTTP/HTTPS/SOCKS5 proxies.
5. **API server**: Test the FlareSolverr-compatible endpoints with curl.
6. **Session management**: Test session create/list/destroy/reuse.

### What cannot be tested yet

7. **Token acquisition**: Requires the challenge-program VM.
8. **cf_clearance clearance**: Requires the challenge-program VM.

These will be tested once the VM port is complete.

### Manual API testing with curl

```bash
# Start the server
turnpass-x --profile profiles/safari-26-ios.json &

# Health check
curl http://localhost:8191/health

# Create a session
curl -X POST http://localhost:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"sessions.create","session":"test"}'

# Request a page
curl -X POST http://localhost:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"request.get","url":"https://example.com/","maxTimeout":60000}'

# List sessions
curl -X POST http://localhost:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"sessions.list"}'

# Destroy the session
curl -X POST http://localhost:8191/v1 \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"sessions.destroy","session":"test"}'
```
