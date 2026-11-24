# Implementation Plan

## Milestones

### Milestone 1: Research (done)

- Read cfsolve source (lib.rs, browser.rs, solver.rs, fingerprint.rs,
  error.rs, engine.rs, http/, session/, challenge/).
- Read flaresolverr-go source (cmd/, internal/, pkg/).
- Document findings on docs branch.

### Milestone 2: Core transport (done)

- `internal/fingerprint`: profile JSON parser.
- `internal/browserprofile`: high-level Browser loader.
- `internal/cookies`: RFC 6265 cookie jar.
- `internal/transport`: uTLS HTTP client with proxy support.
- `internal/errors`: typed error categories.

### Milestone 3: Protocol (done)

- `internal/protocol`: challenge detection (5s, 10s, Turnstile).
- Widget discovery (`.cf-turnstile`, `data-sitekey`, `turnstile.render`).
- Sitekey/action/cData extraction.
- Page title and meta refresh extraction.

### Milestone 4: Solver interface (done)

- `internal/solver`: typed Outcome (Token, Cleared).
- Options (proxy, trusted root, timeout, sink).
- Turnstile request with PageSource (Navigate, HTML, Blank).
- FetchedPage for caller-supplied challenge pages.
- Clearance result.
- Error classification.

### Milestone 5: turnpass CLI (done)

- pflag v1.1.0 with long+short flags.
- Modes: auto, turnstile, challenge.
- Proxy, timeout, profile, sitekey, action, cdata, blank-page.
- Verbose output and debug artifact directory.
- Meaningful exit codes.

### Milestone 6: turnpass-x API (done)

- FlareSolverr-compatible request/response types.
- Session store with TTL and expiration.
- Command handlers: request.get, request.post, sessions.create/list/destroy.
- HTTP server with /health, /, /v1 endpoints.
- Graceful shutdown, structured logging, panic recovery.
- pflag v1.1.0 CLI.

### Milestone 7: Challenge-program VM (in progress)

- `internal/stage2/`: deobfuscator, bytecode interpreter, payload builder.
- This is the largest remaining piece.
- Requires porting cfsolve's `src/challenge/` (200 KB Rust) and
  `src/vm/` to Go.
- Until complete, solve attempts return `Unsupported`.

### Milestone 8: Integration testing (pending VM)

- Test against `https://nopecha.com/captcha/cloudflare`.
- Verify Turnstile token acquisition.
- Verify cf_clearance cookie acquisition.
- Test with public proxies from proxy-scraper.
- Document results.

### Milestone 9: Release preparation (done)

- GitHub Actions CI workflow on main.
- GitHub Actions release workflow on main (draft, no v1).
- gofmt, go vet, go test in CI.
- Cross-compile for linux/amd64 and linux/arm64.

## Dependency choices

| Dependency | Version | Purpose |
| --- | --- | --- |
| github.com/spf13/pflag | v1.1.0 | CLI flag parsing (mandatory) |
| github.com/refraction-networking/utls | v1.6.6 | TLS ClientHello fingerprinting |
| golang.org/x/net | v0.33.0 | SOCKS5 proxy support |
