# Known Limitations

This document is honest about what turnpass can and cannot do today.

## Fully implemented and tested

| Feature | Status |
| --- | --- |
| Browser profile JSON parsing (cfsolve-compatible) | Done |
| Recorded answers loading | Done |
| uTLS ClientHello fingerprinting (Chrome, iOS) | Done |
| HTTP/HTTPS/SOCKS5/SOCKS5h proxy support | Done |
| Cookie jar (RFC 6265 domain/path matching) | Done |
| Cloudflare challenge detection (5s, 10s, Turnstile) | Done |
| Turnstile widget discovery (sitekey, action, cData) | Done |
| Page title extraction | Done |
| Meta refresh redirect detection | Done |
| Typed solver interface (Outcome: Token \| Cleared) | Done |
| Typed error categories with retry semantics | Done |
| FlareSolverr-compatible API (/health, /, /v1) | Done |
| FlareSolverr commands (request.get, request.post, sessions.*) | Done |
| Session management with TTL and expiration | Done |
| turnpass CLI with pflag v1.1.0 | Done |
| turnpass-x CLI with pflag v1.1.0 | Done |
| Unit tests for all packages | Done |
| gofmt, go vet, go test all pass | Done |

## Not yet implemented (returns Unsupported)

### Challenge-program VM

The single largest piece of cfsolve is the challenge-program VM
(`src/challenge/`, ~200 KB of Rust). It consists of:

1. **Deobfuscator**: Uses Oxc's AST to deobfuscate Cloudflare's
   obfuscated challenge scripts.
2. **Bytecode interpreter**: Executes the deobfuscated program.
3. **Codec**: Encodes/decodes the program's payload.
4. **Payload builder**: Constructs the probe answer payload from
   recorded answers and program output.
5. **Orchestrator**: Manages the multi-stage challenge flow (initial
   payload, probe answers, proof-of-work).

Without the VM, turnpass cannot:
- Acquire Turnstile tokens (the widget's challenge program must be
  executed to produce the token).
- Clear Cloudflare challenge pages (the browser-check program must be
  executed to produce the proof payload).

The solver returns `errors.CategoryUnsupported` with a clear message
pointing to this document. No fake tokens or clearance cookies are
fabricated.

**Effort estimate**: The VM port is a multi-week effort. The
architecture is in place (`internal/solver` calls into the VM; the VM
package slot is reserved under `internal/stage2/`).

### Exact HTTP header wire-ordering

Go's `net/http` writes headers alphabetically. cfsolve's patched `wreq`
writes headers in the exact order specified by the profile's
`transport.requests.headers` per request kind.

Turnpass applies the profile's headers to each request, but the wire
order is alphabetical (Go's default). A custom HTTP/2 framer would be
needed to control the exact byte-level ordering.

**Impact**: Some Cloudflare edge configurations may reject requests with
alphabetically-ordered headers. The uTLS ClientHello (which is
browser-accurate) is the most important fingerprint signal and is
correctly reproduced.

### Chrome 154 ClientHello specifics

cfsolve patches BoringSSL to send Chrome 154's ClientHello, which
includes:
- ML-DSA signature algorithm
- GREASE signature algorithms
- `trust_anchors` extension

uTLS's `HelloChrome_Auto` preset tracks recent Chrome versions but may
not include all of these specifics. A custom `ClientHelloSpec` could be
constructed to match exactly, but this requires manual byte-level
specification.

### HTTP/2 SETTINGS frame control

cfsolve patches `http2` to control the SETTINGS frame ordering and
values. Go's `golang.org/x/net/http2` uses its own SETTINGS, which
differ from Chrome's.

### Capture proxy

cfsolve includes a `capture-proxy` tool that records the decoded
payloads a real browser sends to Cloudflare. This is used to produce
the recorded answers (`answers.json`). turnpass does not include a
capture proxy; the recorded answers from cfsolve's profiles can be
reused directly.

## Integration testing

The target test page is `https://nopecha.com/captcha/cloudflare`.

Without the challenge-program VM, turnpass can:
- Navigate to the page (uTLS + proxy if needed).
- Detect whether the page shows a Cloudflare challenge.
- Discover any Turnstile widgets and extract their sitekeys.
- Return the page's title, status, and HTML.

turnpass cannot:
- Acquire a Turnstile token from the page.
- Clear the Cloudflare challenge and obtain `cf_clearance`.

These capabilities will become available once the VM port is complete.

## Summary

turnpass is a functional foundation with all the infrastructure in
place. The transport, detection, API, CLI, and session management layers
are complete and tested. The remaining work is the challenge-program VM,
which is the core solving logic that produces tokens and clearance
cookies.
