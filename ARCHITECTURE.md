# Architecture

## Overview

turnpass is a single Go module that produces two executables:

```
turnpass/
├── cmd/
│   ├── turnpass/          # Core solver CLI
│   └── turnpass-x/        # FlareSolverr-compatible API server
├── internal/
│   ├── browserprofile/   # Loads fingerprint JSON + recorded answers
│   ├── cookies/           # In-memory cookie jar (RFC 6265)
│   ├── errors/            # Typed error categories
│   ├── fingerprint/       # Parses cfsolve-compatible profile JSON
│   ├── protocol/          # Challenge detection, widget discovery
│   ├── solver/            # Unified solver interface
│   └── transport/         # uTLS HTTP client with proxy support
├── api/
│   ├── handlers/          # FlareSolverr command dispatch
│   ├── middleware/        # Logging, recovery, timeout
│   ├── server/            # HTTP server with graceful shutdown
│   ├── sessions/          # In-process session store
│   └── types/             # FlareSolverr request/response types
├── go.mod
└── go.sum
```

## Design principles

1. **Request-based architecture.** No headless browser. The solver
   reproduces browser behaviour at the TLS and HTTP level using uTLS.

2. **Core solver is independent of the API.** The `internal/solver`
   package has no dependency on `api/`. The API server wraps the solver;
   the CLI uses it directly.

3. **Typed outcomes and errors.** `solver.Outcome` is a sum type
   (`OutcomeToken` | `OutcomeCleared`). `errors.Error` carries a
   `Category` (Config, Network, Blocked, Challenged, NotChallenged,
   Rejected, Sink, Unsupported) with `Retryable()` semantics.

4. **Profile compatibility.** The fingerprint JSON parser accepts
   cfsolve's profile format verbatim. Unknown keys are ignored, matching
   the original serde behaviour.

5. **pflag v1.1.0.** Both CLIs use `github.com/spf13/pflag` v1.1.0
   exclusively for flag parsing. Go's standard `flag` package is not
   used.

## Data flow

### turnpass CLI

```
Profile JSON ──► browserprofile.Read ──► solver.New
                                              │
URL ──► solver.Solve ──► transport.New ──► uTLS dial ──► HTTP GET
                                              │
                              protocol.ParsePage ◄── response
                                              │
                              detectChallenge + findWidgets
                                              │
                              Outcome{Token} or Outcome{Cleared}
```

### turnpass-x API server

```
POST / or /v1
      │
      ▼
 handlers.ParseRequest ──► Dispatcher.Handle
      │
      ├── request.get / request.post ──► solver.Solve ──► Solution
      ├── sessions.create               ──► Store.Create
      ├── sessions.list                 ──► Store.List
      └── sessions.destroy              ──► Store.Destroy
      │
      ▼
 types.Response ──► JSON ──► client
```

## Transport layer

The transport uses `github.com/refraction-networking/utls` to produce a
browser-accurate TLS ClientHello:

| Engine | uTLS preset |
| --- | --- |
| chromium | `HelloChrome_Auto` |
| webkit | `HelloIOS_Auto` |

Proxy support covers `http://`, `https://`, `socks5://`, and
`socks5h://` (remote DNS). HTTP CONNECT is used for HTTP/HTTPS proxies;
`golang.org/x/net/proxy` is used for SOCKS5.

The cookie jar (`internal/cookies`) implements RFC 6265 domain and path
matching, Secure/HttpOnly/SameSite awareness, and Set-Cookie parsing. It
is adapted to `net/http.CookieJar` via a thin wrapper so redirects store
and send cookies automatically.

## Session management

The FlareSolverr session store (`api/sessions`) is an in-process map of
session ID to `*Session`, each with its own `cookies.Jar`. Sessions
expire after `session_ttl_minutes` (default 15). The store is thread-safe
and not coupled to the solver.
