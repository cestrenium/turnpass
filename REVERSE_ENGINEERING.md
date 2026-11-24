# Reverse Engineering Findings

This document records what was learned from reading the cfsolve source
(code SHA `06d58d6`, 2026-11).

## Repository structure

```
cfsolve/
├── src/
│   ├── lib.rs              # Public API: Browser, Options, Turnstile, Outcome, Error
│   ├── browser.rs          # Profile loading + validation (17 KB)
│   ├── solver.rs           # Solve entry points (10 KB)
│   ├── engine.rs           # Engine enum (chromium | webkit)
│   ├── fingerprint.rs      # Transport section parser
│   ├── error.rs            # Error enum + classify()
│   ├── http/               # Patched wreq transport (60 KB)
│   │   ├── client.rs
│   │   ├── header_order.rs
│   │   ├── requests.rs
│   │   ├── referrer.rs
│   │   └── decode.rs
│   ├── session/            # Challenge solving flow (95 KB)
│   │   ├── initial.rs
│   │   ├── widget.rs
│   │   ├── challenge_page.rs
│   │   ├── probes.rs
│   │   ├── interaction.rs
│   │   ├── timing.rs
│   │   └── sink.rs
│   ├── challenge/          # VM + deobfuscation (200 KB)
│   │   ├── codec.rs
│   │   ├── expression.rs
│   │   ├── program.rs
│   │   ├── source.rs
│   │   ├── state.rs
│   │   ├── payload.rs
│   │   ├── orchestrator.rs
│   │   ├── merge.rs
│   │   ├── installed.rs
│   │   ├── reduced_timing.rs
│   │   └── tally.rs
│   ├── vm/                 # Bytecode interpreter
│   ├── deobfuscate/        # Oxc AST analysis
│   └── stage2/             # Probe answer replay
├── profiles/
│   ├── safari-26-ios.json          # 15 KB profile
│   └── safari-26-ios/
│       ├── answers.json            # 186 KB recorded probe answers
│       └── challenge-page-answers.json
└── vendor/
    ├── btls-sys/          # Patched BoringSSL (Chrome 154 ClientHello)
    ├── wreq/              # Patched HTTP client
    └── http2/             # Patched HTTP/2
```

## Key findings

### 1. Browser profile format

The profile JSON has these top-level sections:

- `engine`: `"chromium"` or `"webkit"`
- `transport`: profile name, platform, headers, `requests.headers`
  (per-request-kind header ordering), optional `client_hello`
- `browser`: page layout (inner_width, inner_height, challenge_page box)
- `timeline`: script fetch, render, init, params, collect, sent timings
- `intervals`: initialise, handoff, collect, send
- `orchestrator`: intervals, program_startup_ms, callback_ms
- `resource_timing`: phases, navigation, sizes_exposed
- `interaction`: viewport, checkbox position, ready_delay_ms, touch
- `second`: facts (navigator, media, proof_worker, benchmark_worker),
  document, image, durations, startup_ms, pending_ms
- `answers`: path to recorded probe answers (186 KB JSON)
- `challenge_page_answers`: path to challenge-page-specific answers

### 2. Transport

cfsolve patches BoringSSL (`btls-sys`) to send Chrome 154's ClientHello,
which includes ML-DSA and GREASE signature algorithms and the
`trust_anchors` extension that published crates cannot send. It also
patches `wreq` (HTTP client) and `http2` for header ordering and HTTP/2
SETTINGS frame control.

In Go, uTLS provides browser-accurate ClientHello presets
(`HelloChrome_Auto`, `HelloIOS_Auto`). The exact Chrome 154 ClientHello
with ML-DSA is not available in uTLS presets; this is a documented
limitation.

### 3. Header ordering

Each request kind (navigation, iframe, script, orchestrator_post, etc.)
has an explicit header order in `transport.requests.headers`. Headers
are listed as strings; `"user-agent"` is a placeholder (filled from
`transport.headers["User-Agent"]`), `"referer"` and `"origin"` are
filled dynamically, `"content-length"` and `"cf-chl"` are filled per
request.

Go's `net/http` writes headers alphabetically. Exact wire-order
reproduction requires a custom HTTP/2 framer, which is a documented
limitation.

### 4. Challenge program VM

The `src/challenge/` directory (200 KB of Rust) implements:

- **Deobfuscation**: Uses Oxc's arena AST, semantic symbols, visitors,
  and constant evaluator to deobfuscate Cloudflare's challenge scripts.
- **VM**: A bytecode interpreter that executes the deobfuscated program.
- **Codec**: Encodes/decodes the program's payload.
- **Payload**: Builds the probe answer payload from recorded answers.
- **Orchestrator**: Manages the multi-stage challenge flow.

The recorded answers (`answers.json`, 186 KB) contain:
- Navigator properties (hardwareConcurrency, userAgent, etc.)
- Media codecs (RTCReceiverCapabilities for audio and video)
- WebRTC ICE candidates and SDP
- Proof worker timings (digest_us, startup_ms)
- Benchmark worker timings (compile_ms, kernel_ms_per_million)
- 37 probe categories with durations (audio, behavior, clock_resolution,
  font_enumeration, graphics, media, etc.)

### 5. Challenge flow

1. Navigate to the target URL.
2. If a challenge page is returned (403/503 with cf-mitigated), detect
   the challenge kind (5s or 10s/managed).
3. Fetch the Turnstile iframe from `challenges.cloudflare.com`.
4. Fetch the orchestrator script.
5. Deobfuscate and execute the challenge program in the VM.
6. Build the probe payload from recorded answers + program output.
7. POST the payload to the orchestrator endpoint.
8. If accepted, receive a token (Turnstile) or cf_clearance cookie
   (challenge page).
9. For challenge pages, follow the redirect to the protected page.

### 6. Error categories

cfsolve's `Error` enum maps directly to turnpass's `errors.Category`:

| cfsolve | turnpass | Retryable |
| --- | --- | --- |
| Config | CategoryConfig | No |
| Network | CategoryNetwork | Yes |
| Blocked | CategoryBlocked | No |
| Challenged | CategoryChallenged | Yes |
| NotChallenged | CategoryNotChallenged | No |
| Rejected | CategoryRejected | Yes |
| Sink | CategorySink | No |
| Unsupported | CategoryUnsupported | No |

### 7. What turnpass implements vs. defers

**Implemented:**
- Profile JSON parsing (all sections, unknown keys ignored)
- Recorded answers loading
- uTLS transport with Chrome/iOS ClientHello presets
- HTTP/HTTPS/SOCKS5/SOCKS5h proxy support
- Cookie jar (RFC 6265)
- Challenge detection (5s, 10s/managed, Turnstile widget)
- Turnstile widget discovery (`.cf-turnstile`, `data-sitekey`,
  `turnstile.render` calls with action/cData)
- Page title extraction
- Meta refresh redirect detection
- Typed solver interface with Outcome and error categories
- FlareSolverr-compatible API (request.get, request.post,
  sessions.create/list/destroy, /health)
- Both CLIs with pflag v1.1.0

**Deferred (documented as Unsupported):**
- Challenge program VM (deobfuscation + bytecode interpreter)
- Probe payload construction from recorded answers
- Orchestrator POST interaction
- Exact header wire-ordering (requires custom HTTP/2 framer)
- Chrome 154 ClientHello specifics (ML-DSA, trust_anchors)
