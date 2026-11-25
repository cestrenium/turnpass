# Known Limitations

This document is honest about what turnpass can and cannot do today.

## Fully implemented and tested (21 packages, all passing)

| Feature | Status |
| --- | --- |
| Browser profile JSON parsing (cfsolve-compatible, upstream verified) | Done |
| Recorded answers loading (upstream safari-26-ios.json verified) | Done |
| uTLS ClientHello fingerprinting (Chrome, iOS) with HTTP/2 ALPN | Done |
| HTTP/HTTPS/SOCKS5/SOCKS5h proxy support | Done |
| Cookie jar (RFC 6265 domain/path matching) | Done |
| Cloudflare challenge detection (5s, 10s, Turnstile) | Done |
| Turnstile widget discovery (sitekey, action, cData) | Done |
| Typed solver interface (Outcome: Token \| Cleared) | Done |
| Typed error categories with retry semantics | Done |
| FlareSolverr-compatible API (/health, /, /v1) | Done |
| FlareSolverr commands (request.get, request.post, sessions.*) | Done |
| Session management with TTL and expiration | Done |
| turnpass CLI with pflag v1.1.0 | Done |
| turnpass-x CLI with pflag v1.1.0 | Done |
| Challenge page parsing (orchestrator URL, loading address, _cf_chl_opt) | Done |
| Turnstile loader script handling (build hash, route extraction) | Done |
| Turnstile iframe URL construction | Done |
| Challenge POST URL and cf-chl token extraction | Done |
| aa()/a0() string deobfuscation decoder (1441 strings decoded) | Done |
| Full deobfuscation pipeline (XOR keys, constant folding, string decode) | Done |
| Challenge codec (XTEA, RSA seed wrapping, DEFLATE, response mask) | Done |
| Full codec encode pipeline (frame -> pad -> XTEA -> RSA -> base64) | Done |
| Challenge POST channel (send + decode response) | Done |
| VM foundational types (Value, Term, Constant, 19 value kinds) | Done |
| VM register file model (256 registers, type tags, member decoding) | Done |
| VM output types (Position, Instruction, Listing, Path, Exit, Failure) | Done |
| VM AST extraction (FindVM: class, dispatch loop, handlers from JS AST) | Done |
| VM session state (constructor evaluation, register layout recovery) | Done |
| VM dispatch decoder (AST-based + XOR fallback) | Done |
| VM symbolic expression evaluator (~1000 lines, all AST node types) | Done |
| VM disassembler (worklist-based program walker) | Done |
| VM path explorer (symbolic branch conditions) | Done |
| VM logical operators (&&, ||, ?? with short-circuit) | Done |
| VM builtin functions (Math, String, Array, Object, parseInt, isNaN) | Done |
| Encoder parameter extraction (RSA modulus, base64 alphabet, key secret) | Done |
| Probe answer replay infrastructure (answers.json loading and parsing) | Done |
| extraParams collection (timeline, widget config, page signals) | Done |
| Challenge payload construction (first payload, probe payload) | Done |
| Full POST interaction (payload -> codec -> POST -> decode response) | Done |
| HTTP orchestration (fetch, detect, deobfuscate, extract, POST) | Done |
| Integration tested against real Cloudflare (nopecha.com) | Done |
| gofmt, go vet, go test all pass | Done |

## What blocks a successful solve

The entire pipeline is implemented end-to-end:
HTTP transport -> challenge detection -> orchestrator fetch -> deobfuscation
-> encoder extraction -> payload construction -> codec encoding -> POST
-> response decoding -> VM disassembly.

The remaining gap is that the RSA modulus, base64 alphabet, and key-transform
secret are embedded in the **iframe JavaScript** (not the orchestrator).
For challenge pages, the iframe URL is produced by the orchestrator's first
POST response, which requires executing the orchestrator's VM code. The
deobfuscation pipeline decodes 1441 strings and resolves XOR keys, but the
orchestrator's code is still too complex for the current evaluator to execute
directly (it needs full function inlining and control flow unflattening).

For widget pages, the iframe is fetched directly, but the iframe JS is also
obfuscated. The VM class, handlers, and encoding constants must be extracted
from the deobfuscated iframe JS.

### Remaining work before v1

1. **Full function inlining**: Inline simple accessor functions (O(), T0-T9, etc.)
   that the orchestrator defines for property access.
2. **Control flow unflattening**: The orchestrator uses a state machine pattern
   that needs to be unflattened for the evaluator to follow.
3. **VM class extraction from deobfuscated JS**: Once the orchestrator is
   fully deobfuscated, the VM class, encoding constants, and initial program
   can be extracted.
4. **Probe index to answer field mapping**: Map the VM's probe requests to
   the recorded answer fields.
5. **Full multi-stage POST interaction**: First POST -> decode response ->
   probe POST -> decode response -> interaction POST -> extract token/clearance.
6. **Clearance cookie extraction and verification**: Follow the redirect after
   challenge clearance and verify the cf_clearance cookie.

## Integration testing

The target test page is `https://nopecha.com/captcha/cloudflare`.

The full pipeline is verified end-to-end:
- HTTP/2 works (ALPN h2 confirmed against cloudflare.com)
- Challenge page detected (403, 5s challenge)
- Orchestrator fetched (626KB), deobfuscated (467KB, 1441 strings decoded)
- Loader script fetched (87KB)
- Deobfuscation pipeline: XOR keys resolved, constants folded, strings decoded
- VM analysis wired into orchestration flow
- Payload construction, codec encoding, and POST infrastructure complete
- All 21 packages pass: gofmt, go vet, go test ./...
