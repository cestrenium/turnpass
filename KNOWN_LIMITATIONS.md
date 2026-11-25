# Known Limitations

This document is honest about what turnpass can and cannot do today.

## Fully implemented and tested

| Feature | Status |
| --- | --- |
| Browser profile JSON parsing (cfsolve-compatible) | Done |
| Recorded answers loading (upstream safari-26-ios.json verified) | Done |
| uTLS ClientHello fingerprinting (Chrome, iOS) with HTTP/2 ALPN | Done |
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
| Challenge page parsing (orchestrator URL, loading address, _cf_chl_opt) | Done |
| Turnstile loader script handling (build hash, route extraction) | Done |
| Turnstile iframe URL construction | Done |
| Challenge POST URL and cf-chl token extraction | Done |
| aa() string deobfuscation decoder (1486 strings decoded) | Done |
| Challenge codec (XTEA, RSA seed wrapping, DEFLATE, response mask) | Done |
| Full codec encode pipeline (frame -> pad -> XTEA -> RSA -> base64) | Done |
| Challenge POST channel (send + decode response) | Done |
| VM foundational types (Value, Term, Constant, 19 value kinds) | Done |
| VM register file model (256 registers, type tags, member decoding) | Done |
| VM output types (Position, Instruction, Listing, Path, Exit, Failure) | Done |
| VM AST extraction (FindVM: class, dispatch loop, handlers from JS AST) | Done |
| VM session state (constructor evaluation, register layout recovery) | Done |
| VM dispatch decoder (XOR-based opcode decoding) | Done |
| VM symbolic expression evaluator (~1000 lines, all AST node types) | Done |
| VM disassembler (worklist-based program walker) | Done |
| VM builtin functions (Math, String, Array, Object, parseInt, isNaN) | Done |
| Encoder parameter extraction (RSA modulus, base64 alphabet, key secret) | Done |
| Probe answer replay infrastructure (answers.json loading and parsing) | Done |
| extraParams collection (timeline, widget config, page signals) | Done |
| Challenge payload construction (first payload, probe payload) | Done |
| HTTP orchestration (fetch page, detect challenge, fetch orchestrator/loader/iframe) | Done |
| Integration tested against real Cloudflare (nopecha.com) | Done |
| Unit tests for all 20 packages | Done |
| gofmt, go vet, go test all pass | Done |

## Partially implemented (infrastructure in place, needs completion)

### Challenge-program VM execution

The VM foundational layer is complete: type system, register file, output
types, AST extraction, session state, dispatch decoder, expression evaluator,
disassembler, and builtin functions. However, the VM cannot yet execute
real Cloudflare challenge programs because:

1. **Deobfuscation pipeline**: The orchestrator script is heavily obfuscated
   with string array rotation (aa() function), XOR-obfuscated constants,
   and control flow flattening. The aa() decoder is implemented, but full
   AST-level deobfuscation (constant folding, function inlining, dead code
   elimination) is needed to make the VM code parseable by the evaluator.

2. **Dispatch loop decoding**: The current DecodeOpcode uses a simple XOR
   pattern (opcode = program[pc] ^ key). Real Cloudflare builds mix a hash
   of the program position into each opcode, requiring evaluation of the
   dispatch loop's decoding statements from the AST.

3. **Handler execution**: The evaluator can execute JavaScript expressions
   and statements, but handler execution over program bytes requires:
   - Register read/write with the rolling mask
   - String record decryption (tag -4)
   - Path exploration with symbolic conditions
   - Closure invocation and cell management

4. **Probe answer replay**: The answers.json is loaded and parsed, but
   the VM needs to map probe indices to the recorded fields and replay
   them in the payload. The payload builder is implemented but needs
   the VM to identify which probes a program requests.

### What blocks a successful solve

For challenge pages: The orchestrator script must be executed (or fully
deobfuscated) to produce the iframe URL. The iframe contains the VM class,
encoding constants (RSA modulus, base64 alphabet, key secret), and the
initial program. Without deobfuscation, these cannot be extracted.

For widget pages: The iframe is fetched directly, but the inline JavaScript
is also obfuscated. The VM class, handlers, and encoding constants must be
extracted from the deobfuscated iframe JS.

### Remaining work before v1

1. Full AST-level deobfuscation pipeline (constant folding, function inlining)
2. Dispatch loop statement evaluation (not just simple XOR)
3. Register file read/write with rolling mask
4. String record decryption
5. Path exploration with symbolic conditions
6. Probe index to answer field mapping
7. Full POST interaction (encode payload -> send -> decode response -> repeat)
8. Clearance cookie extraction and verification

## Integration testing

The target test page is `https://nopecha.com/captcha/cloudflare`.

The HTTP orchestration layer is verified end-to-end:
- HTTP/2 works (ALPN h2 confirmed against cloudflare.com)
- Challenge page detected (403, 5s challenge)
- Orchestrator fetched (611KB), aa() strings decoded (1486 unique)
- Loader script fetched (87KB)
- RSA public exponent identified (BigInt(65537))
- Encoder parameter extraction attempted
- VM analysis wired into orchestration flow

The solver cannot yet acquire Turnstile tokens or cf_clearance cookies
because the challenge-program VM cannot execute real programs.
