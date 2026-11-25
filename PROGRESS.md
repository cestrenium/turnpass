# Progress and Known Limitations

This document tracks the current state of the turnpass port relative to
cfsolve, as of the latest commit on `dev`.

## What Works

### HTTP Orchestration
- Navigate to a target page and detect Cloudflare challenge type (5s, 10s,
  Turnstile widget).
- Fetch the orchestrator script from challenge pages.
- Fetch the Turnstile loader script (api.js) from widget pages.
- Build and fetch the Turnstile iframe URL (for widget pages).
- Extract inline JavaScript from the iframe HTML.
- Extract `_cf_chl_opt` values from the challenge page HTML (cH, cFPWv,
  cRay, cUPMDTk, cITimeS).
- Construct the orchestrator POST URL with the correct format:
  `/cdn-cgi/challenge-platform/h/<variant>/fo/<id>:<ts>:<nonce>/<ray>/<token>`

### Deobfuscation
- String decoder extraction (b0/aa style with rolling XOR keys, dynamic
  key discovery per orchestrator build).
- XOR key variable resolution (`_0xNNNN = (a=>a).length + N`).
- Constant folding (XOR chains, `(n|0)` patterns, with whitespace
  preservation to ensure valid JS output).
- XOR-access replacement (`obj[N ^ _0xKEY]` → `obj[resolvedN]`).
- Accessor function inlining (`T0(obj)` → `obj[5]`).
- Runtime evaluation via goja (sandboxed execution of deobfuscated scripts
  with `_cf_chl_opt` injection for computed constants).
- The deobfuscated output is valid JavaScript that goja's parser accepts.

### Encoder Parameter Extraction (AST-based)
- **Base64 alphabet**: 64-character string with distinct ASCII chars,
  found via AST walk of string literals and template literals. Validated
  against live Cloudflare orchestrators.
- **RSA modulus**: 1024-bit `BigInt` argument, found via four regex
  patterns (direct `BigInt("0x...")`, lazy-init `BigInt(VAR||(VAR=...))`,
  bare `VAR||(VAR=`0xHEX`)`, and bare `0xHEX` literals). Validated.
- **Program runner**: `<global>.<name> = function(p){ return <run>(new
  <Class>(p), pc, key, []); }` found via AST analysis. Handles computed
  XOR expressions for pc/key (e.g., `65382^(31090^~-19635)^51878`)
  via `evalConstInt` with JavaScript int32 semantics.
- **Initial VM program**: base64-encoded string passed to the runner,
  found via AST. Validated: 27488 bytes of base64 → 20614 bytes of VM
  bytecode.
- **Encoder function name**: the function whose result is passed to
  `send()`, found via AST with lazy-init member access support
  (`obj[VAR||(VAR=`send`)]`).

### Codec
- XTEA block cipher (32 rounds, big-endian).
- RSA seed wrapping (1024-bit modulus, exponent 65537).
- DEFLATE compression with framing/deframing.
- Custom base64 alphabet encode/decode.
- Response XOR mask removal (using the ray token).
- Full encode/decode pipeline: `Codec.Encode(payload)` and
  `Codec.DecodeResponse(body, ray)`.

### VM Infrastructure
- VM class extraction (class with a `run` method containing a dispatch
  loop).
- Constructor evaluation (field initialization).
- Layout recovery (PC register, key register, etc.).
- Opcode decoding (XOR-based with rolling key).
- Symbolic expression evaluator (~1000 lines, handles all AST node
  types).
- Disassembler with worklist traversal.
- Dispatch loop evaluation, path explorer, logical operators.

### API Server (turnpass-x)
- FlareSolverr-compatible HTTP API (`/v1`, `/v2` endpoints).
- Session management with TTL and cookie jars.
- Request validation middleware.
- pflag v1.1.0 CLI with 12 flags.

### Build and Test
- Go 1.27, all 21 packages pass `gofmt`, `go vet`, `go test ./...`.
- 44+ commits on `dev` branch.
- Profile: safari-26-ios (from cfsolve) included for testing.

## What Doesn't Work Yet (Critical Path to HTTP 200)

### 1. Payload Template Extraction (Blocking)
The orchestrator POST payload must match the template defined in the
orchestrator JS. The template is an `ObjectExpression` with many
properties, where each property's value is an expression that reads from
`_cf_chl_opt` (using obfuscated property names).

**Current state**: The solver sends a minimal JSON of `_cf_chl_opt`
standard-name values, which the server rejects with HTTP 400.

**What's needed**:
- Find the payload template `ObjectExpression` in the orchestrator AST
  (cfsolve's `is_payload_template`: object with > N properties, at least
  one field reading a challenge-type option).
- Extract each field's name and expression.
- Evaluate each expression against the `_cf_chl_opt` values (requires
  the obfuscated-to-standard property name mapping).

### 2. 16-Byte Key Secret (Blocking)
The symmetric key for XTEA encryption is derived from a 16-byte secret
that the VM's initial program installs via `window[name] = factory(secret)`.
The secret is a string constant computed by the VM at runtime (sliced
from a length-prefixed constant).

**Current state**: The regex fallback finds false-positive 16-char strings
(like "Noto Color Emoji"). The real secret requires VM execution.

**What's needed**:
- Decode the base64 initial VM program (27488 bytes → 20614 bytes of
  bytecode).
- Disassemble the bytecode using the VM class (the `n2` class in current
  builds, which has only a constructor — the run function `a` is
  standalone, not a method).
- Symbolically execute the initial program, tracking
  `window[NAME] = factory("constant")` patterns.
- The `NAME` that matches the key transform is the key secret's property
  name; the `constant` is the 16-byte secret string.

### 3. Key Transform Name (Blocking)
The key transform is the VM-installed function that the encoder calls.
In current builds, it's accessed via a property lookup
(`He = H3["_0xe620"]`) rather than a direct global call.

**Current state**: `findKeyTransform` looks for unbound global function
calls in the encoder's body, but all calls are to declared functions.

**What's needed**: Trace property lookups like `VAR = OBJ["NAME"]` in the
encoder's enclosing IIFE, where `VAR` is called as a function in the
encoder body. The `NAME` is the key transform name (which maps to the
secret in `installed.built`).

### 4. VM Class Extraction for Orchestrator (Blocking)
The orchestrator's VM class (`n2`/`OP`) has only a constructor, not a `run`
method. The run function (`S9`/`Ep`/`a`) is a standalone function.

**Current state**: `FindVMByRunner` now handles this pattern — it finds the
VM class and run function by name using runner info from the encoder
extraction. Validated: both are found in live orchestrators.

**However**, the dispatch loop in current Cloudflare builds uses a different
pattern than cfsolve expects:
- cfsolve expects: `while(true){ switch(opcode^key){ case N: handler(); } }`
  with byte-sized opcodes (0-255) and a flat switch.
- Current Cloudflare uses: `for(;;){ if(opcode===0){ OU(...) } else try{ tgb(opcode_id, ...) }catch{...} }`
  where `tgb` is a **tree-based recursive dispatcher** with only 2 cases per
  call level. Each case may call `tgb` again with a different opcode ID,
  creating a multi-level dispatch tree.

This is a fundamentally different VM architecture. The `tgb` function has
`switch(opcode_id ^ _0xdaff32)` with only 2 numeric cases (1206955360 and
1477991615), and each case recurses into `tgb` with a new opcode ID. The
opcode is not a single byte — it's a multi-level path through the dispatch
tree.

**What's needed**: A new VM interpreter that can handle the tree-based
dispatch pattern. This requires:
- Decoding the dispatch tree from the `tgb` function's switch cases.
- Following recursive calls to build the full opcode → handler mapping.
- Interpreting opcodes as paths through the tree, not single bytes.
- This is a significant architectural change from cfsolve's flat dispatch.

### 5. VM Program Execution (Blocking)
Executing the orchestrator's response VM program to get the iframe URL
requires the full VM: handler execution, register masking, path
exploration.

**Current state**: The VM has a disassembler and symbolic evaluator, but
they haven't been validated against real Cloudflare VM programs.

### 6. Probe Answer Replay
After the initial POST, the server sends probe questions. The answers
come from the profile's `answers.json` (23 probes, 34 globals).

**Current state**: The answers loading infrastructure exists, but the
probe POST flow (matching probe IDs to answers, building the probe
payload) is not wired.

## Live Test Results (nopecha.com/captcha/cloudflare)

```
$ turnpass --url https://nopecha.com/captcha/cloudflare \
    --profile profiles/safari-26-ios.json --mode challenge --verbose

navigating to https://nopecha.com/captcha/cloudflare
got 403 (5684 bytes)
detected 5s challenge (status 403)
orchestrator script: 627850 bytes
deobfuscated: 627850 -> 464715 bytes
encoder params: alphabet 64 chars, modulus 1024 bits, runner found,
                encoder "u8", initialProgram 27488 bytes
orchestrator POST URL: .../h/b/fo/<id>:<ts>:<nonce>/<ray>/<token>
POST returned HTTP 400; 121 bytes
response: {"d":"<encrypted>"}
```

The HTTP 400 with an encrypted response body confirms the server is
processing the POST. The 400 is expected because:
1. The payload doesn't match the template (wrong field names/values).
2. The 16-byte secret is incorrect (causing the codec to produce
   garbage that the server can't decrypt).

## Architecture Summary

```
turnpass (CLI)
├── internal/browserprofile  — profile loading (cfsolve profiles/ format)
├── internal/transport       — uTLS + HTTP/2 + proxy
├── internal/cookies         — RFC 6265 cookie jar
├── internal/protocol        — challenge detection (5s/10s/Turnstile)
├── internal/challenge       — page parsing, encoder extraction, POST URL
├── internal/deobfuscate     — string decoder, constant folding, inlining
├── internal/codec           — XTEA, RSA, DEFLATE, base64, response mask
├── internal/vm              — class extraction, disassembler, evaluator
├── internal/answers         — probe answer loading
├── internal/extraparams     — timeline, widget params, page signals
├── internal/payload         — payload construction (partial)
├── internal/solver          — orchestration, POST, solve flow
├── internal/errors          — error categories with retry semantics
└── internal/fingerprint     — profile JSON parsing

turnpass-x (API server)
├── api/types      — FlareSolverr types
├── api/sessions   — session manager
├── api/handlers   — request handlers
├── api/middleware — validation
└── api/server     — HTTP server
```
