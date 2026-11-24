# turnpass documentation

This branch holds the project documentation for [turnpass](https://github.com/cestrenium/turnpass),
independent of the `dev` and `main` branches.

## Documents

| Document | Purpose |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | High-level architecture of turnpass and turnpass-x. |
| [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) | Findings from analysing cfsolve's Rust source. |
| [PROTOCOL.md](PROTOCOL.md) | The Cloudflare challenge and Turnstile protocol. |
| [FINGERPRINTS.md](FINGERPRINTS.md) | Browser profile JSON format and recorded answers. |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Go implementation plan and milestones. |
| [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) | What works, what does not, and why. |
| [API.md](API.md) | FlareSolverr-compatible API reference. |
| [CONFIGURATION.md](CONFIGURATION.md) | CLI flags and configuration reference. |
| [BUILDING.md](BUILDING.md) | Build instructions for both executables. |
| [TESTING.md](TESTING.md) | Testing guide and integration test plan. |

## Status

turnpass is an in-progress native Go reimplementation of
[cfsolve](https://github.com/chris124567/cfsolve). The core transport
(uTLS fingerprinting, proxy support, cookie jar), challenge detection,
Turnstile widget discovery, the FlareSolverr-compatible API server, and
both CLIs are implemented and tested. The challenge-program VM (the
obfuscated JS interpreter that produces probe answers) is the largest
remaining piece and is being ported incrementally.

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for details.
