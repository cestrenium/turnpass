# turnpass

Native Go reimplementation of [cfsolve](https://github.com/chris124567/cfsolve), a
request-based Cloudflare challenge and Turnstile solver, plus a
FlareSolverr-compatible HTTP API server.

This repository produces two executables from a single module:

| Executable | Purpose |
| --- | --- |
| `turnpass` | Core solver CLI. Solves Cloudflare Turnstile widgets and clears Cloudflare challenge pages without a headless browser. |
| `turnpass-x` | FlareSolverr-compatible HTTP API server built on top of the `turnpass` solver engine. |

## Branch layout

| Branch | Purpose |
| --- | --- |
| `dev` | Primary development branch. All implementation lives here. |
| `main` | Reserved for the future v1 release. Holds only GitHub Actions workflows and release infrastructure. |
| `docs` | Orphan branch holding project documentation, independent of `dev` and `main`. |

See the `docs` branch for architecture, protocol, fingerprint and API reference
material.

## Status

This is an in-progress reimplementation. See `KNOWN_LIMITATIONS.md` on the
`docs` branch for the current set of verified versus unverified features. The
Cloudflare challenge program VM (the obfuscated JS interpreter that produces
probe answers) is the largest single piece of cfsolve and is being ported
incrementally; until it is complete, only Turnstile widget discovery, sitekey
extraction, challenge detection, transport fingerprinting and the
FlareSolverr-compatible API are fully functional.

## Building

Requires Go 1.27 or newer.

```sh
go build ./cmd/turnpass
go build ./cmd/turnpass-x
```

## License

MIT. See `LICENSE`.
