# Configuration

## turnpass CLI

```
Usage:
  turnpass [flags]

Flags:
  -u, --url string         Target page URL (required)
  -f, --profile string     Browser profile JSON file (required)
  -m, --mode string        Solve mode: auto | turnstile | challenge (default "auto")
  -k, --sitekey string     Turnstile sitekey (selects one widget when multiple exist)
  -a, --action string      Turnstile action (requires --sitekey)
  -d, --cdata string       Turnstile cData (requires --sitekey)
  -B, --blank-page         Render the widget on a blank page at --url (requires --sitekey)
  -H, --html string        Read page HTML from this file instead of navigating
  -p, --proxy string       Proxy URL (http://, https://, socks5://, socks5h://)
  -t, --timeout duration   Request timeout (default 60s)
  -C, --trusted-root string  PEM certificate file to trust instead of system roots
  -v, --verbose            Enable verbose progress output on stderr
  -D, --debug-dir string   Directory to write debugging artifacts to
  -h, --help               Show help
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Config error (invalid profile, missing required flags) |
| 2 | Network error (connection failed, timeout) |
| 3 | Unsupported (challenge-program VM not yet ported) |
| 4 | Blocked (server returned an error page) |
| 5 | Generic error |

### Examples

```bash
# Auto-detect and solve
turnpass --url https://example.com/ --profile profiles/safari-26-ios.json

# Solve a specific Turnstile widget
turnpass --url https://example.com/login \
  --profile profiles/safari-26-ios.json \
  --mode turnstile --sitekey 0xABC --action login

# Blank-page mode (sitekey only)
turnpass --url https://example.com/ \
  --profile profiles/safari-26-ios.json \
  --blank-page --sitekey 0xABC

# With proxy and verbose output
turnpass --url https://example.com/ \
  --profile profiles/safari-26-ios.json \
  --proxy socks5h://127.0.0.1:1080 --verbose
```

## turnpass-x CLI

```
Usage:
  turnpass-x [flags]

Flags:
  -H, --host string          Listening address (default "0.0.0.0")
  -p, --port int             Listening port (default 8191)
  -f, --profile string       Browser profile JSON file (required)
  -x, --proxy string         Default proxy URL for all solves
  -t, --timeout duration     Per-request timeout (default 60s)
      --read-timeout duration   HTTP read timeout (default 10s)
      --write-timeout duration  HTTP write timeout (default 60s)
      --request-timeout duration  Whole-request timeout (default 5m0s)
      --session-ttl duration    Default session TTL (default 15m0s)
  -l, --log-level string     Log level: debug | info | warn | error (default "info")
  -V, --version              Print version and exit
  -h, --help                 Show help
```

### Examples

```bash
# Start on default port 8191
turnpass-x --profile profiles/safari-26-ios.json

# Custom host and port
turnpass-x --profile profiles/safari-26-ios.json --host 127.0.0.1 --port 9000

# With default proxy
turnpass-x --profile profiles/safari-26-ios.json --proxy socks5h://127.0.0.1:1080
```

## Proxy URL formats

| Scheme | Example | Notes |
| --- | --- | --- |
| http:// | `http://proxy:8080` | HTTP CONNECT proxy. |
| https:// | `https://proxy:8443` | HTTPS CONNECT proxy. |
| socks5:// | `socks5://host:1080` | SOCKS5, local DNS. |
| socks5h:// | `socks5h://user:pass@host:1080` | SOCKS5, remote DNS. |

Credentials go in the URL: `scheme://user:pass@host:port`.
