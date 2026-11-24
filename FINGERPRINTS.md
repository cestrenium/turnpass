# Browser Fingerprints

## Profile JSON format

turnpass accepts cfsolve-compatible browser profile JSON files. The
format is designed to be forward-compatible: unknown keys are ignored.

### Top-level sections

```json
{
  "engine": "webkit",
  "transport": { ... },
  "browser": { ... },
  "timeline": { ... },
  "intervals": { ... },
  "orchestrator": { ... },
  "resource_timing": { ... },
  "interaction": { ... },
  "second": { ... },
  "answers": "safari-26-ios/answers.json",
  "challenge_page_answers": "safari-26-ios/challenge-page-answers.json"
}
```

### engine

`"chromium"` or `"webkit"`. Determines:
- uTLS ClientHello preset (Chrome vs iOS).
- Stack trace format (V8 vs JavaScriptCore).
- Referrer handling.

### transport

```json
{
  "profile": "safari_ios_26.2",
  "platform": "ios",
  "headers": {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 ...)"
  },
  "requests": {
    "headers": {
      "navigation": ["sec-fetch-dest: document", "user-agent", ...],
      "iframe": ["sec-fetch-dest: iframe", "user-agent", "referer", ...],
      "script": [...],
      "orchestrator_post": [...],
      "challenge_post": [...],
      ...
    }
  }
}
```

Each request kind has an explicit header order. `"user-agent"` is a
placeholder filled from `headers["User-Agent"]`. `"referer"`,
`"origin"`, `"content-length"`, and `"cf-chl"` are filled dynamically.

### browser

```json
{
  "inner_width": 375,
  "inner_height": 553,
  "challenge_page": {"top": 378, "left": 16, "right": 359}
}
```

### timeline / intervals / orchestrator

Timing schedules for the challenge flow. Parsed as `json.RawMessage` and
passed through to the solver.

### interaction

```json
{
  "width": 300,
  "height": 65,
  "checkbox": {"x": 9, "y": 20.5, "width": 168.125, "height": 24},
  "ready_delay_ms": 1000,
  "device_pixel_ratio": 2,
  "touch": true
}
```

### second

The second-stage probe configuration. Contains:
- `facts`: navigator, media (codecs, RTC), proof_worker, benchmark_worker.
- `document`: shadow_root.
- `image`: effective_type, online.
- `durations`: per-probe timings (37 categories).
- `startup_ms`, `pending_ms`.

### answers / challenge_page_answers

Paths to recorded probe answer files, relative to the profile file's
directory. These files are large (186 KB) and contain the pre-recorded
browser fingerprint data that the challenge-program VM replays.

## uTLS mapping

| engine | uTLS preset | Notes |
| --- | --- | --- |
| chromium | `HelloChrome_Auto` | Tracks recent Chrome versions. |
| webkit | `HelloIOS_Auto` | Tracks recent iOS versions. |

## Validation

turnpass validates the following before any network access:
- `engine` is present and is `chromium` or `webkit`.
- `transport.profile` is present.
- `transport.platform` is present.
- `transport.requests.headers` is present and non-empty.
- Every request kind lists `user-agent`.
- `timeline`, `intervals`, `orchestrator`, `resource_timing`,
  `interaction`, `second` are all present.

Missing or invalid fields produce a `Config` error.
