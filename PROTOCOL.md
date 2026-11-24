# Cloudflare Challenge Protocol

This document describes the Cloudflare challenge protocol as understood
from cfsolve's source code and recorded responses.

## Challenge types

| Type | HTTP Status | Indicators | Description |
| --- | --- | --- | --- |
| 5s | 403/503 | `<title>Just a moment`, `cf-chl-bypass`, `challenge-form` | Basic JavaScript challenge. |
| 10s (managed) | 403/503 | `cf-mitigated` header, `.cf-turnstile` widget | Turnstile-protected managed challenge. |
| Turnstile widget | 200 | `.cf-turnstile` div, `turnstile.render()` | Embedded Turnstile widget on a normal page. |

## Detection logic

turnpass's `protocol.detectChallenge` checks, in order:

1. Title contains "Just a moment" or "Checking your browser".
2. HTML contains `cf-chl-bypass`.
3. HTML contains `id="challenge-form"` or `name="cf-chl`.
4. If any of the above AND the page contains a Turnstile widget or
   `cf-mitigated`/`managed_chl` markers → **10s challenge**.
5. If any of the above without Turnstile → **5s challenge**.
6. Status 403/503 with `cf-mitigated` header → **10s challenge**.
7. Page contains a Turnstile widget → **Turnstile widget** (not a
   challenge page).
8. Otherwise → **no challenge**.

## Turnstile widget discovery

Widgets are discovered from static HTML (no JavaScript execution):

1. `<div class="cf-turnstile" data-sitekey="...">` containers.
2. `data-sitekey` attributes anywhere in the HTML.
3. `turnstile.render(elem, {sitekey:..., action:..., cdata:...})` calls.

The `sitekey`, `action`, and `cdata` are extracted from render calls.
Widgets are deduplicated by sitekey.

## Challenge flow (cfsolve)

The full challenge solving flow in cfsolve is:

1. **Navigate** to the target URL. The response may be:
   - The protected page (no challenge).
   - A 5s challenge page (JS challenge).
   - A 10s challenge page (managed, Turnstile-protected).

2. **Fetch the Turnstile iframe** from `challenges.cloudflare.com`.
   The iframe URL is extracted from the challenge page.

3. **Fetch the orchestrator script**. This is the obfuscated
   JavaScript program that runs in the iframe.

4. **Deobfuscate** the orchestrator script using AST analysis.

5. **Execute** the deobfuscated program in the VM. The program:
   - Collects browser fingerprints (probes).
   - Builds a proof-of-work payload.
   - Measures timing for anti-bot heuristics.

6. **POST the payload** to the orchestrator endpoint:
   - URL: `https://challenges.cloudflare.com/...`
   - Headers: `cf-chl`, `cf-chl-ra: 0`, `content-type: text/plain`
   - Body: encoded payload with probe answers and proof.

7. **Process the response**:
   - For Turnstile: the response contains the token.
   - For challenge pages: the response sets `cf_clearance` cookie and
     redirects to the protected page.

8. **Verify** the clearance by following the redirect.

## Recorded answers

The profile's `answers.json` (186 KB) contains pre-recorded probe
answers for a specific browser. These include:

- `navigator`: hardwareConcurrency, userAgent, deviceMemory, languages.
- `media`: RTCReceiverCapabilities (audio/video codecs), ICE candidates,
  SDP.
- `proof_worker`: digest timings, startup timings.
- `benchmark_worker`: compile timings, kernel timings.
- Probe durations for 37 categories.

The VM replays these answers in the challenge program's payload. The
answers must be consistent with the transport's User-Agent and TLS
fingerprint.

## What turnpass implements

turnpass implements steps 1–3 (navigate, detect, discover widgets) and
the HTTP transport layer. Steps 4–8 (deobfuscate, execute VM, POST
payload, process response, verify) require the challenge-program VM,
which is being ported incrementally.
