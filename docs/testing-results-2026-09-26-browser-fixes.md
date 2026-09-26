# Chrome UAT follow-up — 2026-09-26

The operator reported visible `REDACTED` labels, a broken redirect to `target-001.local`, a WebSocket failure and an upstream error. This local batch follows `521f044`; no push or remote CI run occurred.

## Changes and observations

- Functional identity values now use neutral, reversible `[v:<hex>]` aliases. Ordinary paranoid HTML prose remains verse/lorem. Literal application text using the former marker is retained; generated aliases and escape syntax are not reprocessed by subsequent configured-identity patterns. Digest collisions cannot overwrite inverse mappings. HTTP and WebSocket disclosure headers say `X-Blinder-View: transformed`.
- Absolute same-upstream response locations now keep the validated entry hostname. A visitor on `127.0.0.1` stays there instead of switching to an unresolved alias and losing host-only cookies. This occurs when headers are emitted, including cache and SRI paths, without storing one visitor's hostname in shared cache entries. Other upstream origins remain distinct.
- In Chrome, a fresh page visibly received `[v:956cee] live`. Login succeeded, and the absolute redirect returned to `/account` on `127.0.0.1` with the same session. The capture confirms the 302 followed by an authenticated 200.
- The originally reported WebSocket failure was not reproduced. The synthetic target previously sent a single message and then remained silent. It now sends control-frame heartbeats every 20 seconds, and the page reports close codes. The proxy's idle policy is unchanged; this is fixture hardening, not a claim that the original failure's cause was proven.
- `/unsupported` deliberately labels plain bytes as Brotli. Its generic 502 is the expected negative-test result. The route and PDF-placeholder link now carry explicit expected-result tooltips that survive prose masking.

## Verification

`go test -race -count=1 ./...` passed **699 top-level tests across 16 tested packages**; five opt-in browser tests skipped in that command. The separate tagged functional suite passed all **12 top-level tests**. Vet with functional tags and the static binary build passed. Browser interaction used Chrome's native UI; no certificate warning was bypassed by the agent.

A separate client verified the running WebSocket's certificate against the exported public certificate, received HTTP 101 and `[v:956cee] live`, and completed two server-ping/client-pong exchanges over 40 seconds. This proves the tested live relay and heartbeat path; the original reported failure's cause remains unconfirmed.

The served homepage had **1,110 original decoded bytes and 1,110 rewritten bytes**, with `Content-Length: 1110`, `X-Blinder-Body-Size-Match: exact` and `X-Blinder-View: transformed`. This is one measured fixture, not a universal exact-size claim.

The running test environment retains the certificate fingerprint `e67f6548a29e05e09c24269f0ed57a7bcbb5e28ffb381c487ac6214a368a68e3`. The operator can load it in Chrome; the in-app browser still rejects it. Platform verification succeeds for `127.0.0.1` and fails for the separate operator hostname. Client and operator-host trust acceptance therefore remain open.

Local evidence is under this task's `blinder-browser-fixes-2026-09-26` artifact directory. The tested source digest is `5da99cde5e81b1def92b22d33e53112dd8e3056cdab069dee39d408f53b73daa`; the binary SHA-256 is `a9c8cecf8411145c4e18a24f71e68f1dfc8575645f618ea235e33006f9b0400a`. The UAT processes use `/private/tmp/blinder-browser-corrected` and `/private/tmp/blinder-target-corrected`; the existing local address is unchanged.

An isolated Tor 0.4.9.8 attempt remained at 5% bootstrap for 90 seconds and was stopped cleanly. No direct fallback or public-target request occurred. Live exit/onion acceptance, real-provider CAPTCHA acceptance and the other open gates in the [preceding report](testing-results-2026-09-26-acceptance.md) remain unresolved.
