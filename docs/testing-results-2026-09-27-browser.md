# Chrome acceptance — 2026-09-27

Local work following `d6c6b42`. Chrome was used through the connected browser extension. No GitHub push, live-listener replacement, certificate installation, or browser-security change occurred. All CAPTCHA challenges in this batch were synthetic; no real CAPTCHA was solved.

## Browser results

| Check | Result |
| --- | --- |
| Application behavior | 15 direct/proxy pairs passed: JavaScript navigation, raster loading/failure/dimensions, and malformed HTML behavior. |
| Inline CSP | 20 direct/proxy pairs passed. |
| External CSP/SRI | 29 direct/proxy pairs passed. |
| Provider control matrix | Seven direct/proxy pairs passed after the CAPTCHA changes, including script allow/deny, real CORS preflight decisions, visible HTTP 500 diagnostics, and provider-frame isolation. |
| Positive provider baseline | Direct, stateless provider completed all 13 requests and returned the exact synthetic token. |
| Positive operator flow | All 13 provider requests matched relay requests. Dynamic scripts/frames, fetch, XHR, and extension methods completed. Native submission displayed **Solution submitted**; the original POST returned 200 with its username, target session cookies, refreshed CSRF, and exact solution token. |
| Raw challenge isolation | Before producing its solution field, the actual challenge observed `SecurityError` on parent DOM access and could not read an operator fetch response. The server independently recorded that probe returning 403. Completion still succeeded. |
| Cookie denial | Direct and proxy both exposed `Error: POST 400` for a provider requiring a cross-site Lax cookie. All six proxy requests used the relay; no opaque-origin preflight was introduced. |
| Operator isolation | An active target service worker, cross-origin fetches, iframes and an authenticated popup could not read/control operator content. Positive worker and popup controls passed. |

The first 64 pairs ran at `d6c6b42`, before this CAPTCHA implementation. The later provider and isolation checks exercised the local changes. These are separate observations, not a claim that every earlier browser fixture was rerun against the final tree.

## What the initial failure established

The first current-origin CAPTCHA attempt timed out. Two dynamically created provider resources went directly to the original provider, while an opaque `srcdoc` sandbox changed a same-origin JSON POST into an `Origin: null` preflight and a fetch error.

The fixture also required a cookie that Chrome correctly withheld even when accessing the original target/provider directly. That direct run exposed HTTP 400, so making the proxy force that cookie would have changed the upstream control. The maintained fixture now separates a valid stateless completion profile from the unchanged cross-site Lax denial. Failure evidence is retained alongside the passing comparisons.

## Implementation verified

Raw challenges now use a separate origin per challenge, an expiring private view capability, and active-request binding. Operator credentials stay on the operator origin. Completion messages require the exact child origin/window, challenge and configured fields. Original response policies are copied immutably; no CSP permission is added for the completion bridge.

Provider documents without CSP receive a bounded URL-routing helper. Provider script bytes and integrity attributes stay unchanged. Policy-bearing, unsupported-encoding and BOM documents receive no helper. Actual decoded/output sizes and transformation provenance remain visible; helper insertion can increase body size.

Challenge navigation/report headers use registered destinations. Unknown destinations, unsupported syntax, and nonempty `Link` or `Alt-Svc` fail the private view before headers/body are replayed. Original evidence remains in the queue. Invalid JSON `null` report URLs are rejected rather than repaired into a valid endpoint. Certificate planning includes the challenge wildcard, with independent hostname trust advice.

## Local verification and runtime

- Full race suite: 953 top-level tests and 1,229 subtests passed across 19 packages; ten opt-in tests skipped in that command. Explicit browser results are listed above.
- Tagged functional suite: 12 top-level tests and 26 subtests passed, including deterministic SOCKS/Tor transport checks.
- The final report-URL null guard passed the affected challenge regressions after the full suite. Static checks and a separate local build are recorded with the evidence.
- An intermediate full-suite attempt hit the temporary callback-signature mismatch during integration; the corrected full run passed. Both logs are retained.
- The actual listener on `127.0.0.1:8099` remains PID 71413, executable `/Users/carroll/blinder/blinder`, revision `20f7ef5`, binary SHA-256 `aae1dfe8a7719b340c3f5065d8647ddc299d8f151180f9d468877314300816f5`. These source changes are not serving there.

Source digest for the final Go/JavaScript/module inputs: `659fc0e5f94420d05f421888775d4d5d3179ac5811db5fdc2e2d8d4f2ddd41d7`. The local artifact directory is `blinder-browser-acceptance-2026-09-27`; it contains browser JSON/logs, initial failures, test JSONL, and a per-file source/runtime record. Completion receipts were observed in Chrome. Follow-up cleanup/completion navigation sometimes displayed `ERR_BLOCKED_BY_CLIENT`; no bypass was attempted, and successful cleanup rendering is not claimed.

## Still open

The helper does not cover HTML parsing sinks, workers, dynamic imports, CSS or every dynamically assembled URL; unknown origins remain unchanged. The 13-request pass therefore does not establish general browser network containment. Provider bodies also need wider archival/evidence integration.

CSP-protected completion remains open. The bridge deliberately receives no new policy permission; moving a raw challenge also changes what `'self'` means when target resources use a different alias. Framing denials remain enforced. A faithful solution needs origin-aware execution and resource routing, not permissive CSP additions. Upstream SameSite/sibling-domain relationships, selected real-provider completion, and actual HTTPS trust for provider/challenge aliases need further acceptance.

Tor started normally and opened a private SOCKS listener, but reached only 5% bootstrap in 90 seconds. The log gives no specific cause. The process was stopped cleanly without target requests; no working Tor listener was subsequently visible. Live Tor exit and authorized onion-service acceptance remain untested.
