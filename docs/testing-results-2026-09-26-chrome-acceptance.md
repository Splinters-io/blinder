# Chrome functional acceptance — 2026-09-26

This local batch follows `6497d58`. The Chrome extension is connected, so browser observations below come from Chrome directly. No push, remote CI run, trust-store change or browser-protection change occurred.

## Reproduced fidelity defect

HTML 4xx/5xx responses retained body diagnostics but always replaced the document title with `Transformed view`. A SQLSTATE diagnostic present only in the title disappeared. Error titles now undergo identity masking while retaining diagnostic text. Unchanged titles keep their source spelling and byte length, including entities, CRLF and incomplete markup. Ordinary page titles retain their existing neutral replacement.

Four new regression tests cover status 400/422/500/503, title-only diagnostics, configured product/domain masking, safe HTML escaping, truncated titles, gzip decoding, diagnostic headers and actual representation sizes. They failed before the change and pass afterward.

The reusable local fixture now has an `/error` link returning an upstream HTTP 500 with a synthetic SQLSTATE diagnostic. `/unsupported` remains a separate deliberately malformed-encoding test that produces a proxy-generated 502.

## Accepted checks

- Chrome login reached `/account`; the absolute redirect retained the authenticated loopback origin. The native origin-checked form submitted successfully. HAR confirmed upstream 303/200, 302/200 and form POST 200 respectively.
- The separate synthetic Chrome validation flow restored aliased textarea/select values upstream and displayed HTTP 422 diagnostics, including `E_EMAIL`, the supplied Unicode value and the title `Validation result`. Its ordinary form page retained exactly 432 decoded/emitted bytes. The error body changed from 277 to 279 bytes, correctly measured rather than padded through diagnostic text.
- New real-wire WebSocket acceptance exercises a primary HTTP origin and extra HTTP/HTTPS origins through a local TLS listener. It verifies route scheme/host/port, Origin/Referer, duplicate query values, origin-scoped cookies, fragmented masking/restoration and Close 1000 acknowledgments. A primary-origin cookie is not restored on an extra origin. Synthetic wire clients do not establish browser alias DNS or certificate trust.
- An independent TLS-verified 100-second WebSocket soak received five heartbeats at 20-second intervals, answered all five and completed Close 1000 with EOF.
- Certificate-verified HTTP checks received JSON 200 with integer `9007199254740993` intact, decoded gzip JSON 200, generic malformed-encoding 502, and SQLSTATE-bearing HTML 500 with the configured product name masked in its title/body/header. Content-Length matched every delivered body. The 500's original/revised lengths were 204/208 bytes and reported `different` accurately.

## Browser observations still unresolved

The connected Chrome tab showed `ERR_BLOCKED_BY_CLIENT` for JSON, gzip, malformed-encoding and upstream-error navigation, despite successful independent HTTP responses. The operator was asked whether manual navigation has the same result. No extension was disabled and no warning was bypassed; browser acceptance of those links is not claimed.

An existing tab also showed an isolated WebSocket close code 1006 before reloading. The independent soak did not reproduce it. The fixture closes clients silent for 45 seconds; browser/host suspension is a possible explanation, not a proven cause. The separate history-navigation fix remains verified by earlier repeated browser restores.

## Automated checks and evidence

`go test -race -count=1 ./...` passed **715 top-level tests across 16 packages**; five existing opt-in browser tests skipped in that command. The explicit Chrome validation test above passed separately. The tagged functional suite passed **12 top-level tests**, including a repeat after adding the fixture's error link. Fixture race tests passed after that final fixture edit. Vet with functional tags and static proxy/fixture builds passed.

Local evidence is under the task's `blinder-chrome-acceptance-2026-09-26` directory. Final source digest: `11b6088d08b892c60b1543e6e38f7f3672e46e7cb6bbd933ba668def99b7dd05`. Proxy binary SHA-256: `6bb6d8f448379b33b3f6971ee4fb6c374e61667089b9d064fc6687caff2dff24`. The running programs are `/private/tmp/blinder-chrome-accepted` and `/private/tmp/blinder-target-chrome-accepted`, using the existing local addresses and certificate.

Live Tor/onion, real-provider completion, broader dynamic containment, extra-origin browser trust and HAR viewer/replay retain their previously recorded open status.
