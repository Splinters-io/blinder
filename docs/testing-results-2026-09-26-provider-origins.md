# CAPTCHA provider origin isolation — 26 September 2026

Chrome passed **seven direct/proxy provider comparisons**, followed by all **49 existing CSP/SRI comparisons**. Provider resources now use separate browser origins in Tor mode, preserving the tested upstream control decisions and diagnostic responses. This checkpoint is local; it has not been pushed or deployed to the existing preview.

## What changed

Each configured Tor-routed provider full origin receives a deterministic `captcha-<hash>.localhost` alias. Provider routes are separate from target routing, cookie restoration, response caching and SRI processing. Every request must satisfy the configured origin and optional resource URL regex. Provider configuration is loaded before certificate preparation so generated certificates include these aliases. No trust settings were changed during this work.

The isolated relay forwards real preflights and valid HTTP methods, preserves upstream status and body bytes, and translates corresponding CSP/CORS origins. It does not replace provider CSP with the operator policy, manufacture a CORS grant or inject a runtime into provider documents. Static HTML references, base URLs and refresh navigation are translated while script/style bytes, nonces and integrity metadata stay intact. The relay negotiates gzip/identity when HTML rewriting is enabled. Changed HTML gets an accurate Content-Length and drops invalidated representation validators. Static provider forms, links, frames and refresh destinations back to primary or extra target origins also use their local target aliases.

Provider cookies belong to their browser aliases. Exact-host Domain attributes become host-only, broader domain cookies are rejected, and operator credentials are excluded. The former `/__blinder/captcha/res` endpoint returns 404 on target and operator origins. Direct mode and explicitly direct providers retain their existing browser-direct behavior.

## Browser comparison

| Case | Matching direct/proxy result |
| --- | --- |
| Explicitly allowed provider script | Executes. |
| Provider script denied by target `script-src 'self'` | Blocked; no provider script request. |
| Allowed custom-method CORS request | Preflight and `vendor.sync` reach upstream; the browser reads the original HTTP 500 and SQL-style diagnostic body. |
| Denied preflight | Browser blocks the operation; no actual request reaches upstream. |
| Missing response ACAO | Actual request reaches upstream, but the browser denies access to its response. |
| Provider frame with permitted relative script | Script runs; access to the embedding document remains denied. |
| Provider frame with denied script | Script is blocked by the provider's own policy. |

The fixture records upstream requests separately from SOCKS connections and checks per-request routing through a local SOCKS server. Direct requests and proxied requests each have explicit expectations; merely matching two failures would not pass. The provider fixture used local HTTP origins, not a live Tor circuit. Cookie scope is separately covered by HTTP cookie-jar tests rather than this Chrome comparison.

The initial browser run caught a genuine restoration defect: generic JavaScript masking changed `vendor.sync` into an issued alias, which then failed the upstream preflight. The relay now restores issued method aliases and translates the exact corresponding preflight permission without creating a grant for a different literal method. The original failing report is retained, and the fixture still uses the original method string through the normal scrubber.

The subsequent HTTPS regressions passed all 29 external-resource CSP/SRI pairs and all 20 inline-control pairs. They reused the previously trusted loopback leaf certificate; no browser security warning was bypassed.

## Verification and evidence

- Full race suite: 833 top-level tests across 17 packages, zero failures.
- Tagged functional suite: 12 top-level tests, zero failures.
- `go vet -tags functional ./...`: clean.
- `CGO_ENABLED=0 go build -trimpath ./cmd/blinder`: successful.
- Nine browser fixtures are opt-in in the ordinary suite. Three ran separately in Chrome here; the other skips are not acceptance results.

Evidence is retained in `/Users/carroll/.codex/visualizations/2026/09/23/01a0ce57-c07e-79e0-a189-9f6c7c6023dd/blinder-provider-origins-2026-09-26`, including the initial failure, final browser reports and request counts, race/functional logs and a source manifest. Final source manifest SHA-256: `1de97afd9a0bb311e9a43c52597b295f80e73b4261006fb843515974f007ab53`. The seven provider browser pairs and all automated checks were repeated after the final static target-return and encoding-negotiation fixes; the 49 CSP/SRI pairs ran immediately before those provider-only fixes, with their earlier source manifest retained. The starting revision was `cb7ab672036a066fa33555747cf2615af4bab8e6`.

## Next acceptance work

Dynamic absolute URLs inside provider JavaScript and additional resource types still need routing work. The full synthetic operator-completion fixture predates isolation and must be adapted and rerun, followed by the selected real-provider human workflow. Provider-alias HTTPS trust, upstream SameSite/sibling-domain cookie relationships, live Tor exit/onion operation and complete browser containment remain open. These seven static comparisons do not establish universal CAPTCHA compatibility.
