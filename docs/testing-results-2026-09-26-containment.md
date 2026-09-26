# Browser routing and reversibility — 2026-09-26

This local batch follows `eb0c395`. No push, remote CI run, trust-store change or browser-protection change occurred.

## Browser findings

Native Chrome navigation successfully displayed the reusable fixture's JSON, gzip JSON, synthetic SQLSTATE-bearing HTTP 500 and deliberately unsupported-encoding 502. The large JSON integer remained visible as `9007199254740993`; the configured product was replaced by a neutral functional alias. The earlier extension-controlled navigation errors remain recorded in the preceding report. Native navigation establishes that these pages work in this Chrome session; it does not establish the cause of `ERR_BLOCKED_BY_CLIENT` or certificate verification in other clients.

A separate local containment fixture uses reachable canary origins and a SOCKS relay that resolves those origins to a different backing server. Direct browser requests reach the canaries; properly proxied requests reach the backing server. This distinguishes successful routing from a page that merely happens to load.

The initial wire checks reproduced absolute HTML URLs selecting a canonical alias instead of the browser's entry authority, CSS/JavaScript URLs retaining upstream ports, and an issued IP authority being scrubbed a second time. The corrected browser run loaded its primary script, CSS image, fetch and WebSocket through the proxy. No direct canary requests were recorded. The fixture's restrictive upstream CSP remained enforced, with no reported policy violations.

The extra-origin request used its distinct local alias, but Chrome rejected the certificate with `ERR_CERT_AUTHORITY_INVALID`. The reused acceptance certificate covers loopback, `localhost`, `target-001.local` and the operator hostname, not this fixture's generated extra alias. The overall opt-in browser test therefore fails; its primary checks are not presented as full multi-origin acceptance. A certificate covering the intended aliases, client trust and name resolution remain necessary acceptance steps. No warning was bypassed.

## Changes

- Validated request-specific origin mapping keeps complete registered resource URLs on the browser's current entry authority. Extra origins retain separate aliases. HTML attributes/style blocks, CSS URLs/imports and complete unescaped JavaScript string/template literals share that mapping.
- Issued authorities are protected from a second identity scrub. Paths, queries and fragments retain reversible masking. CSS syntax whitespace remains outside unquoted URL data.
- Response caches and SRI representations are partitioned by browser authority. SRI prefetch selects the eventual resource authority before rewriting and hashing; credential-free extra-origin resources retain that authority in their cache keys.
- Exact registered CSP HTTP(S)/WS(S) sources follow the same mapping without adding blanket permissions. Keywords, nonces/hashes, schemes and path restrictions remain intact. Wildcard and scheme-less sources retain the previous handling; arbitrary policy parsing is not claimed.
- Certificate status reports listener, primary alias, extra aliases and configured operator hostname separately. The existing exit status and macOS trust action remain scoped to the listener, explicitly stated in the output and guide.

Independent review also reproduced a routed URL being submitted back as the local proxy URL instead of its original upstream scheme/host/port. Complete registered URL values now undergo an inverse origin mapping before alias restoration in HTTP JSON/form/query data and reassembled WebSocket text. The regressions check exact upstream values, encoded path/query spellings, JSON number precision, opaque CAPTCHA fields, newly colliding keys and unchanged malformed/plain-text behavior. Generic JSON/text/WebSocket domain aliases retain their previous round trips.

## Verification

`go test -race -count=1 ./...` passed **740 top-level tests across 16 packages**, with six opt-in browser tests skipped. The tagged functional suite passed **12 top-level tests**; vet with functional tags was clean. The opt-in browser run with strict CSP passed its primary script/fetch/WebSocket/CSS routing checks and recorded zero direct canary requests, but failed the extra-origin certificate check described above. A later browser run added an explicit JSON URL-submission round trip; Chrome automation could not execute it because the Mac was locked, and the fixture timed out. The equivalent HTTP and fragmented WebSocket regression checks passed. The operator was asked to unlock the Mac; the browser submission check remains pending rather than being counted as a pass.

After the Mac was unlocked, the same committed fixture was rerun in native Chrome. The JSON submission returned **200 `url-roundtrip-ok`**: the backing server verified the exact original URL, including scheme, hostname, port and path. Primary script, fetch, CSS image and WebSocket checks passed again, with zero direct canary requests and no reported CSP violations. This closes the pending browser submission check. The overall test still fails the extra-origin certificate acceptance case (`ERR_CERT_AUTHORITY_INVALID`); that failure was not skipped or converted to a pass. Evidence is preserved separately as `browser-unlocked.json` and `browser-unlocked.txt`.

The fixture now also supports explicit loopback listener addresses for repeatable certificate setup: proxy `127.0.0.1:18199` and extra canary `127.0.0.1:18181` produce the stable extra alias `host-a9950799.localhost`. Two additional fixture regressions cover address validation, occupied-port failure and routing the fixed extra origin through SOCKS; these and the prior containment wire checks pass with the race detector. This follow-up changes test infrastructure and documentation only. A separate certificate covering those names was prepared under `/private/tmp/blinder-containment-certs`; installing its two-host trust constraints requires operator approval. The existing acceptance certificate and running application build remain unchanged.

Logs, the source manifest and build records are retained in the task's `blinder-containment-2026-09-26` evidence directory. The source manifest SHA-256 is `5394aaa53fd498588247ce8c817ce0f3c1f573f8efd0d54de1dd34c156a56c88`; it lists Go/JS/CJS files and module files with their content hashes. Earlier browser failures remain preserved separately from later results.

## Remaining acceptance

This fixture does not establish universal containment of dynamically assembled or escaped URLs, arbitrary external references, provider scripts or binary traffic. Live Tor/onion, real-provider completion, extra-origin browser trust, and selected HAR viewer/replay retain their separate acceptance status. Loopback platform trust does not establish trust for the operator or aliases.
