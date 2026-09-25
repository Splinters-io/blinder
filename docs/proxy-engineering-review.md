# Proxy engineering lessons for Blinder

**Follow-up:** this review is a historical snapshot. The subsequent working tree fixes the three reproduced acceptance defects, bounds all HAR bodies, corrects replacement MIME and records actual HTTP replacement counts. See [current status](capabilities.md) and the [test report](testing-results-2026-09-23.md) for delivered work and remaining gates.

Reviewed 2026-09-23. Public upstream source: [`kgretzky/evilginx2` at `4c0988a1`](https://github.com/kgretzky/evilginx2/tree/4c0988a1d9db4d172a185e979a38bfd0efdb5830). Blinder baseline: `34eb0a07501d7de8c857e3fffaa7c601b887aa0b`, plus the current uncommitted certificate-preflight, functional-test and documentation changes.

This is a static comparison of transport, URL mapping, cookies, certificates and lifecycle code. Upstream was read in a temporary checkout, not built or executed. Attack workflows, lures, credential collection and injection features are excluded. No upstream code was imported and no Blinder runtime code changed in this review.

The main lesson is that an alias must be part of a consistent routing model. Text replacement alone cannot preserve a browser application's behavior. Blinder also needs to make every loss of fidelity visible to the operator, because its output is used to assess the target.

## What transfers, and where

| Priority | Blinder gap | Useful direction | Acceptance evidence |
| --- | --- | --- | --- |
| P1, next fix | Browser Origin/Referer mismatch | Parse complete origins and translate only registered client origins | Existing failing browser-form test passes; unrelated and deliberately invalid origins remain unchanged |
| P1, architecture | Aliases exist without complete multi-origin routing | One explicit route table shared by HTTP, WebSocket, URL rewriting and certificate preparation | A synthetic two-origin application works without contacting original hosts directly |
| P1, alongside routing | Cookie scope collapses at loopback | Structured cookies plus explicit origin/site relationships | Same-name cookies, host-only cookies, deletion, prefixes and SameSite behavior remain distinguishable |
| P1, privacy boundary | Tor covers proxy transport, not all possible browser egress | Centralize upstream dialing and verify browser network containment separately | Existing SOCKS tests stay green; direct resource/fetch/WS attempts are observed or prevented in browser UAT |
| P2, fidelity | Broad rewriting and inconsistent binary replacement | Context-aware transformations with explicit unsupported outcomes | MIME, encoding, parsing and security-control checks compare direct versus proxied behavior |
| P1, delivery | Missing evidence can still return success | Accurate per-request outcomes, bounded capture and reliable exit status | Existing artifact-failure tests pass; failed/WS requests appear in evidence |

These are proposed priorities for Blinder, not claims that upstream solves each problem.

## 1. Map complete origins before adding more rewrite rules

Upstream parses Origin/Referer and has paired host-mapping functions. [Header handling](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/http_proxy.go#L616-L650), [mapping functions](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/http_proxy.go#L1708-L1770).

Blinder's [`RewriteRequestHeaders`](../internal/rewriter/headers.go) substitutes the alias string. A browser arriving at `https://127.0.0.1:<port>` does not send that alias. This explains the recorded 403 in `TestAcceptanceBrowserOriginForm`.

Introduce a shared origin mapper with explicit client and upstream scheme, hostname and effective port. Use it for HTTP and WebSocket request headers, redirects and URL-valued response headers. Keep it separate from identity-token scrubbing. The current upstream implementation replaces hosts; it is a design reference, not a complete solution for Blinder's scheme/port problem.

Test HTTPS loopback to HTTP upstream, custom ports, IPv6, default-port equivalence and alias entry URLs. Preserve Referer path/query bytes where possible. Leave `null`, unrelated origins and invalid scanner inputs untouched; never make every incoming Origin equal the target. Lookalikes and occurrences of an alias inside a path/query must not become a recognized origin. Map CORS origins without changing whether credentials are allowed.

## 2. Give aliases an explicit route and browser origin

Upstream connects configured host pairs to TLS hostname selection and a DNS component. [Hostname dispatch](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/http_proxy.go#L1611-L1663), [DNS component](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/nameserver.go#L23-L96).

In Blinder, [`AliasDomain`](../internal/scrub/domains.go) creates names, but [`handleRequest`](../internal/proxy/proxy.go) sends every ordinary request to the single configured target. Alias generation does not provide DNS, certificate coverage or distinct upstream routing. Absolute links can therefore become unusable even when the visible identity is successfully scrubbed.

Build an operator-configured route table with a stable route ID, original origin, client origin and transport policy. Derive URL mapping, local name resolution, certificate SANs and dispatch from that table. Reject unknown routes. Discovery may suggest dependencies; it must not automatically authorize newly discovered destinations. Keep local resolution separate from upstream resolution through Tor.

A two-origin fixture should include redirects, relative and absolute links, a JSON URL, an API call and a WebSocket. Every allowed URL must resolve to the intended route, and an unknown alias must never become an arbitrary upstream connection. Where URL-valued fields need reverse mapping on submission, scope that operation explicitly; do not rewrite arbitrary form values, opaque tokens or signed query strings.

Browser origins and browser sites need separate consideration. Moving originally separate sites beneath one alias suffix can change SameSite behavior even if their origins remain distinct. Document what topology the first implementation supports and report the rest as a fidelity limitation.

## 3. Treat cookies as scoped protocol state

Upstream uses parsed response cookies and rewrites their domains. [Cookie handling](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/http_proxy.go#L963-L1008).

Blinder currently splits Set-Cookie strings, removes Domain and aliases names using only the original name. That supports the single-loopback fixture but does not preserve multi-origin cookie scope. Aliasing every name also removes recognizable `__Host-` and `__Secure-` prefixes; this is a code-derived fidelity concern requiring browser verification.

Use parsed attributes with a deliberate policy for malformed or unknown attributes, and preserve the distinction between host-only and domain cookies. The routing/cookie model must account for original host, domain, path and name without incorrectly separating cookies that were intentionally shared. Retain Secure, HttpOnly, SameSite, expiry and deletion behavior; preserve prefix constraints or explicitly report their loss.

Test two origins with the same cookie name, path variants, domain sharing, logout/deletion and browser rejection of invalid prefixed cookies. Keep values opaque for protocol fidelity unless a separate policy explicitly handles their privacy implications. Rewriting the name does not anonymize the value.

## 4. Make fidelity a measurable result of rewriting

Upstream scopes some response transformations by host and MIME, but still uses regular expressions and whole-body reads. [Filter selection](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/http_proxy.go#L1090-L1162), [body read](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/http_proxy.go#L1014-L1015).

Blinder should retain its current decompressed-body limits and build on its content-type dispatch. Use structured URL handling, HTML tokenization and grammar-aware JSON/JS handling where needed. Optional compatibility rules should have explicit host/path/MIME scope and observable outcomes. This repository does not provide a general solution for encoded or dynamically assembled identities.

Extend `BodyResult` to describe the actual output media type and transformation outcome. Today [`rewriteBinaryImage`](../internal/rewriter/binary.go) returns GIF bytes for documents and fonts while the response retains its original Content-Type. Choose an explicit replacement or refusal policy per media family and record the lost functionality.

Preserved security metadata also needs validation against rewritten bytes. CSP hashes, subresource integrity and cache validators may cease to describe the delivered content. These are follow-up test targets, not newly executed reproductions. Distinguish intended target behavior from a limitation introduced by Blinder rather than silently weakening controls to make the page work.

Use paired direct/proxied fixtures: the configured identity changes, while method, status, form behavior, CORS decisions, cookie constraints and supported data types remain consistent. Test integrity-protected scripts/styles, charset/escaping cases, gzip limits, unknown binary content and unsupported encodings explicitly.

## 5. Keep Tor and local certificate setup independent

Upstream disables its configured proxy when setup fails, and a certificate helper makes a direct TLS connection. [Proxy initialization](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/http_proxy.go#L133-L140), [certificate connection](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/certdb.go#L258-L269).

For Blinder, every future upstream probe, metadata fetch and HTTP/WS connection must use the selected transport policy. A Tor failure must remain a failure. Local certificate preparation should remain offline. Keep remote hostname resolution, cancellation and deadlines explicit; do not introduce a direct helper connection while improving preflight.

The current eight deterministic SOCKS scenarios are valuable evidence. They do not establish browser-wide containment: [`safeDomains`](../internal/scrub/domains.go) permits some original references to remain, and dynamic script requests can also escape textual rewriting. This is a code-derived exposure path, not a packet-capture result. Add browser network-observation tests for resources, fetch and WebSockets, plus a controlled browser/network environment when egress containment is required. Rewriting is not a substitute for that boundary.

Successful live Tor and onion UAT remains outstanding. Preserve that status until a bootstrapped service produces successful, recorded requests. An optional connectivity check should be explicit about which destination it contacts.

Upstream also separates certificate storage/management from serving. [Certificate manager](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/certdb.go#L25-L62). Blinder already has persistent leaf certificates, reuse/renewal and explicit user trust in the working tree. Finish OS/browser acceptance of that design; public ACME and an additional signing CA are not needed for the present loopback workflow. Alias expansion will require revalidating SAN coverage and the scope of installed trust.

## 6. Close the existing delivery gaps before expanding scope

The [recorded functional baseline](testing-results-2026-09-23.md) remains the acceptance gate: 25 passing and four failing working-tree scenarios, representing three defects. This review did not rerun or change those tests.

Fix Origin mapping, return nonzero promptly after listener failure, and attempt all requested artifact writes while returning nonzero if any fail. Only announce readiness after a successful bind. Add the full tagged functional suite to CI once those acceptance failures are corrected; do not skip them to obtain a green result.

The next evidence work belongs to Blinder's own design. [`handleRequest`](../internal/proxy/proxy.go) records hard-coded per-request scrub/leak counts, omits failed requests from the manifest and returns early for WebSocket upgrades. [`har.Writer`](../internal/har/har.go) retains the session in memory, and its response-body cap only applies to binary content.

Record actual request outcomes and transformation reasons, including failures and WS upgrades. Bound text, binary and aggregate capture; make truncation visible. Consider an incremental journal with final HAR export for long sessions. Preserve original evidence for the operator while reporting what was changed, refused or not examined to the consumer of scrubbed output. Do not label detected-and-replaced matches as proof that no identity remains.

## Behaviors to leave behind

Upstream removes CSP and other security headers, forces credentialed CORS in a branch, and changes Secure cookies to SameSite=None. [Response policy changes](https://github.com/kgretzky/evilginx2/blob/4c0988a1d9db4d172a185e979a38bfd0efdb5830/core/http_proxy.go#L913-L970). Those behaviors would alter the security properties Blinder is supposed to help inspect. The useful contribution is the explicit mapping structure; protocol weakening is not a compatibility fix for this project.

## Suggested implementation order

1. Close the three reproduced acceptance defects and enable the functional CI gate.
2. Introduce the shared origin mapper with HTTP/WS and negative-case tests.
3. Implement a bounded two-origin routing fixture, including cookies, resolution, certificate coverage and browser egress observations.
4. Add transformation outcomes, correct replacement MIME, accurate evidence and bounded capture.
5. Complete browser/scanner, OS trust and successful live Tor/onion UAT against the documented boundaries.

Steps 2–5 are proposed work, not delivered features. The first Origin fix may introduce the mapper incrementally; it does not need to wait for full multi-origin support.
