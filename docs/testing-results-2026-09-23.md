# Testing baseline — 2026-09-23

**Current working-tree result: 29 passed, 0 failed, 0 skipped functional scenarios.** The three acceptance defects documented below are fixed locally. See [delivery follow-up](#delivery-follow-up--local-working-tree) for the changes and validation; the earlier sections preserve the original baseline.

Product revision: `34eb0a07501d7de8c857e3fffaa7c601b887aa0b`, merged main. Tests and documentation were added locally on `codex/functional-uat`; product source was unchanged. Host: macOS arm64, Go 1.26.0. The deterministic suite used synthetic loopback targets; a separate live Tor attempt is recorded below.

[GitHub CI for this exact revision](https://github.com/Splinters-io/blinder/actions/runs/35919065350) passed. Local `go test -race -count=1 -timeout 120s ./...` passed all nine existing internal packages, and vet passed. The CLI had no package tests before this work.

The completed black-box suite, including the Tor additions, produced **23 passing scenarios and 4 failing scenarios**, counting leaf tests only. The four failures represent three distinct defects. Both the test harness and the spawned CLI ran with race instrumentation; no race diagnostic was reported. Vet passed with the functional tests included, and a static CLI build also succeeded.

## Findings

| Priority | Reproduction | Observed result | Why it matters |
| --- | --- | --- | --- |
| P1 | `TestAcceptanceBrowserOriginForm` | The direct target accepts the POST; the same form sent through `https://127.0.0.1:<proxy-port>` returns 403 `origin rejected` | Normal browser form/CSRF checks break on the documented entry URL; a scanner can silently lose authenticated or state-changing coverage |
| P2 | `TestAcceptanceOccupiedPortExits` | Bind logs `address already in use`, but the CLI remains alive after three seconds and only exits when signalled | A launcher/operator can believe the service is running; readiness and automation become unreliable |
| P1 | `TestAcceptanceArtifactFailureExitsNonzero/har` and `/output` | Requested evidence cannot be written (`not a directory`); shutdown logs the error but returns exit 0 | Automation reports a successful session even though the requested evidence is missing |

Source pointers at the tested revision:

- `internal/rewriter/headers.go:159–163` only replaces the alias hostname in Origin/Referer. It does not map the actual loopback client origin, including scheme and port, to the target origin. A fix should parse and match the recognized proxy origin; it must preserve unrelated, null and deliberately adversarial origins used in security testing.
- `cmd/blinder/main.go:109–114` logs listener failure from a goroutine, while the main goroutine still waits only for a signal at line 126. Return the server failure to the process lifecycle and exit nonzero.
- `cmd/blinder/main.go:132–145` logs shutdown/flush errors but does not affect process exit status. Keep attempting all requested artifact writes and return a failure status if a required write fails.

These are reproducible operator-facing defects. They do not invalidate the prior privacy/protocol corrections, but they prevent acceptance of the complete workflow.

## Passing scenarios

- Four CLI validation cases: missing target, hostless URL, onion-without-Tor, short identity token.
- Eight session/evidence cases: unauthenticated access, HTML form retained with identity scrubbed, login/cookie/relative redirect, JSON escaped identity plus large integer and MIME fidelity, gzip, unsupported encoding rejection, logout, and valid original HAR plus owner-only artifacts.
- Two upstream TLS cases: reject an untrusted certificate by default; allow it only with the explicit override.
- One WebSocket case: correct real handshake, identity split across text fragments scrubbed after assembly, connection closed by graceful process shutdown.
- Eight Tor/SOCKS cases, each covering HTTP and WebSocket: HTTP onion/default port, HTTPS onion/default port, custom port, clearnet remote hostname handling, certificate rejection over SOCKS, and SOCKS rejection/disconnection/unavailability with zero direct target requests.

## Tor results

**Deterministic transport checks: PASS, 8/8.** The fixture records SOCKS5 CONNECT requests and confirms unresolved onion/clearnet names are sent as domain addresses (ATYP=3), with the correct port. Synthetic unresolvable names work through the fixture. Rejection, disconnect and an unavailable SOCKS listener all produce generic HTTP/WS errors; the directly reachable target sees no requests. This is transport-boundary evidence, not a packet-level proof that every possible workflow has no DNS leaks.

**Live circuit smoke test: BLOCKED by incomplete bootstrap.** An isolated installed Tor 0.4.9.8 client was started with a temporary data directory and a loopback SOCKS listener. It reached 45% (`requesting_descriptors`) and reported repeated relay connection timeouts. A real Blinder instance targeted `https://check.torproject.org` through this client; requesting `/api/ip` returned HTTP 502, body `upstream error`, after **30.039498 seconds**. Blinder logged `context deadline exceeded`.

The bounded error path was observed, but a successful Tor exit or onion rendezvous was not. No `IsTor: true` response was obtained. Both temporary processes were stopped, and existing Tor configuration was unchanged. Complete T01–T06 in the UAT guide with a bootstrapped service; the SOCKS fixture does not waive this acceptance requirement.

## UAT status

**Pending operator acceptance.** Opening the proxy in the in-app browser stopped at `ERR_CERT_AUTHORITY_INVALID`. The browser automation tool requires the operator to handle certificate warnings. No certificate exception or trust-store change was made. Browser rendering, interactive login and a real scanner run therefore have no PASS result yet.

Use the [UAT guide](testing.md) to run the synthetic target and record the selected workflow. Successful live Tor routing, onion-service UAT, a production target, load/soak runs, an external HAR viewer and the cross-platform release matrix remain unverified. The existing README limitations remain applicable.

## Suggested next request for Claude

> Please review the new functional/acceptance tests on `codex/functional-uat` and fix the three reproduced defects above: browser Origin/Referer mapping on the documented loopback URL, CLI exit on listener failure, and nonzero exit when requested evidence cannot be written. Preserve unrelated/adversarial origins and keep attempting all artifact writes on shutdown. Add focused regressions for those boundaries, then run the full race suite, vet, static build and `make test-functional`, including the eight Tor/SOCKS scenarios. Keep the acceptance tests active; once they all pass, add the full functional suite to CI. Leave browser/scanner and live Tor/onion UAT sign-off pending until we run the documented operator checklist together; the live Tor attempt stalled during bootstrap and the mock is not a substitute.

## Certificate preflight follow-up — local working tree

After the baseline above, product code was extended with persistent local certificates, `--preflight`, approved macOS user trust via `--trust-cert`, and an explicit ephemeral mode. See the current [certificate guide](testing.md#local-certificate-trust). These changes remain local on `codex/functional-uat`; the earlier main revision does not include them.

The updated functional run has **25 passing and 4 failing leaf scenarios**. The two new passing scenarios prepare a certificate without a target and verify HTTPS across process restarts using the exported public certificate, and exercise declined/unsupported trust without changing a trust store. All eight Tor scenarios still pass; the original four acceptance failures remain.

The final full package race suite, vet and static macOS arm64 and Linux amd64 builds pass. Unit checks cover public-file repair without identity changes, renewal and name changes, preservation of damaged private identities, file permissions/symlinks, and concurrent initialization. A first-start locking race found during the full suite was corrected and verified with 20 repeated concurrency/unsafe-path runs.

Preflight generated a persistent certificate on the test machine, then reused the same fingerprint on a second invocation. Both correctly returned status 2 because platform trust still needs approval. No certificate was installed into a system or user trust store. The macOS installation command and selected browser's acceptance remain UAT steps; a successful client-specific trust-pool test does not establish those results.

## OS-specific certificate advice follow-up — local working tree

Preflight now detects macOS or the Linux distribution and prints the appropriate certificate advice. macOS receives a quoted trust command retaining the selected store/alias/endpoint. Ubuntu/Debian receives client-specific guidance, with a distinction between Blinder's leaf certificate and root-CA installation. Both receive a curl verification command with the actual public certificate path and endpoint. The README, specification and UAT guide describe the platform/client trust distinction and remote-client setup.

Validation passed: the CLI and TLS package race tests, the two certificate functional scenarios, vet for the changed packages, the native static build and a Linux amd64 cross-build. Detection tests cover Ubuntu, Debian, derivatives, unknown Linux, malformed fields and os-release precedence/fallback. Command checks cover spaces, apostrophes and literal shell metacharacters. The functional certificate scenario also made a verified HTTPS request with the installed macOS curl using `--cacert`; no trust store was changed.

A native preflight smoke check detected macOS, printed the selected IPv6 endpoint and a path containing spaces correctly, and returned 2 for missing platform trust. Ubuntu guidance was tested with synthetic os-release data and cross-compiled, not run on a live Ubuntu host. Browser/OS trust installation remains pending UAT. The full functional suite was not rerun for this advice change; the earlier three acceptance defects remain open.

## Delivery follow-up — local working tree

The full functional suite now passes **29/29 leaf scenarios**, with no failures or skips, including all eight Tor/SOCKS cases. The previous four failures are corrected:

- Browser Origin/Referer mapping uses complete recognized origins, including scheme and port, and is shared with WebSocket upgrades. Negative checks retain null, unrelated, malformed and duplicate origins instead of repairing scanner input.
- An occupied port exits promptly and nonzero without announcing a ready listener. Server errors reach the process lifecycle; the periodic stats ticker stops during shutdown.
- Required evidence-write and shutdown failures produce a nonzero exit. The functional checks verify that a failed HAR write still allows reports to be saved, and a failed report destination still allows HAR output.

Additional corrections apply the HAR body cap to text and binary requests/responses, report truncation with original sizes, preserve UTF-8 boundaries and binary request bytes, and account for elapsed time in request-start timestamps. Binary replacements now advertise the actual GIF media type. HTTP manifest entries include failures and request-local replacement counts under concurrent load; unknown residual leakage is explicitly `-1`. Repeated manifest flushes no longer duplicate findings.

Validation: `go test -race -count=1 -timeout 120s ./...`, `go vet -tags functional ./...`, the full functional suite, the native static build and a Linux amd64 static cross-build all pass. One old HAR test asserted capture-completion time in the start field; it was corrected to verify the start-time behavior. The new HAR tests cover text, form charsets, UTF-8 truncation, binary data and invalid text. Concurrent manifest checks verify independent request counts and stable totals across repeated flushes.

The GitHub workflow now includes the complete functional suite. This is an uncommitted local configuration change, not a claim of a new remote CI run. The rebuilt local executable includes these corrections. No trust-store installation or live Tor/browser UAT was performed in this follow-up. Remaining architecture and acceptance work is tracked in [delivery gates](capabilities.md#remaining-delivery-gates).
