# Local operator and evidence acceptance — 2026-09-26

This batch follows local commit `63c10ff` and tests the operator isolation and HAR consumer changes before committing them. Nothing was pushed and no GitHub CI result is claimed. Masking and Tor remain independent.

## Reproduced defect and correction

The stronger browser test first proved that the operator session was authenticated, then opened its queue from an ordinary target page. Fetch and iframe attempts were blocked, but a same-origin popup exposed the original target URL and raw challenge text. The previous programmatic checks missed that path.

Operator controls now live at `https://blinder-operator.localhost:<port>/__blinder/captcha/`, on the same listener but a separate browser origin. Only loopback peers can reach them. Target origins return 404 for operator controls while retaining the scoped provider resource relay. The host-only `__Host-blinder-operator` cookie stays on the operator host, and reserved current/legacy credentials are removed before upstream forwarding.

Cookie-authenticated mutations require the configured operator Origin. Raw challenge documents, including separate solve windows, run inside opaque sandboxed frames; direct provider documents receive a sandbox policy. Operator pages sever cross-origin popup relationships and disallow service workers. Target service-worker behavior is preserved.

Browser testing also caught a regression during implementation: `Referrer-Policy: no-referrer` made native form submissions send `Origin: null`. Operator control pages now use `same-origin`; the token-bearing login URL retains `no-referrer`. Null and cross-origin submissions remain rejected. Native completion showed its receipt and resumed the original session with its CSRF data intact.

## Verification

| Check | Result |
| --- | --- |
| `go test -race -count=1 ./...` | 690 top-level tests passed across 15 tested packages; zero failures. Five opt-in browser tests skipped in this command. |
| `go test -tags functional -race -count=1 -timeout 120s ./tests/functional` | All 12 top-level tests passed. |
| `go vet -tags=functional ./...` | Clean. |
| `CGO_ENABLED=0 go build ./cmd/blinder` | Clean; local binary retained separately. |
| `TestCaptchaSessionBrowserOperatorIsolation` | Passed in the in-app browser with authenticated positive controls, a target-controlled service worker, unreadable fetch/iframe/popup documents, and no operator navigation intercepted by that worker. |
| `TestCaptchaFlowBrowser` | Passed: 13 synthetic provider requests, nested frames, extension methods, native completion receipt, original session and refreshed CSRF preserved. |
| `TestCaptchaBrowserRoutingIframeAndProviderRoute` | Passed: target/operator separation and configured provider SOCKS routing. |
| `TestCaptchaProviderOperatorChallengeBrowserRoute` | Passed: synthetic widget visibly loaded; recording SOCKS fixture observed both target and provider. |
| HAR export adapter | All five Node tests passed, including the installed Playwright 1.62.1 importer/matcher; no skipped consumer check. |

The browser fixtures ran sequentially over local HTTP secure-context hostnames. They did not bypass a TLS warning, change OS trust, solve a live CAPTCHA, or establish a live Tor circuit. The response-fidelity browser check belongs to the [preceding checkpoint](testing-results-2026-09-26-postcommit.md) and was not rerun for this operator-only change.

## HAR consumer result

Playwright's importer treated Blinder's binary request `postData._encoding` extension as plain text. The optional [local Playwright export](playwright-har-export.md) preserves the canonical capture and writes binary request attachments understood by that consumer. Its matcher now accepts the original binary POST bytes and rejects their base64 text as a different request. Response bytes and diagnostic metadata remain intact. This proves importer/matcher compatibility for the fixture, not viewer UI or end-to-end browser replay.

## Evidence and open acceptance

Local evidence is under `blinder-acceptance-2026-09-26` in this task's artifact directory. It includes the failing popup reproduction, four accepted browser logs, test JSONL, consumer results, and `source-sha256.json`. The source digest (Go/JavaScript sources, scripts and module files) is `2e360f8e9b1b48465762aacf5c8ac1a94b8890acb43bcce9f66d2c85915c7e3f`. The tested static binary SHA-256 is `04d81d40786497a9faa43170c95b3e2c5420c7c725ccae442791cc085cb41c88`.

The certificate now covers the reserved operator hostname. Existing certificates lacking that name are reissued, changing their fingerprint while retaining the store/signing-key location. The current macOS trust helper checks the listen hostname only: actual client trust for both endpoints remains pending. Live Tor exit/onion requests, live-provider human completion, broader dynamic browser network containment, browser WSS acceptance, and chosen HAR viewer/replay acceptance remain open. These local results do not establish universal provider compatibility or complete anonymization.
