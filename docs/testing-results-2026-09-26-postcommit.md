# Local review after 7d707ab — 2026-09-26

This reviews the local working tree based on `7d707ab63e1b290295c3b6958018e3e1004f35e6`. The fixes below are uncommitted; no push, deployment or GitHub CI run was performed. Logs and source hashes are retained in the task evidence directory `blinder-postcommit-review-2026-09-26`.

## Reproduced findings and corrections

- **Masking and transport:** removed the new requirement that `--paranoid` use Tor, following the operator's explicit scope decision. Masking works with either direct or Tor routing. Onion targets still require Tor. Real CLI regressions cover both the flag and YAML configuration, exact prose size and preserved error diagnostics.
- **Cookie restoration:** extra-origin responses now record cookie mappings under the selected upstream rather than the primary target. HTTP, HEAD, bodyless responses, revalidation and SRI-cache responses share that correction. Same-origin SRI prefetch uses the configured route's cookie scope even when a resource URL spells its equivalent hostname differently. Real transport tests cover cookies, caches, SRI and WebSocket requests.
- **Route rejection:** HTTP now returns 421 when the origin mapper rejects the Host, without falling back to the primary target. Numeric ports normalize consistently and bracketed IPv6 works on the default port. Real TLS tests exercise accepted/rejected routes and registered certificate names. Synthetic fixtures now declare their ephemeral listeners or registered Host explicitly.
- **CORS fidelity:** invalid origin values, including trailing paths and empty query/fragment delimiters, no longer become valid local permissions. Valid translated proxy origins and the `null`/`*` protocol values are not passed through the identity scrubber again. Regressions cover fresh cache and revalidation responses. The origin syntax follows the [Fetch CORS rules](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials).
- **HAR cleanup retries:** after committing an export, a failed journal removal or corrupt-journal backup retries only the pending cleanup. Repeated flushes cannot replay those already committed entries; new evidence waits for retirement before appending. Fault-injection tests cover transient and persistent failures, corrupt recovery, and requests arriving after the commit.
- **HAR configuration:** negative capture and memory-entry budgets are rejected through both YAML and embedded configurations. The CLI reuses its initial validated configuration load.

## Verification

| Check | Result |
| --- | --- |
| `go test -race -count=1 -timeout 120s -json ./...` | 679 top-level tests passed; 15 tested packages passed. Zero failures; five opt-in browser tests skipped. |
| `go test -tags functional -race -count=1 -timeout 120s -json ./tests/functional` | All 12 top-level CLI functional tests passed. |
| `go vet -tags functional ./...` | Clean. |
| `CGO_ENABLED=0 go build -o /private/tmp/blinder-postcommit-verified ./cmd/blinder` | Clean. |
| Separate in-app browser form/error run | Passed with race detection. Masked form: 432 original/rewritten/emitted bytes. HTTP 422 diagnostic: 277 original, 285 rewritten/emitted bytes; configured identity masked and form values restored upstream. |
| Separate in-app browser synthetic provider/operator run | Passed with race detection. Thirteen provider requests, nested frames, custom HTTP methods, original session/CSRF retained and visible submission receipt. |
| `git diff --check` | Clean. |

The form browser fixture received a test-only ephemeral-listener correction after the full automated run and then passed its separate browser run. Production code did not change after the full run. Browser cleanup endpoints reached their handlers and completed the tests; navigation could report a connection error as the fixture servers shut down. These two browser results do not convert the other skipped browser checks into passes. No live CAPTCHA was solved.

## Remaining acceptance and limits

The earlier certificate-trust and live Tor blockers in the [prior report](testing-results-2026-09-26.md) remain unresolved: browser HTTPS/WSS requires the operator's local trust step; live exit/onion testing needs a working SOCKS endpoint or bridge configuration. Synthetic SOCKS results do not establish live Tor acceptance. Live provider human completion, broader browser containment and selected HAR viewer/replay acceptance remain open.

Cookie mapping still uses the configured Host scope; it does not implement complete scheme-aware or browser Domain/Path cookie isolation. HAR cleanup state is held in memory: a process crash between final HAR replacement and journal retirement can still replay entries on restart. The new regressions establish same-process retry correctness, not crash-atomic export.
