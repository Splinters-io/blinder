# Regression, functional testing and UAT

Use these as three separate gates. Package regressions check specific defect classes; functional tests exercise the actual CLI and network boundary; UAT verifies the selected browser/scanner workflow with an operator. Green CI alone is not UAT approval or a general anonymization guarantee.

The [2026-09-26 report](testing-results-2026-09-26.md) records current local verification. The [2026-09-23 report](testing-results-2026-09-23.md) preserves the three reproduced issues on main `34eb0a0` and their subsequent working-tree fixes. Browser/scanner, OS trust and successful live Tor/onion UAT remain separate acceptance gates.

## Automated checks

Run from the repository root with Go 1.26+, on macOS or Linux:

```sh
go vet -tags functional ./...
go test -race -count=1 -timeout 120s ./...
make test-functional
CGO_ENABLED=0 go build -o /tmp/blinder ./cmd/blinder
```

The functional suite builds a race-instrumented CLI, starts synthetic HTTP/HTTPS targets on loopback, launches a separate proxy process, makes real TLS requests, and inspects exit status and evidence files. It uses ephemeral ports and temporary directories, terminates its child processes, and needs no real account, public target, Tor service or scanner installation. Building may download the Go toolchain/modules if they are not cached.

Coverage includes CLI validation, authentication with a real cookie jar, relative redirects, logout, HTML scrubbing, escaped JSON and large integers, MIME fidelity for JSON, gzip decoding, rejection of unsupported encoding, upstream certificate verification, WebSocket text fragmented across an identity, shutdown with a live WebSocket, original HAR data, and owner-only artifact permissions.

Response-fidelity regressions cover Unicode byte lengths, compressed/chunked payloads, original versus rewritten sizes, cache/HEAD/304 provenance, bodyless 204/304 responses, partial-read evidence, transport failures, HTML error diagnostics and HTTP 200 JSON validation errors. Run `go test -race -count=1 ./internal/proxy -run '^TestResponseFidelity'` for this group. Browser checks remain opt-in rather than being counted as passed when skipped.

Run `go test -race -count=1 ./internal/jsonedit` and `go test -race -count=1 ./internal/proxy -run '^TestJSONFidelity'` for JSON source fidelity. Real HTTP fixtures compare direct and proxied request/response bytes, including duplicate keys, whitespace/order, string escapes, large integers, exponent spellings and negative zero. They verify minimal alias edits and nested CAPTCHA opacity scoped to the configured submission path. Malformed error fixtures retain HTTP 500, SQL-style diagnostics and original broken grammar while redacting escaped identities. Ambiguous escapes and cross-fragment residual identities still exercise the `null` fallback.

Run `go test -race -count=1 ./internal/proxy -run '^TestPathFidelity'` for real upstream path restoration, encoded slashes/reserved characters, untouched escape spelling, restored cache identities and SRI version constraints.

Run `go test -race -count=1 ./internal/formedit` and `go test -race -count=1 ./internal/proxy -run '^TestFormFidelity'` for form/query source fidelity. Exact upstream bytes, duplicates, pair ordering, percent-escape spelling, bare keys and opaque CAPTCHA values are compared with direct requests, including malformed percent escapes. Only ampersands are treated as separators; unchanged literal semicolons are retained.

Run `go test -race -count=1 ./internal/rewriter -run '^TestResponseHeaderFidelity'` for custom diagnostic headers, configured identity redaction and exclusion of hop-by-hop/Connection-nominated fields and invalid representation metadata. These do not establish byte-range translation or safe reversible mapping of identity-bearing custom field names.

Run `go test -race -count=1 ./internal/ws` and `go test -race -count=1 ./internal/proxy -run '^TestProxyWebSocketExtraOriginAcceptance$'` for primary/extra HTTP/HTTPS routes, unknown-host rejection, full-origin TLS selection, fragmented text restoration, and synthetic SOCKS remote-hostname routing without direct fallback. These local fixtures do not establish live Tor/onion or browser-generated ws/wss URL containment.

Run `go test -race -count=1 ./internal/rewriter -run '^TestHTMLFidelity'` for untouched HTML source preservation and configured redaction in comments and incomplete markup. Changed attributes and intentionally replaced content are covered separately.

Run `go test -race -count=1 ./internal/proxy -run '^TestWebSocket(Refusal|Transport|Handshake|101|Literal)'` for refused-upgrade status/body fidelity, partial errors, transport failures, 101 evidence while frames remain active, and matching JavaScript rewrites through normal/SRI paths. These checks do not establish dynamically assembled URL containment or trusted browser WSS acceptance.

Run `go test -race -count=1 ./internal/rewriter -run '^TestProse'` for prose byte budgets, entity/Unicode handling, literal boundary whitespace, short text, and reversible textarea/option values, including slash-ended form elements.

Run `go test -race -count=1 ./internal/rewriter ./internal/proxy -run '^TestBodySize'` for whole-HTML size matching. These tests compare differently sized responses, including gzip input, and require each final decoded length and the signed difference between them to match upstream. They also verify that fitting occurs after provider URL expansion, that SQL-style diagnostics, script text and form values survive, and that insufficient adjustment space is reported rather than taken from functional content. These are synthetic fidelity fixtures, not proof of SQL injection detection on arbitrary sites.

For a local browser form/diagnostic check:

```sh
BLINDER_REVIEW_BROWSER=1 go test -race -count=1 -timeout 130s ./internal/proxy -run '^TestResponseFidelityBrowser$' -v
```

Open the URL in `/private/tmp/blinder-response-browser-url.txt`, check the ordinary paragraph has become verse, click **Validate**, and confirm that the page displays `E_EMAIL`, the validation message and the Unicode input `café`, while its configured identity uses its reversible alias. The fixture verifies that textarea and option values reach upstream as `AcmeCorp & café`, not filler. The upstream response must remain 422. Then navigate to `/review-cleanup` on the fixture origin to finish. The local browser run matched the complete form page at **432 original → 432 rewritten → 432 emitted bytes**. The error response retained its diagnostic text with **277 → 285 → 285 bytes**; error content was not shortened to force a match. This does not establish wider site compatibility or universal content anonymisation.

The synthetic provider browser flow (`BLINDER_REVIEW_BROWSER=1 go test -race -count=1 -timeout 190s ./internal/proxy -run '^TestCaptchaFlowBrowser$' -v`) also passed in the in-app browser on 2026-09-26. Its nested frames, dynamic scripts and 13 provider requests—including extension methods—used the configured local SOCKS relay. Native operator submission displayed **Solution submitted**, and the original POST resumed with its session cookie and fresh CSRF field. The receipt confirms delivery to the waiting request; upstream acceptance is checked separately by the fixture. This is synthetic provider acceptance, not a solved live CAPTCHA or a live Tor circuit.

Tor mode also has eight deterministic SOCKS5 scenarios: HTTP and HTTPS onion targets on their default ports, a custom target port, a clearnet hostname passed to SOCKS for resolution, certificate rejection through the tunnel, and proxy rejection/disconnection/unavailability. Every scenario exercises both HTTP and WebSocket paths. The failure cases use a directly reachable target and assert that it receives zero requests.

```sh
go test -tags functional -race -count=1 -timeout 120s -run '^TestTor' ./tests/functional
```

These checks inspect the SOCKS5 destination type and original hostname; the synthetic SOCKS server maps destinations only to local fixtures. They validate Blinder's transport behavior, not a live Tor circuit or an onion-service rendezvous.

Acceptance checks additionally require:

- An occupied listen port must cause a prompt nonzero exit.
- Failure to save requested HAR or manifest evidence must produce a nonzero exit.
- A legitimate browser-origin form POST through the documented loopback URL must still succeed at the upstream origin check.

To run the acceptance checks or a subset of functional checks during development:

```sh
go test -tags functional -race -count=1 -timeout 120s -run '^TestAcceptance' ./tests/functional
go test -tags functional -race -count=1 -timeout 120s -run '^(TestCLIValidation|TestLoginJSONAndEvidence|TestUpstreamTLSVerification|TestWebSocketFragmentAndShutdown|TestTor.*)$' ./tests/functional
```

For machine-readable evidence:

```sh
go test -tags functional -race -count=1 -timeout 120s -json ./tests/functional > /tmp/blinder-functional.json
```

Preserve the command's exit code when using CI wrappers. The updated GitHub workflow runs the default package race suite, vet with functional tests included, the full `make test-functional` suite and a static build. This configuration is local until published; a new remote CI result has not been claimed. Keep acceptance tests active.

## Independent HAR schema check

The fixture contains only synthetic data. It exercises journal materialization, text/gzip, binary requests and responses, redirects/cookies, 101 upgrades, partial HTTP 503 and transport failure status 0. The checker uses the separately maintained [HAR schema](https://github.com/ahmadnassri/har-schema) through a pinned validator, with local semantic assertions. No capture is uploaded, and the validator is not a production dependency.

```sh
har_check_dir=$(mktemp -d /tmp/blinder-har-check.XXXXXX)
npm install --prefix "$har_check_dir" --cache "$har_check_dir/npm-cache" --ignore-scripts --no-audit --no-fund har-validator@5.1.5
BLINDER_HAR_COMPAT_OUTPUT="$har_check_dir/compat.har" go test -race -count=1 ./internal/har -run '^TestHARCompatibilityFixture$'
BLINDER_HAR_VALIDATOR="$har_check_dir/node_modules/har-validator" node scripts/validate-har.cjs "$har_check_dir/compat.har" --fixture
```

`har-validator` is deprecated; this isolated, pinned check tests the historical HAR 1.2 format. Schema acceptance does not prove viewer compatibility or replay. In particular, binary request `postData._encoding` is a Blinder extension. Import the fixture into the intended tool as a separate acceptance step.

## Manual UAT setup

Build once and start the synthetic target in terminal A:

```sh
make build
go run ./tests/uat-target --listen 127.0.0.1:18080
```

Start Blinder in terminal B:

```sh
uat_dir=$(mktemp -d /tmp/blinder-uat.XXXXXX)
printf 'Evidence directory: %s\n' "$uat_dir"
./blinder --target http://127.0.0.1:18080 \
  --listen 127.0.0.1:18099 --identity AcmeCorp \
  --har "$uat_dir/session.har" --output "$uat_dir/output"
```

Open `https://127.0.0.1:18099/` in the chosen browser and complete the local certificate setup below. Record that setup step separately from functional test results.

The only credentials are the synthetic `tester` / `fixture-only`. The fixture binds only to loopback. No real secrets or production traffic are required. Set the scanner's target URL to the Blinder HTTPS address; Blinder is a reverse proxy, not a forward-proxy configuration field.

### Local certificate trust

Blinder terminates HTTPS from the browser/scanner and presents its own certificate. The operator must accept or trust that certificate in the client being tested. Clients may use different trust stores, so installing it in the operating system alone is not evidence that every browser or scanner will accept it. Confirm a successful connection in each selected client. The operator must handle browser-generated certificate warnings; browser automation resumes after that step.

| Connection or setting | What it controls |
| --- | --- |
| Browser/scanner → local Blinder HTTPS endpoint | Trust in Blinder's certificate for the name/IP used in the URL |
| Blinder → HTTPS target | Verification of the target certificate, enabled by default; `--no-verify-tls` disables only this check |
| Blinder → Tor SOCKS endpoint → target | Upstream routing and onion connectivity; it does not configure local certificate trust or repair certificate errors |

**Preflight and repair:** ordinary startup now creates or reuses a persistent certificate. You can run the certificate checks before starting the proxy, with no target required:

```sh
./blinder --preflight --listen 127.0.0.1:18099
```

Preflight exits after setup. It detects the running OS and prints the fingerprint, expiry, public certificate path, action taken, platform trust status and OS-specific advice. Linux detection reads `ID`, `VERSION_ID` and `ID_LIKE` from `/etc/os-release`, falling back to `/usr/lib/os-release` only if the first file is missing. It never executes the file; absent or malformed identity information produces generic Linux advice. [OS release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html).

Exit 0 means platform verification passed for the displayed host; exit 2 means platform trust still needs setup; exit 1 means preparation failed. Client-specific trust can succeed while preflight continues to return 2. No upstream/Tor or listen-port test is performed by certificate-only commands. Normal proxy startup reports missing trust but continues so clients with their own certificate-file settings can connect.

#### Certificate advice by OS

**macOS:** copy the exact `--trust-cert` command printed by preflight. It includes the current certificate directory, alias and listen address. For the default store and alias in this UAT example:

```sh
./blinder --trust-cert --listen 127.0.0.1:18099
```

Review the fingerprint, type `yes` and complete any OS approval. This installs the displayed server certificate for SSL to that host in the current user's login Keychain; it does not install a signing CA or change administrator trust. Declining leaves trust unchanged. If platform trust is already verified, installation is skipped. Run preflight in a new process after changing trust, then verify the browser/scanner separately.

**Ubuntu / Debian:** use the printed `curl --cacert` command for a verified CLI request after starting Blinder. For example, replacing the path with the exported public certificate:

```sh
curl --cacert '/path/printed/by/preflight/certificate.pem' https://127.0.0.1:18099/
```

This selects a certificate file for the client; it does not modify global trust. [curl certificate verification](https://curl.se/docs/sslcerts.html).

For a browser or scanner, compare the displayed fingerprint and configure its supported server-certificate trust/exception mechanism. Blinder exports a self-signed **leaf certificate**, so do not import it as an issuing CA in an Authorities tab. If that client only supports custom root CAs, the current leaf-only setup may not satisfy it; record that client as unsupported/pending rather than claiming that OS detection solved trust.

Ubuntu documents installation of root CA certificates using `/usr/local/share/ca-certificates/*.crt` and `update-ca-certificates`. That is a system-wide CA workflow, not Blinder's recommended leaf-certificate setup. Blinder does not run `sudo` or automatically modify Linux trust. [Ubuntu root CA guide](https://documentation.ubuntu.com/server/how-to/security/install-a-root-ca-certificate-in-the-trust-store/index.html).

**Other or unknown Linux:** use client-specific certificate trust and verify a request. Blinder does not assume an Ubuntu certificate-store layout. Browser trust behavior depends on the selected application and packaging; Firefox documents separate Linux integration mechanisms. [Firefox certificate stores](https://support.mozilla.org/en-US/kb/setting-certificate-authorities-firefox).

**Remote clients, containers and WSL:** detection identifies Blinder's running environment, not the browser's machine or host OS. Transfer only `certificate.pem` to the client machine when needed and verify its fingerprint. Keep `identity.pem`, which contains the private key, in Blinder's private store. Use a URL whose hostname/IP is covered by the certificate; importing trust does not repair a hostname mismatch.

#### Certificate reuse and renewal

The default certificate directory is under the platform's user configuration directory, keyed by alias and listen host (changing only the port reuses it). To choose an explicit store, add `--cert-dir "$uat_dir/certs"` to **both** setup commands and the proxy command. A new store is created with mode 0700. `identity.pem` contains the private key plus certificate and must have mode 0600; only `certificate.pem` is intended for client import. Missing or damaged public exports are regenerated from the identity. Existing directories with broad permissions, unsafe file paths and damaged private identities are reported for operator repair; they are not silently overwritten. Restore a known valid identity or select a new private directory if recovery is needed.

Normal proxy startup also creates `version-signing.key` (32 random bytes, mode 0600) in this private store. It survives certificate renewal and authenticates expired SRI references after restart. Back it up with the private state; corruption or unsafe permissions stop startup instead of silently rotating ownership. Removing/changing the store loses the ability to recognise previously issued references, so discard old client pages when deliberately replacing it. Ephemeral TLS still uses the default endpoint directory for this separate key.

`TestVersionRegistryProcessPersistence` checks issuance and expired-reference ownership in separate OS processes. CAPTCHA browser fixtures are opt-in: run `BLINDER_REVIEW_BROWSER=1 go test -race -count=1 -timeout 100s ./internal/proxy -run '^TestCaptchaProviderOperatorChallengeBrowserRoute$' -v`, open the temporary URL written to `/private/tmp/blinder-captcha-provider-browser-url.txt`, and verify the synthetic widget appears. Navigate to `/review-cleanup` on that fixture origin to clear its temporary operator cookie and finish. The recording SOCKS fixture must observe both target and provider. `TestCaptchaBrowserRoutingIframeAndProviderRoute` separately checks ordinary resource routing and the former iframe-read regression. These synthetic fixtures never solve a live CAPTCHA.

For the complete synthetic operator flow, run:

```sh
BLINDER_REVIEW_BROWSER=1 go test -race -count=1 -timeout 190s ./internal/proxy -run '^TestCaptchaFlowBrowser$' -v
```

Open the URL in `/private/tmp/blinder-flow-browser-url.txt`. Wait for “Provider APIs and nested frame passed” and the populated synthetic response field, then click **Submit Solution**. Navigate to `/review-cleanup` on the fixture origin within 25 seconds to clear its temporary operator cookie. The test asserts provider redirects, scripts, frames, POST/fetch and XHR, PUT/PATCH/DELETE/OPTIONS, PROPFIND and `vendor.sync`, including session cookies and bodies. It also verifies the original username, refreshed CSRF field and target cookies reach the resumed request. `/private/tmp/blinder-flow-browser-result.json` records the observed requests and recording-SOCKS destinations. This is a local SOCKS fixture, not a live Tor circuit.

The package regressions `TestProviderRelayArbitraryMethodsOnWire`, `TestProviderRelayArbitraryPreflightMethods`, `TestProviderRelayCustomMethodRequiresSession`, and `TestProxyCustomMutationInvalidatesCachedGET` cover method fidelity and cache effects without a browser. Malformed method tokens, expired sessions, out-of-scope redirects, excessive request bodies and provider read timeouts are tested separately. Only genuine CORS preflights are handled locally; ordinary OPTIONS reaches the provider.

Persistent certificates last 90 days. Startup renews them when seven days or less remain, and reissues them if required endpoint names change. A replacement changes the fingerprint and needs new trust approval. Previous public certificates are retained as `previous-<fingerprint>.pem`; use them to identify and remove obsolete trust. On macOS, the operator can remove the old user trust setting with `security remove-trusted-cert` and the chosen previous public certificate path, then manage any remaining certificate entry in Keychain Access. Other clients use their own certificate removal interface.

For UAT, record the fingerprint, expiry, endpoint, selected client and trust scope. After trusting/importing the public certificate, verify a connection with certificate verification enabled. Restart with the same store and names and confirm the fingerprint and successful connection are unchanged. Repeat the trust step after renewal/reissue. `--ephemeral-cert` opts out of persistence and generates a new 24-hour certificate per run; it cannot be combined with `--cert-dir` or `--trust-cert`. `curl --insecure` is only a per-request bypass, not evidence that trust setup succeeded.

Local certificate acceptance does not establish scrub correctness, upstream TLS trust or successful Tor bootstrap. Those remain separate checks below.

## Operator checklist

Record browser/scanner name and version, OS, exact Blinder commit and dirty state, command-line flags, tester, date, observed result, and evidence location for every row. Statuses are PASS, FAIL or NOT RUN; a known failure remains FAIL.

| ID | Action | Acceptance result |
| --- | --- | --- |
| U01 | Run preflight, confirm OS-appropriate advice and explicit trust/client setup, then start target and proxy; repeat after a restart | Detected OS matches the running environment; displayed commands use the selected endpoint/store; page loads with client verification enabled; fingerprint stays unchanged on reuse; validity and trust scope are recorded; upstream TLS policy is unchanged |
| U02 | Inspect the landing page and its source | Synthetic identity `AcmeCorp` is absent from the rewritten title/body; login controls remain usable |
| U03 | Log in with the fixture credentials, refresh `/account`, then log out | Relative redirect works, `session-ok` is shown while authenticated, refresh keeps the session, `/account` becomes 401 after logout |
| U04 | Visit **Origin-checked form** and submit `hello` | Shows `form accepted`; unrelated/invalid origins remain rejected; automated acceptance now passes |
| U05 | Open **JSON** and **Gzip JSON**, inspecting raw response data | JSON remains valid, large integer is exactly `9007199254740993`, technical fields survive, configured identity is removed |
| U06 | Return to `/` and observe the live WebSocket label | Label ends in ` live` with the configured identity scrubbed; no WebSocket protocol error |
| U07 | Visit **Unsupported encoding** | Generic 502, with no original body/identity reaching the client |
| U08 | Crawl the synthetic target with the selected scanner, using its documented TLS/session setup | Scanner reaches expected routes and authenticated content; record scan coverage and unexpected errors against a direct-target baseline |
| U09 | Stop Blinder with Ctrl-C while the live page is open | Process exits promptly; WebSocket closes; HAR and three JSON evidence files exist, parse and have owner-only file permissions |
| U10 | Inspect the original login POST and responses in the HAR | Original upstream URL, form body and original identity-bearing response are retained on the operator side; chosen HAR viewer can open the file |
| U11 | Try a second instance on the same listen port | Second instance exits nonzero promptly without announcing readiness; automated acceptance now passes |
| U12 | Request an output path below a regular file, then stop after a request | Failure produces a nonzero exit and does not prevent the other artifact destination being attempted; automated acceptance now passes |

The automatic checks simulate several of these flows. They do not substitute for U01–U12 in a named browser/scanner and operator acceptance.

The automated persistent-certificate test verifies HTTPS across restarts using only the exported public certificate in a client trust pool. Actual macOS Keychain installation and the selected browser/scanner's acceptance remain operator UAT steps; automated tests do not modify system or user trust stores.

## Live Tor UAT

Tor is a required acceptance track. A mocked SOCKS5 pass does not satisfy it. Use a bootstrapped Tor service and record its version, bootstrap status, SOCKS address, target, timings and outcome. Use an operator-controlled onion target for the authenticated and WebSocket flows.

For a separate temporary Tor client, with Tor already installed, in another terminal:

```sh
tor_uat_dir=$(mktemp -d /tmp/blinder-tor-uat.XXXXXX)
tor --DataDirectory "$tor_uat_dir/client" \
  --SocksPort 127.0.0.1:19050 --ClientOnly 1 --Log 'notice stdout'
```

Wait for `Bootstrapped 100%` before recording a successful circuit test. Start a separate Blinder instance for the read-only exit check:

```sh
./blinder --target https://check.torproject.org \
  --listen 127.0.0.1:18100 --tor --tor-addr 127.0.0.1:19050
```

Request `https://127.0.0.1:18100/api/ip` with the chosen client, handling Blinder's certificate as above. Require a successful JSON response with `IsTor: true`; do not require the original exit IP to survive scrubbing. This checks clearnet exit routing only. Stop this instance before switching the target to the operator-controlled onion service.

| ID | Action | Acceptance result |
| --- | --- | --- |
| T01 | Start the isolated client and wait for bootstrap | 100% bootstrap recorded; failure to bootstrap remains NOT RUN for circuit-dependent cases |
| T02 | Run the exit check through Blinder | Successful response reports `IsTor: true`; upstream TLS verification remains enabled |
| T03 | Run login/logout, JSON and WebSocket cases against an operator-controlled `.onion` target with `--tor` | Same functional outcomes as U03/U05/U06, with successful onion routing recorded separately from a clearnet exit check |
| T04 | Stop the isolated Tor process while leaving Blinder running; issue fresh HTTP and WebSocket requests | Generic errors, no successful direct requests to a target reachable outside Tor; observe target access logs/network traffic to check fallback |
| T05 | Restart Tor, wait for bootstrap and retry | Fresh requests and WebSocket connections recover; session behavior is recorded |
| T06 | Run slow responses and the intended session duration through Tor | Timeouts are bounded and observable; record whether the current 30-second upstream timeout fits the workflow |

An onion address in a SOCKS5 CONNECT request demonstrates remote destination handling. A broader no-DNS-leak claim additionally needs network observation during the chosen real workflow. Stop the temporary Tor and Blinder instances when the session finishes.

## Explicit scope checks before wider use

- **Absolute links and redirects:** inspect `/absolute-redirect` without following external aliases automatically. Rewritten aliases do not currently provide complete origin/DNS routing. Record whether the intended target depends on this, and block that workflow if it does.
- **Documents and fonts:** inspect `/document.pdf`. Binary content is replaced with a GIF placeholder while the original MIME type remains; document/font rendering fidelity is not established. The fixture PDF is a metadata sample, not a complete rendered document.
- **Privacy boundaries:** encoded HTML/JS, arbitrary unknown binary content, cookie values and binary/control WebSocket payloads need separate policy and tests. A passing fixture is not evidence that every response is anonymized.
- **Evidence:** verify imports into the intended HAR tool. Independent schema and synthetic semantic checks pass. Selected viewer import, replay and WebSocket frame capture remain separate acceptance work; handshake evidence is covered by local regressions.
- **Routing and scale:** complete the live Tor track above; complex multi-origin applications, long-running sessions, load, memory growth and all release platforms remain separate test work.

Release acceptance requires the open functional failures to be fixed, the full functional command to pass, and the selected operator workflow to have evidence and explicit sign-off. Acceptance of Tor mode also requires the live Tor/onion track; do not substitute the local SOCKS fixture. Keep unsupported capabilities visible in the release scope.
