# Regression, functional testing and UAT

Use these as three separate gates. Package regressions check specific defect classes; functional tests exercise the actual CLI and network boundary; UAT verifies the selected browser/scanner workflow with an operator. Green CI alone is not UAT approval or a general anonymization guarantee.

The [provider-origin report](testing-results-2026-09-26-provider-origins.md) records the latest isolated provider routing and CSP/CORS comparison. The [earlier acceptance report](testing-results-2026-09-26-acceptance.md) records operator browser isolation and independent HAR consumer checks. The [post-commit review](testing-results-2026-09-26-postcommit.md), [fidelity report](testing-results-2026-09-26.md) and [2026-09-23 report](testing-results-2026-09-23.md) preserve earlier verification. Selected browser/scanner workflows, certificate trust and successful live Tor/onion UAT remain separate acceptance gates.

The [behavior-preservation checkpoint](testing-results-2026-09-26-behavior.md) records the current image, JavaScript-navigation and malformed-source work. An initial browser comparison exposed a percent-encoded JavaScript URL acquiring a CSP grant. The decoded-hash correction has package regressions; the final expanded browser comparison is pending and must not be inferred from earlier passing pairs.

The [content-contract checkpoint](testing-results-2026-09-26-content-contract.md) records generated-filler identity checks, response-level content requirements and the replacement of the outdated preview process that still emitted removal labels. Its live root-response check is separate from browser workflow acceptance.

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

Replicated controls must produce the same allow/block decision on the direct target and its corresponding proxy representation. Test permitted and denied operations, as well as report-only behavior. A page loading successfully is not sufficient evidence: a removed restriction can make a broken replication look functional. Preserve the original policy in operator evidence and record any unsupported translation separately.

For CSP, run the ordinary regressions with `go test -race -count=1 ./internal/rewriter ./internal/proxy -run '^TestCSP|^TestControlFidelityCSPWire|^TestCaptchaCSP'`. Then run the paired browser fixture using an existing certificate trusted by the selected browser for `127.0.0.1`:

```sh
BLINDER_REVIEW_BROWSER=1 \
BLINDER_REVIEW_CERT_DIR=/private/tmp/blinder-acceptance-certs \
go test -race -count=1 -timeout 200s ./internal/proxy -run '^TestControlFidelityBrowser$' -v
```

Open the URL in `/private/tmp/blinder-csp-browser-url.txt` within 180 seconds. The fixture runs the direct baseline, navigates to Blinder, and compares execution, computed style and policy-violation events. It records `/private/tmp/blinder-csp-browser-result.json`. Both stages use local synthetic targets; the command does not install trust or bypass certificate warnings. See the [CSP acceptance report](testing-results-2026-09-26-csp.md) for measured coverage and remaining work.

For image, JavaScript-navigation and malformed-source regressions:

```sh
go test -race -count=1 ./internal/rewriter -run '^(TestRaster|TestJavaScriptURL|TestHTMLFidelity)'
go test -race -count=1 ./internal/proxy -run '^(TestMalformedHTMLSource|TestBehaviorFidelityTruncatedSourceWire)'
```

Raster checks validate actual decoding, format, dimensions and byte lengths for JPEG, static PNG and GIF; GIF timing/frame geometry, minimal JPEG EXIF orientation, corrupt-image failures, textual diagnostics, embedded data URLs and legal padding boundaries are covered separately. Decoding has explicit pixel/dimension/frame budgets. Unsupported formats/APNG and PNG EXIF orientation remain limitations, and decoder tests do not establish every browser's tolerance for corrupt files. JavaScript-navigation tests check executable syntax and string masking, URL percent decoding, original CSP hash scope and denial when only an encoded or transformed spelling matches. Malformed HTML checks retain bogus/unterminated comment envelopes and incomplete source while masking identities, including a real HTTP 503 with preserved diagnostics and actual body length. Cases where identities cross syntax delimiters still exercise conservative omission.

Run the paired browser comparison with an existing certificate trusted for `127.0.0.1`:

```sh
BLINDER_REVIEW_BROWSER=1 \
BLINDER_REVIEW_CERT_DIR=/private/tmp/blinder-acceptance-certs \
go test -race -count=1 -timeout 200s ./internal/proxy -run '^TestBehaviorFidelityBrowser$' -v
```

Open `/private/tmp/blinder-behavior-browser-url.txt` in the chosen browser within 180 seconds. The fixture automatically runs direct and proxied stages and records `/private/tmp/blinder-behavior-browser-result.json`. Compare explicit permitted/blocked JavaScript execution and CSP events, image load/error events and natural dimensions, malformed comment execution boundaries, and actual upstream image requests. The separate wire test checks incomplete trailing source that the browser omits from its DOM. A disconnected browser or timed-out stage remains incomplete acceptance; neither an opt-in skip nor equality between two unexpected failures counts as a pass. See the behavior checkpoint for the exact state of the current rerun.

Run `go test -race -count=1 ./internal/jsonedit` and `go test -race -count=1 ./internal/proxy -run '^TestJSONFidelity'` for JSON source fidelity. Real HTTP fixtures compare direct and proxied request/response bytes, including duplicate keys, whitespace/order, string escapes, large integers, exponent spellings and negative zero. They verify minimal alias edits and nested CAPTCHA opacity scoped to the configured submission path. Malformed error fixtures retain HTTP 500, SQL-style diagnostics and original broken grammar while redacting escaped identities. Ambiguous escapes and cross-fragment residual identities still exercise the `null` fallback.

Run `go test -race -count=1 ./internal/proxy -run '^TestPathFidelity'` for real upstream path restoration, encoded slashes/reserved characters, untouched escape spelling, restored cache identities and SRI version constraints.

Run `go test -race -count=1 ./internal/rewriter ./internal/proxy -run '^(TestRequestOrigin|TestResource|TestCompleteResource|TestBodyOrigin|TestTargetContainmentPrimaryURLRoutes)'` for validated entry-origin URL mapping and cache/SRI isolation. Registered primary resource URLs in HTML, CSS and complete unescaped JavaScript literals must keep the hostname and port used to enter the proxy; extra origins must retain their separate aliases. Browser checks must also verify every extra alias resolves locally and passes certificate verification. A failed extra-origin fetch remains a failed acceptance case even when the primary script, CSS, fetch and WebSocket paths work.

For repeatable browser containment UAT, prepare a separate certificate store with the stable extra-origin name:

```sh
./blinder --preflight --listen 127.0.0.1:18199 --alias localhost \
  --extra-origin https://127.0.0.1:18181 \
  --cert-dir /private/tmp/blinder-containment-certs
```

Review its fingerprint and verify browser trust for `127.0.0.1` and `host-a9950799.localhost`, the two hostnames used by this fixture. `localhost` remains the configured primary alias and a certificate SAN; this browser entry uses the IP. On macOS, multiple hostname constraints belong in one trust operation: repeated single-host installations replace that certificate's existing trust settings. The system command supports repeated `-s` arguments in one invocation. [Apple implementation](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/trusted_cert_add.c). After explicit operator approval, the scoped command is:

```sh
/usr/bin/security add-trusted-cert -r trustRoot -p ssl \
  -s 127.0.0.1 -s host-a9950799.localhost \
  -k "$HOME/Library/Keychains/login.keychain-db" \
  /private/tmp/blinder-containment-certs/certificate.pem
```

Then run:

```sh
BLINDER_REVIEW_BROWSER=1 \
BLINDER_REVIEW_CERT_DIR=/private/tmp/blinder-containment-certs \
BLINDER_REVIEW_PROXY_LISTEN=127.0.0.1:18199 \
BLINDER_REVIEW_EXTRA_LISTEN=127.0.0.1:18181 \
go test -race -count=1 -timeout 200s ./internal/proxy -run '^TestTargetContainmentBrowser$' -v
```

Open the URL in `/private/tmp/blinder-containment-browser-url.txt` within 180 seconds. The fixture automatically records the script, CSS, fetch, WebSocket, submitted-URL round trip and extra-origin results in `/private/tmp/blinder-containment-browser-result.json`. Its recording SOCKS relay and separate direct canaries use only local servers. The command does not generate certificates or install trust; each browser hostname must pass certificate verification. Explicit listener addresses require loopback IPs and nonzero ports; occupied ports fail without falling back. Omitting the two listener variables retains random ports, and ordinary wire tests always use their own random ports.

Run `go test -race -count=1 ./internal/formedit` and `go test -race -count=1 ./internal/proxy -run '^TestFormFidelity'` for form/query source fidelity. Exact upstream bytes, duplicates, pair ordering, percent-escape spelling, bare keys and opaque CAPTCHA values are compared with direct requests, including malformed percent escapes. Only ampersands are treated as separators; unchanged literal semicolons are retained.

Run `go test -race -count=1 ./internal/rewriter -run '^TestResponseHeaderFidelity'` for custom diagnostic headers, configured identity redaction and exclusion of hop-by-hop/Connection-nominated fields and invalid representation metadata. These do not establish byte-range translation or safe reversible mapping of identity-bearing custom field names.

Run `go test -race -count=1 ./internal/ws` and `go test -race -count=1 ./internal/proxy -run '^TestProxyWebSocketExtraOriginAcceptance$'` for primary/extra HTTP/HTTPS routes, unknown-host rejection, full-origin TLS selection, fragmented text restoration, and synthetic SOCKS remote-hostname routing without direct fallback. These local fixtures do not establish live Tor/onion or browser-generated ws/wss URL containment.

Run `go test -race -count=1 ./internal/rewriter -run '^TestHTMLFidelity'` for untouched HTML source preservation and configured redaction in comments and incomplete markup. Changed attributes and intentionally replaced content are covered separately.

Run `go test -race -count=1 ./internal/proxy -run '^TestWebSocket(Refusal|Transport|Handshake|101|Literal)'` for refused-upgrade status/body fidelity, partial errors, transport failures, 101 evidence while frames remain active, and matching JavaScript rewrites through normal/SRI paths. These checks do not establish dynamically assembled URL containment or trusted browser WSS acceptance.

Run `go test -race -count=1 ./internal/rewriter -run '^TestProse'` for prose byte budgets, entity/Unicode handling, literal boundary whitespace, short text, and reversible textarea/option values, including slash-ended form elements.

For compact identity aliases and short display reservations:

```sh
go test -race -count=1 ./internal/scrub -run '^(TestCompactValue|TestValueAlias|TestShortText)'
go test -race -count=1 ./internal/proxy -run '^(TestCompactIdentity|TestContentChangeShortBodyTag|TestDelta)'
go test -race -count=1 ./internal/rewriter -run '^(TestProse|TestWholeDocumentFit)'
```

These checks cover exact alias byte budgets, Unicode case restoration, literal marker safety, concurrent request views, fixed-width namespace exhaustion, bounded display reservations and fallback counts. Real HTTP fixtures verify equal response sizes without shortening diagnostics and restoration of submitted aliases. Short display outputs are distinct only while reservations succeed; one-byte exhaustion remains an explicit lost-signal case. The [size and change-signal report](testing-results-2026-09-26-size-signals.md) records this checkpoint.

Run `go test -race -count=1 ./internal/rewriter ./internal/proxy -run '^TestBodySize|^TestTitle|^TestHTMLQuotedAttrEdits'` for whole-HTML size matching. These tests compare differently sized responses, including gzip input, and require each final decoded length and the signed difference between them to match upstream. They also verify that fitting occurs after provider URL expansion, that SQL-style diagnostics, script text and form values survive, and that insufficient adjustment space is reported rather than taken from functional content. These are synthetic fidelity fixtures, not proof of SQL injection detection on arbitrary sites.

For the offline [paired response comparator](response-deltas.md), run:

```sh
go test -race -count=1 ./internal/delta ./cmd/blinder-diff
go test -race -count=1 ./internal/proxy ./internal/manifest -run 'TestDelta|TestRequestIdentity'
```

The HTTP acceptance fixture uses real local transports, repeated stable baselines, equal-length changed prose, a larger page and an upstream 503 diagnostic. It checks exact body lengths and changed-content signals without exposing original data in the report. Set `BLINDER_DELTA_EVIDENCE_DIR` to a private directory to save its synthetic manifest, selections and report. Separate regressions cover lost/introduced changes, constant size overhead, partial writes, cache provenance, session/context isolation and missing measurements. No browser, live target or certificate changes are required for these checks.

For a local browser form/diagnostic check:

```sh
BLINDER_REVIEW_BROWSER=1 go test -race -count=1 -timeout 130s ./internal/proxy -run '^TestResponseFidelityBrowser$' -v
```

Open the URL in `/private/tmp/blinder-response-browser-url.txt`, check the ordinary paragraph has become verse, click **Validate**, and confirm that the page displays `E_EMAIL`, the validation message and the Unicode input `café`, while its configured identity uses its reversible alias. The fixture verifies that textarea and option values reach upstream as `AcmeCorp & café`, not filler. The upstream response must remain 422. Then navigate to `/review-cleanup` on the fixture origin to finish. The local browser run matched the complete form page at **432 original → 432 rewritten → 432 emitted bytes**. The error response retained its diagnostic text with **277 → 285 → 285 bytes**; error content was not shortened to force a match. This does not establish wider site compatibility or universal content anonymisation.

The synthetic provider flow `TestCaptchaFlowBrowser` passed in the in-app browser on 2026-09-26 before provider origins were isolated. Its nested frames, dynamic scripts and 13 provider requests—including extension methods—used the previous local SOCKS relay. Native operator submission displayed **Solution submitted**, and the original POST resumed with its session cookie and fresh CSRF field. That historical evidence remains valid for its recorded revision; it is not current human-completion acceptance. The fixture needs adaptation and rerunning against the isolated provider routes described below.

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

Preserve the command's exit code when using CI wrappers. The updated GitHub workflow runs the default package race suite, vet with functional tests included, the full `make test-functional` suite and a static build. The provider-origin changes in the latest local acceptance report have not yet been pushed or run in remote CI. Keep acceptance tests active.

## Independent HAR compatibility checks

The fixture contains only synthetic data. It exercises journal materialization, text/gzip, binary requests and responses, redirects/cookies, 101 upgrades, partial HTTP 503 and transport failure status 0. The checker uses the separately maintained [HAR schema](https://github.com/ahmadnassri/har-schema) through a pinned validator, with local semantic assertions. No capture is uploaded, and the validator is not a production dependency.

```sh
har_check_dir=$(mktemp -d /tmp/blinder-har-check.XXXXXX)
npm install --prefix "$har_check_dir" --cache "$har_check_dir/npm-cache" --ignore-scripts --no-audit --no-fund har-validator@5.1.5
BLINDER_HAR_COMPAT_OUTPUT="$har_check_dir/compat.har" go test -race -count=1 ./internal/har -run '^TestHARCompatibilityFixture$'
BLINDER_HAR_VALIDATOR="$har_check_dir/node_modules/har-validator" node scripts/validate-har.cjs "$har_check_dir/compat.har" --fixture
```

`har-validator` is deprecated; this isolated, pinned check tests the historical HAR 1.2 format. Schema acceptance does not prove viewer compatibility or replay. Binary request `postData._encoding` is a Blinder extension.

Playwright 1.62.1's installed HAR importer/matcher was tested separately, without launching a browser. It requires binary request attachments instead of that extension. Export a consumer copy with the optional local adapter:

```sh
node scripts/export-playwright-har.cjs "$har_check_dir/compat.har" "$har_check_dir/playwright-export"
node --test scripts/export-playwright-har.test.cjs
BLINDER_PLAYWRIGHT_MODULE=/absolute/path/to/installed/playwright \
  node --test scripts/export-playwright-har.test.cjs
```

The export directory must be new. The source capture remains unchanged; keep exported `capture.har` and its private attachments together. The last command enables the independent consumer test, which otherwise skips. Matching the original binary POST bytes and response is verified; viewer UI, browser replay, gzip fulfillment, transport failures and WebSocket frame replay are not established by this check. See [HAR export details](playwright-har-export.md).

## CAPTCHA browser acceptance

Configured operator controls are served at `https://blinder-operator.localhost:<listen-port>/__blinder/captcha/`. Use the **Browser login** URL printed at startup to establish the temporary operator cookie. The hostname resolves locally and uses the same listener as the target proxy, but a separate browser origin. Only loopback peers can access controls. Target-origin control URLs return 404. The old `/__blinder/captcha/res` endpoint returns 404 on both target and operator origins; Tor-routed resources now use separate `captcha-<hash>.localhost` origins. Treat the printed login token as an operator credential.

Run the browser fixtures **one at a time**: their host-only operator cookie shares a hostname across ports. They use synthetic data and HTTP localhost secure contexts, so they do not verify production HTTPS certificate trust or solve live CAPTCHAs. Opt-in skips are not acceptance passes.

For built-in/custom configuration, complete-origin routing and certificate-name coverage:

```sh
go test -race -count=1 ./internal/captcha ./cmd/blinder -run '^(TestParseConfig|TestProviderRoutes|TestProviderResourceOrigins|TestProviderCertificate)'
go test -race -count=1 ./internal/captcha -run '^(TestProviderAliasRelay|TestProviderRelayRestoresMethod|TestProviderRelayRejectsInvalidRestoredMethods|TestProviderRelayRejectsMultiplePreflightMethods|TestProviderRuntimeOriginRecovery)'
go test -race -count=1 ./internal/proxy -run '^(TestProviderOrigin(Routes|Rejects|Forwards|Document|BrowserCookie)|TestProviderRestrictedBase|TestProviderStaticReturn|TestProviderHTMLNegotiates|TestProviderLegacy)'
```

These checks cover full-origin distinctions and default-port equivalence, strict config validation, URL-regex enforcement, direct-provider exceptions, opaque URL/body bytes, reserved credentials, browser cookie scoping, provider errors, arbitrary HTTP methods and preflight method restoration. They also cover static base/refresh routing and rejection of the old relay endpoints. They do not exhaust every combination of main config files, provider files and CLI overrides.

For the current direct-versus-proxy browser comparison:

```sh
BLINDER_PROVIDER_BROWSER=1 go test -race -count=1 -timeout 200s ./internal/proxy -run '^TestProviderOriginBrowserControlPairs$' -v
```

Open the URL in `/private/tmp/blinder-provider-browser-url.txt` in Chrome within 180 seconds. The fixture runs seven direct cases, then their proxied counterparts: script allow/deny, a readable HTTP 500 response through CORS, denied preflight, denied ACAO, isolated provider frame and denied provider script. It records `/private/tmp/blinder-provider-browser-report.json`, comparing browser outcomes and actual provider requests through the recording SOCKS transport. A connection count alone is insufficient: the denied cases must retain their missing resource requests. Chrome passed all seven pairs (14 case observations), including the original HTTP 500 diagnostic body. The initial extension-method restoration failure is retained separately from the passing rerun.

Provider HTML uses original inline script/style bytes and CSP/SRI metadata, without an injected runtime. The operator's raw challenge `srcdoc` remains opaque and has a completion bridge. The current comparison covers static URLs and these control decisions over HTTP; host-only cookie scoping is tested separately with an HTTP cookie jar. Dynamic absolute URLs, upstream SameSite/sibling-domain cookie relationships and complete human completion need separate acceptance. No certificate trust is installed by these fixtures, and this comparison does not establish provider-alias HTTPS trust or live Tor acceptance.

For authenticated popup and service-worker isolation:

```sh
BLINDER_REVIEW_BROWSER=1 go test -race -count=1 -timeout 150s ./internal/proxy -run '^TestCaptchaSessionBrowserOperatorIsolation$' -v
```

Open the URL in `/private/tmp/blinder-captcha-browser-url.txt`. The fixture first verifies a cookie-authenticated operator document, then opens the target page and activates its service worker. When enabled, click **Run popup isolation check**. A real popup must reach the authenticated operator endpoint; blocking the popup does not count as isolation. The test requires denied target access to operator DOM/fetch/frame content, denied operator worker registration, no operator cookie on target requests, and no operator navigation interception by the active target worker. It automatically unregisters the worker, clears the cookie on the operator origin and finishes. Results are written to `/private/tmp/blinder-captcha-browser-result.json`.

The earlier complete synthetic operator-flow fixture remains available for adaptation and rerunning; its prior pass predates isolated provider routes:

```sh
BLINDER_REVIEW_BROWSER=1 go test -race -count=1 -timeout 190s ./internal/proxy -run '^TestCaptchaFlowBrowser$' -v
```

The historical flow uses `/private/tmp/blinder-flow-browser-url.txt` and records `/private/tmp/blinder-flow-browser-result.json`. Its acceptance requires provider redirects, scripts, frames, POST/fetch and XHR, PUT/PATCH/DELETE/OPTIONS, PROPFIND and `vendor.sync`, then operator submission and resumption with the original username, refreshed CSRF and target cookies. Update its provider assumptions and rerun the full flow before recording current completion acceptance. This is a local SOCKS fixture, not a live Tor circuit.

`TestCaptchaProviderOperatorChallengeBrowserRoute` and `TestCaptchaBrowserRoutingIframeAndProviderRoute` also exercise the earlier operator relay fixtures. Keep their historical evidence separate from the new provider-origin comparison. Current provider requests do not require an active challenge session: browser-managed provider cookies support ordinary widgets as well as pending challenges. All OPTIONS, including CORS preflights, go upstream; Blinder translates real policy responses rather than granting preflight locally.

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

The unsupported-encoding link is a deliberate negative test: its body is not valid Brotli despite its `br` header, and HTTP 502 is expected. The document link deliberately becomes a transparent GIF. Their tooltips identify these outcomes even when paranoid mode replaces the visible link text. The WebSocket fixture sends a heartbeat every 20 seconds; its page reports a close code on disconnect rather than leaving a generic failure message. Neither heartbeat traffic nor a successful upgrade alone establishes arbitrary real-application WebSocket compatibility.

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

Preflight exits after setup. It detects the running OS and prints the fingerprint, expiry, public certificate path, action taken, platform trust status and OS-specific advice. It also checks the primary alias, configured extra-origin aliases and, when a CAPTCHA config path is supplied, `blinder-operator.localhost` separately. With `--tor`, configured provider aliases are included in certificate SANs and the endpoint checks. Provider config loads before certificate preparation. Use the same alias, extra-origin, CAPTCHA, Tor and certificate-store options as the intended proxy run so these checks cover its browser hostnames. Linux detection reads `ID`, `VERSION_ID` and `ID_LIKE` from `/etc/os-release`, falling back to `/usr/lib/os-release` only if the first file is missing. It never executes the file; absent or malformed identity information produces generic Linux advice. [OS release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html).

For a Tor CAPTCHA configuration, the certificate-only check is:

```sh
./blinder --preflight --listen 127.0.0.1:18099 --tor \
  --captcha-config captcha.yaml --cert-dir /path/to/session-certs
```

This prepares/checks the configured endpoint names without connecting to Tor or installing trust. Test browser trust for each displayed provider alias separately; generating the SANs does not establish browser acceptance.

Exit 0 means platform verification passed for the displayed **listen host**; exit 2 means that host still needs platform trust setup; exit 1 means preparation failed. Alias/operator results are reported independently and do not change this exit status. Client-specific trust can succeed while preflight continues to return 2. These platform checks do not test DNS resolution or the selected browser's trust store. No upstream/Tor or listen-port test is performed by certificate-only commands. Normal proxy startup reports missing trust but continues so clients with their own certificate-file settings can connect.

#### Certificate advice by OS

**macOS:** copy the exact `--trust-cert` command printed by preflight. It includes the current certificate directory, alias and listen address. For the default store and alias in this UAT example:

```sh
./blinder --trust-cert --listen 127.0.0.1:18099
```

Review the fingerprint, type `yes` and complete any OS approval. This installs the displayed server certificate for SSL to that host in the current user's login Keychain; it does not install a signing CA or change administrator trust. Declining leaves trust unchanged. If platform trust is already verified, installation is skipped. Run preflight in a new process after changing trust, then verify the browser/scanner separately.

The macOS `--trust-cert` action installs trust for the **listen host only**, even when preflight lists several hostnames on the certificate. CAPTCHA UAT requires verified browser connections to `blinder-operator.localhost` and, in Tor mode, each provider alias on that port; multi-origin UAT requires each extra alias as well. Compare the same fingerprint and complete the selected client's trust setup for those hostnames separately. A ready result for `127.0.0.1` does not imply the operator or alias result is ready.

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

The default certificate directory is under the platform's user configuration directory, keyed by alias, listen host and additional alias names (changing only the port reuses it). Adding Tor-routed providers can select a different default store. To choose an explicit store, add `--cert-dir "$uat_dir/certs"` to **both** setup commands and the proxy command. A new store is created with mode 0700. `identity.pem` contains the private key plus certificate and must have mode 0600; only `certificate.pem` is intended for client import. Missing or damaged public exports are regenerated from the identity. Existing directories with broad permissions, unsafe file paths and damaged private identities are reported for operator repair; they are not silently overwritten. Restore a known valid identity or select a new private directory if recovery is needed.

Normal proxy startup also creates `version-signing.key` (32 random bytes, mode 0600) in this private store. It survives certificate renewal and authenticates expired SRI references after restart. Back it up with the private state; corruption or unsafe permissions stop startup instead of silently rotating ownership. Removing/changing the store loses the ability to recognise previously issued references, so discard old client pages when deliberately replacing it. Ephemeral TLS still uses the default endpoint directory for this separate key.

`TestVersionRegistryProcessPersistence` checks issuance and expired-reference ownership in separate OS processes.

Persistent certificates last 90 days. Startup renews them when seven days or less remain, and reissues them if required endpoint names change. A replacement changes the fingerprint and needs new trust approval. Previous public certificates are retained as `previous-<fingerprint>.pem`; use them to identify and remove obsolete trust. On macOS, the operator can remove the old user trust setting with `security remove-trusted-cert` and the chosen previous public certificate path, then manage any remaining certificate entry in Keychain Access. Other clients use their own certificate removal interface.

The operator hostname and configured Tor-provider aliases are required certificate SANs. An explicit store whose certificate lacks required names is reissued with a new fingerprint; its separate version-signing key remains unchanged. Recheck browser trust for target, operator and provider endpoints after reissue. This provider-routing implementation does not install additional trust automatically.

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

- **Absolute links and redirects:** registered same-upstream links and resource URLs should retain the validated browser entry hostname and port; registered extra origins should use distinct aliases. Verify resolution and certificate trust for those aliases before accepting the workflow. Dynamically assembled or escaped URLs require separate observation; static rewriting does not establish complete browser network containment.
- **Documents and fonts:** inspect `/document.pdf`. Binary content is replaced with a GIF placeholder and served as `image/gif`; document/font rendering fidelity is not established. The fixture PDF is a metadata sample, not a complete rendered document.
- **Images and executable links:** compare actual image requests, status, load/error events and natural dimensions against the direct target, including a corrupt image and a failed HTTP response. Check permitted and denied `javascript:` navigation under the original corresponding CSP. Supported raster masking and package tests do not close unsupported-format, decoder or arbitrary-JavaScript fidelity gaps.
- **Privacy boundaries:** encoded HTML/JS, arbitrary unknown binary content, cookie values and binary/control WebSocket payloads need separate policy and tests. A passing fixture is not evidence that every response is anonymized.
- **Evidence:** verify imports into the intended HAR tool. Independent schema, synthetic semantic and Playwright importer/matcher checks pass; binary requests need the optional Playwright export adapter. Selected viewer UI, browser replay and WebSocket frame capture remain separate acceptance work; handshake evidence is covered by local regressions.
- **Routing and scale:** complete the live Tor track above; complex multi-origin applications, long-running sessions, load, memory growth and all release platforms remain separate test work.

Release acceptance requires the open functional failures to be fixed, the full functional command to pass, and the selected operator workflow to have evidence and explicit sign-off. Acceptance of Tor mode also requires the live Tor/onion track; do not substitute the local SOCKS fixture. Keep unsupported capabilities visible in the release scope.

### External CSP and SRI comparison

Run `BLINDER_REVIEW_BROWSER=1 go test -race -count=1 -run '^TestExternalControlFidelityBrowser$' -v ./internal/proxy` and open the local HTTPS URL written to `/private/tmp/blinder-external-csp-browser-url.txt` in the already trusted Chrome profile. The fixture runs the direct baseline followed by Blinder and verifies execution, policy violations, resource errors and upstream request counts. It writes `/private/tmp/blinder-external-csp-browser-result.json`. See the [29-pair acceptance record](testing-results-2026-09-26-external-csp.md). Do not replace a browser trust failure with a certificate bypass or count an opt-in skip as a pass.
