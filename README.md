<p align="center">
  <img src="docs/assets/blinder-header.svg" alt="Blinder — less identity, more signal. A content-blind reverse proxy." width="100%">
</p>

<p align="center">
  <strong>A local reverse proxy for content-blind security scanning.</strong><br>
  Go · Local HTTPS · HTTP &amp; WebSocket · Tor / SOCKS5
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> &nbsp; / &nbsp;
  <a href="#certificates">Certificates</a> &nbsp; / &nbsp;
  <a href="#tor">Tor</a> &nbsp; / &nbsp;
  <a href="#evidence">Evidence</a> &nbsp; / &nbsp;
  <a href="#development">Development</a>
</p>

---

Blinder lets you inspect an application's technical behavior while reducing the identity information exposed to your scanner or LLM workflow. It rewrites configured domains, identity tokens and selected response content, and keeps original HTTP evidence on the operator's side.

```text
 Browser / scanner ── HTTPS ── Blinder ── direct or Tor ── Target
                                │
                                └── Original evidence → operator
```

| | What you get |
| :--- | :--- |
| **Content scrubbing** | Configured identities and domain references rewritten across supported HTTP content and WebSocket text. |
| **Session handling** | Reversible cookie names and recognized browser Origin/Referer mapping for HTTP and WebSocket requests. |
| **Private routing** | Upstream HTTP and WebSocket through Tor SOCKS5, with remote hostname resolution. |
| **Local HTTPS** | Persistent certificates, OS-aware setup advice and explicit macOS user trust. |
| **Evidence** | Original HTTP HAR, request manifest, domain mapping and scrub report. |

**Development release.** The tested workflow is single-target scanning. Full multi-origin browsing and complete anonymization remain open engineering work; review [supported behavior and delivery gates](docs/capabilities.md) when choosing a workflow.

## Quick start

Build with **Go 1.26+**, then run the standalone binary. Use targets you are authorized to test.

```sh
git clone https://github.com/Splinters-io/blinder.git
cd blinder
make build
./blinder --preflight
```

Follow the OS-specific certificate advice, then start a session:

```sh
capture_dir=$(mktemp -d)
./blinder --target https://your-authorized-target.example \
  --identity YourOrganisation \
  --har "$capture_dir/session.har" \
  --output "$capture_dir/output"
```

Point your browser or scanner at **`https://127.0.0.1:8099`** as its target URL. Blinder is a reverse proxy. Add multiple identity tokens with repeated `--identity` flags.

Stop with **Ctrl-C** to save the session evidence. Startup and evidence-write failures return a nonzero exit status.

## Certificates

Preflight generates or reuses the local certificate and prints its public path, fingerprint, expiry and next steps.

| Platform | Setup |
| :--- | :--- |
| **macOS** | Run the printed `--trust-cert` command, review the fingerprint and approve user Keychain trust. |
| **Ubuntu / Linux** | Use the printed `curl --cacert` command or your browser/scanner's server-certificate trust settings. |

Use `--cert-dir DIR` for a chosen private store. Certificates persist across restarts; `--ephemeral-cert` selects a temporary identity. Preflight exit **2** means platform trust needs setup; a client using its own certificate file can still connect successfully.

The endpoint store also holds a private `version-signing.key`, independent of certificate renewal. Keep it across restarts so expired resource references remain recognisable. `--ephemeral-cert` keeps TLS temporary; resource-reference ownership still persists in the default endpoint store.

[Certificate setup, OS guidance and renewal →](docs/testing.md#local-certificate-trust)

## Tor

Start your Tor service and wait for bootstrap, then select its SOCKS endpoint:

```sh
./blinder --target http://your-service.onion \
  --tor --tor-addr 127.0.0.1:9050 \
  --identity YourOrganisation
```

Clearnet targets can use the same route. Target TLS verification stays enabled. Tor failures return an error without falling back to a direct target connection.

[Tor setup and live acceptance checklist →](docs/testing.md#live-tor-uat)

## Evidence

Keep original captures on the operator's side; they contain real target data.

| Output | Contents |
| :--- | :--- |
| `--har FILE` | Original HTTP requests and responses before scrubbing. |
| `blinder-manifest.json` | HTTP outcomes, replacement counts and extracted identity metadata. |
| `blinder-dealias.json` | Alias-to-original domain mapping. |
| `blinder-scrub-report.json` | Recorded identity/domain matches and aggregate counts. |

JSON reports are saved under `--output DIR` with owner-only file permissions. `--har-max-body` bounds each captured request/response body, with truncation recorded in the HAR. Shutdown attempts both HAR and report output even if one fails.

[Capture behavior and artifact format →](docs/capabilities.md#evidence)

## Development

```sh
make test              # Package regressions with race detection
make lint              # Go vet
make test-functional   # Real CLI, TLS, sessions, evidence, WebSocket and SOCKS5
```

The local functional suite passes **29/29 scenarios**, including the acceptance checks and eight Tor/SOCKS scenarios. GitHub Actions is configured to run the functional suite alongside package tests, vet and a static build. Browser/scanner, OS trust and successful live Tor/onion acceptance are tracked separately.

[Testing & UAT guide](docs/testing.md) · [Test results](docs/testing-results-2026-09-23.md) · [Delivery gates](docs/capabilities.md#remaining-delivery-gates) · [Technical specification](SPEC.md)

---

<p align="center">
  <img src="docs/assets/blinder-mark.svg" alt="Blinder's redacted empty-set project mark" width="48" height="48"><br>
  <sub>LESS IDENTITY. MORE SIGNAL.</sub><br>
  <sub><a href="docs/brand.md">Project artwork</a></sub>
</p>
