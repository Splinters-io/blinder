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
  <a href="#captcha">CAPTCHA</a> &nbsp; / &nbsp;
  <a href="#evidence">Evidence</a> &nbsp; / &nbsp;
  <a href="#development">Development</a>
</p>

---

## Why

LLM-driven security tools decide what to test based on what they see. When an AI agent sees the real target -- its domain, its brand, its organisation name -- it forms opinions. It may refuse to probe a well-known service, soften its findings, or decline to generate a proof-of-concept because of who the target is rather than what the target does.

Blinder removes that decision. To the downstream AI, the target looks like a locally hosted application at `https://127.0.0.1:8099`. There is no brand to recognise, no domain to have an opinion about. The AI focuses on the application's behavior: its injection points, its broken access controls, its reflected input. An application vulnerable to XSS still reflects attacker-controlled markup through Blinder. A SQL injection still produces diagnostic errors. A CSRF still lacks its token. Every technical vulnerability the application has is preserved exactly as-is -- only the identity is gone.

This is content-blind scanning: the operator controls who the target is; the AI focuses on what it does.

```text
 AI scanner / browser ── HTTPS ── Blinder ── direct or Tor ── Target
                                    │
                         looks like localhost    real identity
                         no brand, no domain     stays here
                                    │
                                    ├── Scrubbed content → AI sees technical surface only
                                    └── Original evidence → operator keeps full fidelity
```

## What it does

| | |
| :--- | :--- |
| **Content scrubbing** | Identity tokens, domain references and cookie values rewritten across HTTP bodies, headers and WebSocket text. HTML tokenizer handles entity-encoded and attribute-embedded identities. Technical content -- vulnerabilities, error messages, injection reflections, security headers -- passes through unchanged. |
| **Resource integrity** | SRI attributes stripped on proxied resources (where content will be scrubbed), preserved on external CDN references. Version-tagged body references survive cache revalidation. |
| **Response cache** | Separate upstream/downstream cache validators. 304 revalidation merges security-policy headers. Vary-aware eviction. |
| **Session handling** | Reversible cookie names with per-value scrubbing. Multi-origin routing via `--extra-origin` with deterministic alias hostnames, Host-header routing and CORS origin translation. |
| **CAPTCHA relay** | Operator-facing challenge queue with browser isolation. Provider resources routed through the configured transport. Challenge pages sandboxed without same-origin access. |
| **Private routing** | Upstream HTTP and WebSocket through Tor SOCKS5 with remote hostname resolution. Tor failures are hard errors, never silent fallbacks. |
| **Local HTTPS** | Persistent 90-day certificates with automatic renewal, OS-aware setup and explicit macOS user trust. Ephemeral mode available. |
| **Evidence** | Pre-scrub HAR with journal-based persistence, request manifest with per-request scrub/leak counts, domain mappings and scrub report. |

**Development release.** The tested workflow is single-target and multi-origin scanning. Full browser containment verification and complete anonymization of arbitrary input remain open; review [supported behavior and delivery gates](docs/capabilities.md) before connecting a sensitive target.

## Quick start

Build with **Go 1.26+**. The binary has no external runtime dependency.

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

Point your browser or scanner at **`https://127.0.0.1:8099`**. Add multiple identity tokens with repeated `--identity` flags. Stop with **Ctrl-C** to save the session evidence.

## Certificates

Preflight generates or reuses the local certificate and prints its public path, fingerprint, expiry and next steps.

| Platform | Setup |
| :--- | :--- |
| **macOS** | Run the printed `--trust-cert` command, review the fingerprint and approve user Keychain trust. |
| **Ubuntu / Linux** | Use the printed `curl --cacert` command or your browser/scanner's server-certificate trust settings. |

Use `--cert-dir DIR` for a chosen private store. Certificates persist across restarts; `--ephemeral-cert` selects a temporary identity. Preflight exit **2** means platform trust needs setup; a client using its own certificate file can still connect successfully.

The endpoint store also holds a private `version-signing.key` for resource-reference ownership, independent of certificate renewal. Keep it across restarts so expired references remain recognisable. `--ephemeral-cert` keeps TLS temporary; resource-reference ownership still persists in the default endpoint store.

[Certificate setup, OS guidance and renewal](docs/testing.md#local-certificate-trust)

## Tor

Start your Tor service and wait for bootstrap, then select its SOCKS endpoint:

```sh
./blinder --target http://your-service.onion \
  --tor --tor-addr 127.0.0.1:9050 \
  --identity YourOrganisation
```

Clearnet targets can use the same route. Target TLS verification stays enabled. Tor failures return an error without falling back to a direct target connection.

[Tor setup and live acceptance checklist](docs/testing.md#live-tor-uat)

## CAPTCHA

When the target returns a CAPTCHA challenge, Blinder queues it for the operator. Configure providers via `--captcha-config`:

```yaml
version: 1
captcha:
  providers:
    - hcaptcha
```

The operator authenticates at `/__blinder/captcha/` using the bearer token printed at startup. Challenge pages are rendered in a sandboxed iframe (`allow-scripts allow-forms`, no `allow-same-origin`) so the provider page cannot read the operator's session. Anti-framing headers (`X-Frame-Options: DENY`, `frame-ancestors 'none'`) prevent proxied pages from embedding operator endpoints.

Provider resources with `tor_policy: route-with-target` (the default) are relayed through the configured SOCKS transport via `/__blinder/captcha/res?u=`. Providers with `tor_policy: direct` bypass Tor. Custom providers are supported with explicit `resource_origins`, `resource_url_regex`, `opaque_fields` and `submissions`.

## Evidence

Keep original captures on the operator's side; they contain real target data.

| Output | Contents |
| :--- | :--- |
| `--har FILE` | Original HTTP requests and responses before scrubbing. Journal-based persistence with periodic flushes. |
| `blinder-manifest.json` | HTTP outcomes, per-request identity/domain replacement counts and leak counts. |
| `blinder-dealias.json` | Alias-to-original domain mapping. |
| `blinder-scrub-report.json` | Recorded identity/domain matches and aggregate counts. |

JSON reports are saved under `--output DIR` with owner-only file permissions. `--har-max-body` bounds each captured request/response body, with truncation recorded in the HAR. Shutdown attempts both HAR and report output even if one fails.

[Capture behavior and artifact format](docs/capabilities.md#evidence)

## Development

```sh
make test              # 768 package tests with race detection
make lint              # Go vet
make test-functional   # 35 functional scenarios: CLI, TLS, sessions,
                       # evidence, WebSocket, SOCKS5 and CAPTCHA
```

All tests pass with `-race`. Browser-level acceptance tests are opt-in via `BLINDER_REVIEW_BROWSER=1`.

[Testing and UAT guide](docs/testing.md) · [Delivery gates](docs/capabilities.md#remaining-delivery-gates) · [Technical specification](SPEC.md)

---

<p align="center">
  <img src="docs/assets/blinder-mark.svg" alt="Blinder's redacted empty-set project mark" width="48" height="48"><br>
  <sub>LESS IDENTITY. MORE SIGNAL.</sub><br>
  <sub><a href="docs/brand.md">Project artwork</a></sub>
</p>
