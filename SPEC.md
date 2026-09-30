# Blinder — Technical Specification

Standalone content-blind reverse proxy for exposure-protected security scanning.

**Version:** 2.0 (Go rewrite)
**Status:** Draft
**Date:** 2026-09-23

**Implementation status:** This is a draft design, including goals that are not
fully implemented. See [README.md](README.md) for the current boundaries and
known limitations. In particular, oversized HTTP responses are rejected with
502 rather than streamed; unsupported content encodings are rejected; malformed
or ambiguous JSON is replaced with `null`; and WebSocket binary/control payloads
are not a universal anonymization boundary. The “zero leaks” principle below is
a design goal, not a verified claim about arbitrary input.

---

## 1. Problem Statement

Security scanners need to test live web applications without the operator's LLM seeing target identity — domains, organisation names, emails, branding, or content. The scanner must receive the full technical surface (headers, cookies, forms, injection points, status codes, security headers) while the identity layer is systematically stripped.

A secondary problem: even without an LLM in the loop, bug bounty researchers want to scan .onion services and capture complete HTTP transaction evidence (HAR files) through a privacy-preserving proxy.

## 2. Solution

Blinder is a standalone reverse proxy binary. It sits between any HTTP client (scanner, browser, curl) and the real target. Every response passes through a multi-stage scrub pipeline that removes identity while preserving technical surface. Optionally, the raw (pre-scrub) HTTP transactions are captured in HAR 1.2 format for evidence and replay.

The operator also sets up trust for the local HTTPS endpoint presented by Blinder. Browsers and scanners must accept or trust its certificate before they can use that connection. Startup prepares or reuses a persistent certificate and reports local trust status. `--preflight` performs certificate setup without serving traffic, and `--trust-cert` offers an explicit macOS user-trust action. Local certificate trust is separate from upstream certificate verification and Tor connectivity. See the [operator guide](docs/testing.md#local-certificate-trust).

## 3. Design Principles

- **Zero leaks.** Every byte leaving the proxy toward the client passes through the scrub gate. Defence in depth: content-type-specific rewriters handle the bulk, the universal scrub gate catches anything they missed.
- **Immutability.** Configuration, scrub rules, and domain maps are immutable after construction. Request handling produces new response objects; nothing mutates shared state.
- **Fail closed.** If a response cannot be parsed or scrubbed, replace it with a safe placeholder rather than passing it through. Unknown content types get domain scrubbing at minimum.
- **Content-blind by default.** The proxy does not need to understand the application's business logic. It operates on HTTP primitives: headers, bodies, content types, status codes.
- **Evidence-grade capture.** HAR output is written atomically, timestamped, and includes both request and response in full fidelity (pre-scrub). The HAR file is the operator's evidence — it never reaches the client.

## 4. Architecture

```
                    ┌─────────────────────────────────────┐
                    │            BLINDER PROXY             │
 Client ──HTTPS──> │                                       │
 (scanner,         │  TLS Termination                      │
  browser,         │       │                               │
  curl)            │  Request Rewrite (alias → real)       │
                   │       │                               │
                   │  ┌────┴────┐                          │
                   │  │ Upstream │──── HTTPS/SOCKS5 ──────>│ Target
                   │  │ Fetch   │     (direct or Tor)      │ (.com or .onion)
                   │  └────┬────┘                          │
                   │       │                               │
                   │  HAR Writer (pre-scrub, atomic)        │
                   │       │                               │
                   │  Content Rewriter (per content-type)   │
                   │       │                               │
                   │  Scrub Gate (universal final pass)     │
                   │       │                               │
                   │  Response to Client (scrubbed)         │
                   └─────────────────────────────────────┘
```

### 4.1 Standalone Binary

Single `blinder` binary, no runtime dependencies. Cross-compiled for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.

### 4.2 Sidecar Model

Blinder runs in a separate process from the scanner. The scanner connects to `https://127.0.0.1:<port>` and sees only scrubbed responses. The operator starts blinder in a private terminal with the real target URL — that URL never enters the scanner's context.

## 5. Modules

### 5.1 `cmd/blinder/main.go`

CLI entry point. Flag parsing, signal handling (SIGINT/SIGTERM for graceful shutdown), startup banner.

### 5.2 `internal/config`

Immutable configuration. Constructed once from CLI flags, never modified.

```go
type Config struct {
    TargetURL       string       // real target (never exposed to client)
    ListenAddr      string       // default "127.0.0.1:8099"
    AliasDomain     string       // default "target-001.local"
    IdentityTokens  []string     // org names, brands to scrub
    VerifyTargetTLS bool         // default true
    Paranoid        bool         // strip all text, JS paths, CSS identifiers
    Tor             *TorConfig   // nil = no Tor
    HAR             *HARConfig   // nil = no HAR capture
    OutputDir       string       // manifest/reports output
}

type TorConfig struct {
    SOCKSAddr string  // default "127.0.0.1:9050"
}

type HARConfig struct {
    FilePath    string  // output .har file path
    MaxBodySize int64   // max body size to capture (default 10MB)
}
```

### 5.3 `internal/proxy`

Reverse proxy core using `net/http/httputil.ReverseProxy` with a custom `Transport`.

Responsibilities:
- TLS termination (local CA with session leaf certificates)
- Request rewriting (alias domain → real target in Host, Referer, Origin)
- Upstream fetch (direct HTTPS or via SOCKS5 for Tor)
- Response capture (pre-scrub, for HAR)
- Pipeline dispatch: rewriter → scrub gate → client

The proxy uses `http.RoundTripper` composition:
1. Base: `http.Transport` (direct) or SOCKS5-dialing transport (Tor)
2. Wrapped with HAR-capturing middleware
3. Response bodies read fully, then passed through the rewrite pipeline

### 5.4 `internal/rewriter`

Content-type-specific response rewriting. Each rewriter is a pure function: `(body []byte, contentType string, path string) → []byte`.

| Content Type | Rewriter | What it does |
|---|---|---|
| `text/html` | `rewriteHTML` | Strip comments, scrub domains/emails, replace title/meta/text nodes, replace images with 1x1 GIF data URI, preserve form structure |
| `application/json` | `rewriteJSON` | Scrub domain/email references in string values |
| `text/javascript` | `rewriteJS` | Scrub domain references |
| `text/css` | `rewriteCSS` | Scrub domain references in `url()` values |
| `text/xml` | `rewriteXML` | Scrub domain references |
| `image/*`, `video/*`, etc. | `rewriteBinary` | Replace with minimal placeholder, extract metadata |
| fallback | `rewriteGeneric` | Domain scrubbing on UTF-8 text |

Header rewriting is separate:
- **Passthrough headers:** security headers, technology fingerprints (Server, X-Powered-By, CSP structure, HSTS, CORS, etc.)
- **Scrub headers:** Location, Content-Location, Link, Refresh, Set-Cookie domains
- **CSP rewriting:** preserve keywords ('self', 'unsafe-inline', nonces, hashes), scrub domains

### 5.5 `internal/scrub`

Universal scrub gate. Final checkpoint — every string leaving the proxy passes through.

Scrub order (each pass is independent, no mutation of shared state):
1. Target domain references (case-insensitive, exact match)
2. Identity tokens (configurable, case-insensitive)
3. Email addresses (replace with `user@<alias>`)
4. Remaining domain references (stable SHA-256 alias)
5. Public IPv4 addresses (replace with RFC 5737 TEST-NET-3: `203.0.113.1`)

Domain aliasing is deterministic: `SHA256(domain)[:8]` → `host-<hex>.<alias_domain>`. Same domain always gets the same alias across requests, so the client can correlate "same origin" without knowing the real domain.

Safe domains pass through un-aliased: googleapis.com, cloudflare.com, w3.org, schema.org, iana.org, *.local, *.localhost, *.test, *.example.com.

The gate maintains a leak log (context, type, count) for the scrub report.

### 5.6 `internal/metadata`

Binary file metadata extraction. When the rewriter replaces a binary (image, PDF, font, office doc), this module extracts structural metadata from the original bytes.

Split into two categories:
- **Technical** (sent to client as `X-Blinder-Meta` header): format, dimensions, embedded JS/macros, producer software, form fields, encryption
- **Identity** (vaulted in manifest, never sent to client): author, GPS, company, copyright, title

Extraction is purely structural (byte-level parsing of format headers), not library-dependent. No CGo, no image decoders. Supported formats:

| Format | Technical fields | Identity fields |
|---|---|---|
| JPEG | dimensions, EXIF software, progressive, ICC profile | GPS, artist, camera make/model |
| PNG | dimensions, color type, chunk types, ICC | — |
| GIF | dimensions, version, color table | — |
| WebP | dimensions, subformat | — |
| BMP | dimensions | — |
| PDF | version, /JavaScript, /AcroForm, /XFA, /OpenAction, /Encrypt, Producer | Author, Title, Company |
| OOXML (.docx/.xlsx/.pptx) | macros, ActiveX, OLE objects, application version | Author, Company, Title |
| Font (.ttf/.otf/.woff/.woff2) | SFNT type, table count, version | Copyright, foundry, vendor URL |
| Video (MP4/MKV/AVI) | container format, ftyp brand | — |
| Audio (MP3/WAV/Ogg/FLAC) | container format, ID3 presence | — |

### 5.7 `internal/tor`

SOCKS5 transport for Tor connectivity.

```go
func NewTorTransport(socksAddr string, tlsConfig *tls.Config) *http.Transport
```

Uses `golang.org/x/net/proxy` to create a SOCKS5 dialer. The dialer is composed with the standard `http.Transport` so all upstream connections route through Tor. TLS handshake happens through the SOCKS tunnel.

Validation at startup:
- Verify SOCKS5 proxy is reachable (TCP connect to socksAddr)
- For .onion targets, Tor is mandatory — refuse to start without `--tor`
- Log the Tor circuit status if possible (SOCKS5 handshake success)

### 5.8 `internal/har`

HAR 1.2 writer. Captures the **real** (pre-scrub) HTTP transactions.

```go
type Writer struct {
    entries []Entry
    mu      sync.Mutex
}

func (w *Writer) Record(req *http.Request, reqBody []byte, resp *http.Response, respBody []byte, elapsed time.Duration)
func (w *Writer) Flush(path string) error
```

HAR structure (per spec http://www.softwareishard.com/blog/har-12-spec/):
- `log.creator`: `{"name": "blinder", "version": "2.0.0"}`
- `log.entries[]`: one per request/response pair
  - `request`: method, url, httpVersion, headers, queryString, postData, headersSize, bodySize
  - `response`: status, statusText, httpVersion, headers, content (mimeType, size, text/encoding), headersSize, bodySize
  - `timings`: send, wait, receive (from elapsed duration)
  - `startedDateTime`: ISO 8601

Body capture rules:
- Text bodies (HTML, JSON, JS, CSS, XML): captured as UTF-8 text
- Binary bodies under `maxBodySize`: captured as base64 with `encoding: "base64"`
- Binary bodies over `maxBodySize`: truncated, `comment: "truncated at <N> bytes"`
- The HAR contains the **real** response (pre-scrub). It is written to the operator's filesystem, never sent to the client.

Flush is atomic: write to a temp file, then rename. This prevents partial writes if the process is killed.

### 5.9 `internal/manifest`

Audit trail and de-aliasing map. Written on shutdown.

Three output files:
- `blinder-manifest.json`: per-request scrub log, session summary, identity vault
- `blinder-dealias.json`: `{alias → real_domain}` map for post-scan report translation
- `blinder-scrub-report.json`: leak counts by type and context

### 5.10 `internal/ws`

WebSocket proxying. Handles the HTTP Upgrade handshake and bidirectional frame relay with scrubbing.

```go
func HandleUpgrade(w http.ResponseWriter, r *http.Request, target *url.URL, scrubber *scrub.Gate) error
```

Flow:
1. Client sends `Upgrade: websocket` request
2. Proxy rewrites the request (alias → real domain in Host/Origin) and forwards to upstream
3. Upstream responds with `101 Switching Protocols`
4. Proxy hijacks both connections and enters relay mode
5. Frames are relayed bidirectionally with content scrubbing:
   - **Text frames (opcode 0x1):** domain scrubbing applied via the scrub gate before forwarding to client. Server→client direction only — client→server frames pass through with alias→real rewriting.
   - **Binary frames (opcode 0x2):** passed through unmodified (binary WebSocket data is typically protocol buffers, MessagePack, or application-specific binary — not worth parsing for domains)
   - **Control frames (ping/pong/close):** relayed verbatim
6. HAR capture: the initial HTTP Upgrade request/response is recorded. Individual WebSocket frames are not captured in the HAR (HAR 1.2 has no WebSocket frame model).

Uses Go's `net/http` Hijacker interface — no external WebSocket library needed. The proxy reads/writes raw frames using the RFC 6455 wire format directly (simple: 2-byte header + optional mask + payload).

Connection lifecycle:
- If either side sends a Close frame, relay it and shut down both sides
- If either connection errors or times out, close both
- Idle timeout configurable (default 5 minutes for no-activity WebSocket connections)

### 5.11 `internal/tls`

Self-signed certificate generation for the alias domain. Uses Go's `crypto/x509` and `crypto/ecdsa` (P-256, faster than RSA for ephemeral certs).

SAN entries: alias domain, `localhost`, `127.0.0.1`, `::1`, and the listen host. Wildcard listen addresses use their loopback counterpart for the displayed client endpoint.

CLI startup defaults to a persistent local CA under the platform's user configuration directory (`<config>/blinder/ca/`); `--cert-dir` overrides this location. A private `ca-identity.pem` atomically stores the CA certificate/key pair, while `ca-certificate.pem` exports only the public CA certificate. Store directories require mode 0700, private identities require mode 0600, and concurrent CA preparation is serialized with a file lock on supported macOS/Linux platforms. Missing public exports are repaired from the canonical CA identity. Corrupt CA identities and unsafe file paths fail with an actionable error rather than discarding existing keys. Each session generates a leaf certificate in memory, signed by the CA, with SANs for the current alias, extra origins and endpoint hostnames.

The CA persists for 90 days and is renewed at startup with seven days or less remaining. Previous CA public certificates are retained as `previous-ca-<fingerprint>.pem` for removal of old trust. CA reuse preserves the fingerprint across restarts; renewal changes it and requires a one-time trust step. Adding or removing extra origins, changing the alias or reconfiguring endpoints only affects the session leaf certificate -- the CA and its trust relationship are unchanged. `--ephemeral-cert` retains a 24-hour memory-only self-signed leaf mode with no CA.

`--preflight` prepares the CA and checks platform verification for the displayed endpoint, returning 0 for ready, 2 for trust setup needed, or 1 for setup failure. It does not test listener availability, upstream connectivity or Tor bootstrap. On macOS, `--trust-cert` requests explicit approval to trust the local CA for SSL in the current user's login Keychain; the CA is MaxPathLen 0 and signs only end-entity certificates. Other platforms/clients use their own CA-certificate import or CA-file option. Successful platform verification does not prove that clients with separate stores trust the CA.

Certificate status includes OS-specific advice. macOS receives an explicitly quoted trust command carrying the current CA directory, alias and listen address. Linux distribution detection reads `ID`, `VERSION_ID` and `ID_LIKE` from `/etc/os-release`, or `/usr/lib/os-release` if the first file is missing, without executing either file. Ubuntu/Debian receives CA trust guidance for system-wide trust via `update-ca-certificates`; unknown Linux receives generic guidance. macOS/Linux also receives a `curl --cacert` verification command for the actual endpoint. Client-specific trust does not alter the platform-check exit status. OS detection identifies the running environment and cannot verify a remote browser's trust store. See the [certificate guide](docs/testing.md#certificate-advice-by-os).

## 6. CLI Interface

```
blinder [flags]

Required:
  --target, -t URL         Real target URL

Network:
  --listen, -l ADDR        Listen address (default: 127.0.0.1:8099)
  --tor                    Route upstream through Tor SOCKS5 proxy
  --tor-addr ADDR          Tor SOCKS5 address (default: 127.0.0.1:9050)
  --no-verify-tls          Skip TLS verification on real target

Scrubbing:
  --alias DOMAIN           Alias domain the client sees (default: target-001.local)
  --identity, -i TOKEN     Identity tokens to scrub (repeatable)
  --paranoid               Maximum scrubbing: strip all text, JS paths, CSS IDs

Capture:
  --har FILE               Write HAR 1.2 file with real (pre-scrub) transactions
  --har-max-body SIZE      Max body size to capture in HAR (default: 10MB)
  --output, -o DIR         Output directory for manifest and reports

TLS:
  --cert-dir DIR           Override the private persistent certificate directory
  --preflight              Prepare/check local certificate and platform trust, then exit
  --trust-cert             Request approved macOS user trust installation, then exit
  --ephemeral-cert         Use a new 24-hour in-memory certificate for this run
```

### 6.1 Examples

Basic scan through blinder:
```bash
blinder -t https://target.example.com -i "TargetOrg"
```

Scan a Tor hidden service:
```bash
blinder -t http://facebookwkhpilnemxj7asber7.onion --tor -i "Facebook"
```

Full evidence capture:
```bash
blinder \
  -t https://target.example.com \
  -i "TargetOrg" "Target Org" \
  --har /tmp/scan-evidence.har \
  -o /tmp/blinder-output
```

Paranoid mode with Tor:
```bash
blinder \
  -t http://something.onion \
  --tor \
  --paranoid \
  --har /tmp/evidence.har
```

## 7. Tor Integration

### 7.1 .onion Resolution

.onion addresses resolve only through Tor. Blinder detects `.onion` targets and enforces `--tor` (refuse to start without it).

### 7.2 Transport Chain

```
Client ──HTTPS──> Blinder ──SOCKS5──> Tor ──onion-routing──> Hidden Service
                  (local)    (local)   (Tor network)         (.onion)
```

The SOCKS5 connection carries the full hostname (SOCKS5h / remote DNS resolution). Blinder never resolves .onion addresses locally.

### 7.3 Clearnet via Tor

Non-.onion targets can also route through Tor for anonymity:
```bash
blinder -t https://clearnet-target.com --tor
```

### 7.4 Prerequisites

The operator must have a running Tor instance. Blinder does not manage Tor — it connects to an existing SOCKS5 endpoint. Typical setup:

```bash
# macOS
brew install tor && tor

# Linux
sudo apt install tor && sudo systemctl start tor

# Verify
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

## 8. HAR Capture

### 8.1 What Gets Captured

The HAR file records the **real** HTTP transactions (pre-scrub). This is the operator's evidence file — proof of what was sent to and received from the target.

Each entry contains:
- Request: method, URL (real target), headers, query parameters and capped body
- Response: status, headers and capped body (text or base64-encoded binary)
- Timing: total elapsed time, currently assigned to the HAR wait field; send/receive are not independently measured
- Timestamps: estimated request start from capture time minus elapsed duration, formatted as RFC3339Nano

`--har-max-body` applies separately to request and response bodies of every type. Original byte sizes remain recorded alongside truncation comments. Text truncation preserves UTF-8 boundaries. Binary or invalid-UTF-8 request bytes use the `postData._encoding: "base64"` extension; response bytes use HAR's `content.encoding`. Session entries are still buffered until shutdown. See [current evidence behavior](docs/capabilities.md#evidence).

### 8.2 What Does Not Get Captured

- The scrubbed response (what the client sees) — this is ephemeral
- Blinder's internal processing (rewrite decisions, scrub gate catches)
- TLS handshake details (cipher suite, certificate chain)

### 8.3 Import Compatibility

HAR uses the 1.2 log structure. Independent import/replay verification remains required for:
- Chrome DevTools (Network tab → Import HAR)
- Burp Suite (via HAR importer extension)
- OWASP ZAP
- Charles Proxy
- `har-analyzer`, `har-viewer`, and other tooling

### 8.4 Security of HAR Files

HAR files contain the **real** target data — URLs, headers, cookies and captured bodies. Handle them with the same care as the target data itself. Blinder writes them with 0600 permissions (owner-only read/write); capture truncation and missing transaction types must be accounted for when interpreting evidence.

## 9. Security Considerations (ASVS-Aligned)

### 9.1 Input Validation (ASVS V5)

- **Target URL:** validated at startup. Must be a valid HTTP/HTTPS URL (or HTTP for .onion). Reject file://, javascript://, data:// schemes.
- **Listen address:** validated as a valid host:port. Reject binding to 0.0.0.0 without explicit `--bind-all` flag (prevents accidental exposure).
- **Identity tokens:** minimum 3 characters (avoid false positives from short tokens). Maximum 100 tokens.
- **CLI arguments:** no shell interpolation. All values are string literals passed to Go's flag parser.
- **Upstream responses:** decompressed bodies are limited to 50 MiB; unsupported encodings, decoding failures and oversized bodies return a generic 502. There is no streaming fallback.
- **HAR body size:** capped at `--har-max-body` (default 10 MiB) for each request/response. This bounds individual captures, not aggregate session memory.

### 9.2 Output Encoding (ASVS V5)

- **Domain aliases:** generated from `SHA256(domain)[:8]` — deterministic, collision-resistant within a session, no user-controlled data in the alias format.
- **Placeholder text:** static Lorem Ipsum. No user-controlled content in placeholders.
- **JSON output (manifest, HAR):** serialised with Go's `encoding/json` which handles escaping. No string concatenation for JSON construction.
- **X-Blinder-Meta header:** compact JSON from `encoding/json`, not string formatting.

### 9.3 Cryptography (ASVS V6)

- **TLS for client-facing:** local ECDSA P-256 CA (MaxPathLen 0, 90-day lifetime) signs session leaf certificates. Leaf SANs include alias domain, localhost, loopback IPs, listen host, extra-origin aliases and CAPTCHA hostnames. Trust the CA once; adding origins or changing aliases does not require re-trusting. `--ephemeral-cert` falls back to a 24-hour self-signed leaf with no CA.
- **TLS for upstream:** uses Go's default TLS 1.2+ configuration. `--no-verify-tls` disables verification of the target's HTTPS certificate and logs a warning. It does not establish browser trust in Blinder's local certificate. Tor or an `.onion` hostname alone does not require this override; HTTPS target verification remains enabled by default, including through Tor.
- **Domain hashing:** SHA-256 truncated to 8 hex characters (32 bits). This is for aliasing consistency, not security — collision within a single session is acceptable (same alias for two different domains would reduce information, not leak it).

### 9.4 Error Handling (ASVS V7)

- **Upstream errors** (connection refused, timeout, TLS failure): return 502 Bad Gateway to client with a generic message. Never include the real target URL or hostname in the error response.
- **Parse errors** (malformed HTML, invalid JSON): fall through to generic domain scrubbing. Never pass unparseable content through unscrubbed.
- **Scrub gate failures:** if the gate itself panics (should never happen), the response is replaced with a 500 and an empty body. The proxy does not pass unscrubbed data under any circumstance.
- **HAR write failures:** logged as warnings. HAR capture failure does not stop the proxy — it degrades gracefully.
- **Manifest write failures:** logged as errors on shutdown. Non-fatal.

### 9.5 Access Control (ASVS V4)

- **Listen address:** defaults to 127.0.0.1 (loopback only). Binding to a non-loopback address requires `--bind-all` flag and prints a security warning.
- **Output files:** written with 0600 permissions (owner read/write only).
- **HAR files:** same 0600 permissions. Contains sensitive target data.
- **No authentication on the proxy itself.** It listens on loopback; if you need auth, use SSH tunneling or a firewall.

### 9.6 Data Protection (ASVS V8)

- **Real target URL:** stored only in the process's memory and CLI arguments. Never written to any output file visible to the client. Present in HAR files and manifest (operator-only artifacts).
- **Identity tokens:** stored in memory only. Not written to output files.
- **Leak log:** records what was caught (context, type) but not the original leaked value — only the pattern that matched.
- **Graceful shutdown:** on SIGINT/SIGTERM, flush HAR and manifest, then exit. On SIGKILL, incomplete HAR may be lost (temp file is deleted by OS).

### 9.7 Denial of Service Resilience (ASVS V11)

- **Request body size:** capped at 50MB. Requests with larger bodies are rejected with 413.
- **Response body size:** responses over 50MB are streamed through with domain-only scrubbing. Full HTML/JSON parsing is skipped.
- **Concurrent connections:** Go's `http.Server` handles this with goroutines. No artificial limit, but each connection allocates memory for the response body. Consider `--max-conns` flag if memory is constrained.
- **Timeouts:** upstream fetch timeout defaults to 30 seconds. Client read/write timeout defaults to 60 seconds. Both configurable.

## 10. Testing Strategy

### 10.1 Unit Tests

Each module has its own test file. Tests are pure (no network, no filesystem) where possible.

| Module | Test focus |
|---|---|
| `internal/config` | Validation: reject bad URLs, bad listen addresses, .onion without --tor |
| `internal/rewriter` | HTML scrubbing, JSON scrubbing, CSS url() rewriting, binary replacement, form preservation, CSP keyword preservation |
| `internal/scrub` | Domain replacement, identity token matching, email replacement, IP replacement, safe domain passthrough, alias stability |
| `internal/metadata` | JPEG/PNG/GIF/BMP/WebP dimension extraction, PDF feature detection, OOXML macro detection, identity/technical split |
| `internal/har` | HAR structure validity, body encoding (text vs base64), atomic flush, body size cap |
| `internal/tor` | SOCKS5 dialer construction (mocked), .onion enforcement |
| `internal/ws` | Upgrade handshake, text frame scrubbing, binary frame passthrough, close/timeout lifecycle |
| `internal/tls` | Cert generation, SAN verification, key type |

### 10.2 Integration Tests

Full proxy pipeline with a test HTTP server:
- Request flows through proxy, response is scrubbed
- Domain references in HTML, JSON, headers are replaced
- Form structure (input names, types, CSRF tokens) preserved
- Binary responses replaced with placeholders, metadata extracted
- HAR file written with real (pre-scrub) data
- Manifest de-alias map is accurate
- Scrub gate catches leaks the rewriter missed

### 10.3 Leak Tests

Adversarial tests that try to leak identity through:
- Encoded domains (URL-encoded, base64, hex)
- Domains in data: URIs
- Domains in SVG content
- Domains in CSS `url()` with quotes/escapes
- Domains in JavaScript string literals
- Domains in HTML attribute values (not just href/src)
- Identity tokens with mixed case, partial matches
- Public IPs in various contexts (headers, body, JSON values)

### 10.4 Fuzz Tests

Go's built-in fuzzing (`go test -fuzz`):
- Fuzz the HTML rewriter with arbitrary HTML inputs
- Fuzz the scrub gate with arbitrary strings
- Fuzz the metadata extractors with arbitrary binary inputs
- Goal: no panics, no unscrubbed output

### 10.5 Coverage Target

80% line coverage minimum. Scrub gate and rewriter modules target 90%+.

## 11. Build and Distribution

### 11.1 Build

```makefile
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

build:
    CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o blinder ./cmd/blinder

release:
    GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o blinder-linux-amd64  ./cmd/blinder
    GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o blinder-linux-arm64  ./cmd/blinder
    GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o blinder-darwin-amd64 ./cmd/blinder
    GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o blinder-darwin-arm64 ./cmd/blinder
```

No CGo. No external dependencies at runtime. Single static binary.

### 11.2 Dependencies

Minimal:
- `golang.org/x/net/proxy` — SOCKS5 dialer for Tor
- Standard library for everything else (crypto, http, json, regexp)

### 11.3 Repository Structure

```
blinder/
├── cmd/
│   └── blinder/
│       └── main.go              # CLI entry point
├── internal/
│   ├── config/
│   │   ├── config.go            # Configuration types and validation
│   │   └── config_test.go
│   ├── proxy/
│   │   ├── proxy.go             # Reverse proxy core
│   │   ├── transport.go         # HTTP transport (direct + SOCKS5)
│   │   └── proxy_test.go
│   ├── rewriter/
│   │   ├── rewriter.go          # Content-type dispatch
│   │   ├── html.go              # HTML rewriting
│   │   ├── json.go              # JSON rewriting
│   │   ├── css.go               # CSS rewriting
│   │   ├── headers.go           # Header rewriting
│   │   ├── binary.go            # Binary replacement
│   │   ├── rewriter_test.go
│   │   └── html_test.go
│   ├── scrub/
│   │   ├── gate.go              # Universal scrub gate
│   │   ├── domains.go           # Domain detection and aliasing
│   │   └── gate_test.go
│   ├── metadata/
│   │   ├── extract.go           # Metadata extraction dispatch
│   │   ├── image.go             # Image metadata (JPEG, PNG, GIF, WebP, BMP)
│   │   ├── pdf.go               # PDF metadata
│   │   ├── office.go            # OOXML metadata
│   │   ├── font.go              # Font metadata
│   │   ├── media.go             # Video/audio metadata
│   │   └── extract_test.go
│   ├── har/
│   │   ├── writer.go            # HAR 1.2 writer
│   │   ├── types.go             # HAR data types
│   │   └── writer_test.go
│   ├── tor/
│   │   ├── transport.go         # SOCKS5 transport for Tor
│   │   └── transport_test.go
│   ├── ws/
│   │   ├── proxy.go             # WebSocket upgrade + frame relay
│   │   └── proxy_test.go
│   ├── tls/
│   │   ├── cert.go              # Self-signed cert generation
│   │   └── cert_test.go
│   └── manifest/
│       ├── manifest.go          # Audit trail and de-alias map
│       └── manifest_test.go
├── go.mod
├── go.sum
├── Makefile
├── SPEC.md                      # This document
└── README.md
```

## 12. Passthrough and Scrub Rules

### 12.1 Headers — Passthrough (Technical Signal)

These headers pass through verbatim because they carry security-relevant technical information:

```
Content-Type, Content-Length, Content-Encoding, Transfer-Encoding,
Cache-Control, Pragma, Expires, ETag, Vary,
X-Content-Type-Options, X-Frame-Options, X-XSS-Protection,
X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, X-Generator,
X-Drupal-Cache, X-Varnish, X-Cache, X-Cache-Hits, X-Served-By,
X-Runtime, X-Request-Id,
Content-Security-Policy, Content-Security-Policy-Report-Only,
Strict-Transport-Security,
Access-Control-Allow-Origin, Access-Control-Allow-Methods,
Access-Control-Allow-Headers, Access-Control-Expose-Headers,
Access-Control-Max-Age, Access-Control-Allow-Credentials,
Permissions-Policy, Referrer-Policy,
Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
Cross-Origin-Resource-Policy,
WWW-Authenticate, Retry-After, Server, Via
```

### 12.2 Headers — Scrub (Identity)

These headers have their domain references rewritten:

```
Location, Content-Location, Link, Refresh, P3P, X-Redirect-By
Set-Cookie (domain= attribute rewritten, cookie name hashed)
```

### 12.3 CSP Rewriting

CSP directives are parsed token-by-token:
- **Keywords preserved:** `'self'`, `'unsafe-inline'`, `'unsafe-eval'`, `'strict-dynamic'`, `'none'`, nonces (`'nonce-...'`), hashes (`'sha256-...'`)
- **Scheme sources preserved:** `data:`, `blob:`, `https:`, `http:`, `ws:`, `wss:`
- **Domain sources:** rewritten through the domain aliaser

## 13. Migration from Python Prototype

The Python prototype (`packages/blinder/`) remains as the in-process RAPTOR integration. The Go binary is the standalone distribution.

### 13.1 Feature Parity

Everything the Python prototype does, the Go binary does:
- Content-type-specific rewriting (HTML, JSON, JS, CSS, XML, binary)
- Universal scrub gate (domains, emails, IPs, identity tokens)
- Binary metadata extraction (images, PDF, OOXML, fonts, video/audio)
- Self-signed TLS certificate
- Domain aliasing (stable SHA-256)
- Manifest and de-alias output

### 13.2 New in Go Version

- Tor SOCKS5 support (--tor, --tor-addr)
- HAR 1.2 capture (--har)
- True concurrent request handling (goroutines vs GIL)
- Single static binary (no Python runtime, no pip dependencies)
- WebSocket proxying with text-frame scrubbing
- Streaming large responses (no full-body buffering for >50MB)
- Fuzz testing of parsers
- Non-loopback bind protection (--bind-all required)

### 13.3 RAPTOR Integration

The Go binary integrates with RAPTOR the same way the Python prototype does — the scanner's `--url` points at blinder's listen address. No code changes needed in the scanner.

For in-process use (when RAPTOR wants to start/stop blinder programmatically), a thin Python wrapper can launch the Go binary as a subprocess and manage its lifecycle.

## 14. Open Questions

1. **HTTP/2?** Go's reverse proxy supports HTTP/2 out of the box, but HAR 1.2 doesn't model HTTP/2 streams well. Start with HTTP/1.1 for HAR compatibility; HTTP/2 to upstream is fine.

2. **Certificate pinning?** If the scanner does cert pinning (unlikely for blinder's use case), the local CA-signed cert will fail. Not a priority — document the workaround (--insecure on the scanner side).

3. **Response streaming vs. buffering?** Full-body buffering is needed for HTML parsing and scrubbing. For responses over 50MB, stream with line-by-line domain scrubbing only. This means very large HTML pages (>50MB) get weaker scrubbing — acceptable tradeoff.

---

*End of specification.*
