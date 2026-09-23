# Blinder

A local reverse proxy for security-scanner workflows. It rewrites configured target domains, identity tokens, and selected response content while preserving technical information for analysis. Optional HAR and manifest files retain operator-side evidence.

Blinder is experimental. The implemented protections and limitations below describe the current code; `SPEC.md` is a design document, not a guarantee of complete anonymization.

## Build and run

Requires Go 1.26 or later. The resulting binary has no external runtime dependency.

```sh
make build
./blinder --target https://your-authorized-target.example \
  --identity YourOrganisation \
  --har /tmp/blinder-evidence.har \
  --output /tmp/blinder-output
```

Point the scanner at `https://127.0.0.1:8099`. Blinder generates an ephemeral self-signed TLS certificate, so configure the scanner to accept that certificate. For a local smoke test:

```sh
curl --insecure https://127.0.0.1:8099/
```

Identity flags are repeatable: `--identity 'Example Company' --identity ExampleBrand`. Upstream TLS verification remains enabled unless `--no-verify-tls` is supplied. Use only targets you are authorized to test.

`.onion` targets require `--tor`; an existing SOCKS5 service must be available at `127.0.0.1:9050` or `--tor-addr`. Blinder does not start Tor. Binding outside loopback requires `--bind-all`.

Stop with SIGINT or SIGTERM to flush configured artifacts. HAR, manifest, and de-alias files contain real target data and belong on the operator side of the workflow.

## Implemented boundaries

- Requests are buffered and capped at 50 MiB, including chunked/unknown-length uploads. Body read failures return 400 and oversized requests return 413 before forwarding.
- HTTP responses support identity and gzip content encoding. Unsupported encodings, decoding failures, and responses exceeding 50 MiB after decompression return a generic 502. There is no large-response streaming fallback.
- The upstream timeout covers reading the response body as well as connection setup. The current default is 30 seconds.
- JSON numbers retain their original precision. Malformed JSON, trailing non-whitespace content, or key collisions introduced by scrubbing produce the safe JSON placeholder `null`.
- Configured identity matching is Unicode-aware and does not rescan its own replacements. Identity-token matches in the scrub report use a generic label rather than storing the configured token itself.
- WebSocket handshakes, masking, frame lengths, fragment ordering, and text UTF-8 are validated. Frames and reassembled text messages are limited to 16 MiB. Text is scrubbed after reassembly, including identities split across frames.
- WebSocket compression/extensions are not negotiated. Invalid frames close both sides. Traffic in either direction resets the idle deadline; shutdown closes tracked WebSocket connections and cancels pending dials.

## Known limitations

- HTML and JavaScript rewriting still use limited parsers. Arbitrarily escaped, encoded, obfuscated, or dynamically assembled identities are not comprehensively detected. Passing regression tests does not establish a universal no-leak boundary.
- Binary WebSocket messages and ping/pong payloads pass through unchanged. The HTTP unknown-content fallback is also not a general binary anonymizer.
- Domain aliases do not implement complete multi-origin routing, wildcard DNS, or browser origin isolation. Absolute rewritten links and multi-domain applications need further work.
- Cookie names are reversible and domain attributes are removed for loopback compatibility. Complete multi-origin cookie scoping and cookie-value anonymization are not implemented.
- HAR capture is buffered in memory and flushed on shutdown. Its per-body cap currently applies to binary responses only; WebSocket upgrade transactions are not captured. It is not yet a full-fidelity archival/replay system.
- Manifest per-request scrub/leak counters and parts of metadata extraction remain incomplete. `--cert-dir` is currently accepted but does not persist certificates.

These limits must be accounted for before using Blinder as a boundary between a sensitive target and an untrusted consumer. Use synthetic fixtures to validate the specific workflow first.

## Development

```sh
make test
make lint
CGO_ENABLED=0 go build -o /tmp/blinder ./cmd/blinder
```

The suite includes both rounds of review regressions, cookie-jar checks, timeout tests, and protocol validation. Short fuzz runs can be executed independently:

```sh
go test -run '^$' -fuzz '^FuzzGateUnicode$' -fuzztime=15s -parallel=2 ./internal/scrub
go test -run '^$' -fuzz '^FuzzJSONScrubbing$' -fuzztime=15s -parallel=2 ./internal/rewriter
go test -run '^$' -fuzz '^FuzzFrameValidation$' -fuzztime=15s -parallel=2 ./internal/ws
```

GitHub Actions runs vet, the race suite, and a static build on pushes to main and pull requests. Fuzz seeds are part of the normal test suite; the commands above also explore generated cases.
