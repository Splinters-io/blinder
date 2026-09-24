# Supported behavior and delivery gates

This is the working-tree implementation status. The [test report](testing-results-2026-09-23.md) separates the previous main baseline from subsequent local fixes. Changes here have not been published by this session.

## Supported workflow

Blinder supports a configured target reached through a local HTTPS reverse proxy, directly or through Tor SOCKS5. Synthetic acceptance covers login/logout and cookies, browser-origin form submissions, JSON, gzip, upstream TLS verification, fragmented WebSocket text, certificate persistence and evidence output. The local functional suite passes 29/29 scenarios.

Origin and Referer translation uses recognized local origins, including scheme and port, for HTTP and WebSocket. Unrelated, opaque, malformed and duplicate origins remain unchanged. Multi-origin routing is supported: `--extra-origin` (repeatable) registers additional upstream origins, each served under a deterministic alias hostname (`host-<sha256[:4]>.<alias>`). The proxy routes by Host header, the TLS certificate covers all alias SANs, and CORS Access-Control-Allow-Origin headers map each upstream origin to its local alias.

The CLI binds before reporting readiness, exits on listener failure, and returns nonzero if shutdown or a requested artifact write fails. Both artifact destinations are attempted even if one fails. The functional CI step is configured locally; no new GitHub run has been claimed.

## Resource and protocol controls

| Area | Implemented behavior |
| --- | --- |
| Requests | Buffered; 50 MiB maximum including unknown-length bodies. Read failures return 400; oversized bodies return 413 before forwarding. |
| Responses | Identity/gzip decoding; 50 MiB after decompression. Unsupported encodings and read/size failures return a generic 502. No large-response streaming fallback. |
| Timeouts | Default 30-second upstream deadline includes response reading; client timeout defaults to 60 seconds. |
| JSON | Original number precision retained. Invalid JSON, trailing content or scrub-induced key collisions produce `null`. |
| Identity matching | Unicode-aware configured matching without rescanning replacements; configured-token findings use a generic label. |
| WebSocket | Handshake, masking, fragmentation, frame lengths and UTF-8 validated. Text is scrubbed after reassembly. Frames/reassembled text limited to 16 MiB. Extensions are not negotiated. |
| Connection lifecycle | WebSocket activity in either direction refreshes the idle deadline. Shutdown closes tracked connections and cancels pending dials. |
| Local TLS | Persistent 90-day leaf certificates; startup renewal with seven days or less remaining. OS-aware guidance and explicit macOS user trust; ephemeral mode available. |
| Binary replacement | Supported binary media/documents/fonts become a GIF placeholder labelled `image/gif`, with available metadata extracted separately. This deliberately loses original rendering/functionality. |

Resource controls are operational protections. Increasing a limit or adding streaming requires tests for memory, cancellation and scrubbing across chunk boundaries; removing a cap alone does not improve coverage safely.

## Evidence

HAR retains pre-scrub upstream HTTP data. Its configured per-body cap now covers request bodies and text/binary responses. Original sizes and truncation comments remain available; UTF-8 truncation avoids splitting a code point. Binary/invalid-UTF-8 request data uses the explicit `postData._encoding: "base64"` extension. Response binary data uses HAR's `content.encoding`. Request start timestamps account for elapsed upstream time.

HAR flushes automatically every 30 seconds for durability across crashes, merging new entries with any existing file on disk. A configurable memory cap (maxEntries) auto-flushes when the in-memory buffer exceeds the threshold, bounding memory for long scan sessions. Failed upstream requests (dial errors, body read failures) and WebSocket upgrade transactions are captured with full request details and error/status information. External HAR viewer/replay compatibility remains a separate acceptance check, particularly for the request encoding extension.

HTTP manifest entries include success and failure status plus request-local identity/domain replacement counts, isolated across concurrent requests. `scrub_count` measures gate matches, not every structural transformation such as image/title replacement. `leak_count` measures residual target-domain and identity-token occurrences in scrubbed output; 0 means the scrubber caught every configured pattern in that response. The legacy scrub report's `total_leaks` counts recorded matches, not proof that those identities reached the client. Repeated manifest flushes replace the finding snapshot rather than multiplying counts.

WebSocket manifest coverage and complete metadata extraction remain open. Raw evidence, mappings and identity metadata belong only on the operator's side.

## Remaining delivery gates

These are implementation work and acceptance criteria, not waived requirements.

| Workstream | Completion criterion |
| --- | --- |
| Multi-origin browser fidelity | `--extra-origin` registers additional upstreams with origin-aware alias hostnames (scheme+host+port hashed via `AliasOrigin`), Host-header routing, per-origin TLS SANs, CORS ACAO echoes the actual requesting origin (localhost/loopback/alias all get a matching response), origin-aware Location header rewriting, origin-aware HTML body URL rewriting via OriginMapper, collision detection at startup. Extra-origin .onion validation enforced. WebSocket routing for extra origins remains open. |
| Context-aware rewriting | HTML entities and attribute values decoded via golang.org/x/net/html tokenizer before scrubbing; HTML body URLs (href, src, action) routed through OriginMapper for origin-aware rewriting before scrubbing. Test corpus covers entity-encoded identity tokens, attribute URLs, script blocks and paranoid mode. Arbitrary obfuscated/dynamically constructed identities are not currently covered. |
| Opaque-content policy | Cookie values scrubbed bidirectionally with unambiguous per-value tokens. Hash disambiguation checks uniqueness against ALL existing scrubbed values (including literal values that match the hash suffix format), extending the hash length until unambiguous. Multiple cookies with the same aliased name restore correctly. Server-to-client ping/pong text payloads scrubbed. Binary WebSocket frames pass through unchanged. |
| Browser network containment | Observed browser resource/fetch/WS traffic remains in the selected route; preserved third-party references and dynamic requests are assessed. SOCKS transport tests alone do not establish this. |
| Evidence durability and completeness | HAR uses journal-based incremental persistence (periodic flushes append to JSONL at 0600 permissions; final flush streams entries to the HAR without loading all into memory). Configurable capture budget (`SetCaptureBudget`) limits total entries in the export. Partial journal records are skipped during recovery (valid subsequent entries preserved); errors reported with corrupt journal backed up. Memory bounded by maxEntries cap. Failed flushes preserve entries for retry. Corrupt prior HAR backed up. Failed request and WS upgrade capture. HTML metadata (title, author, generator) extracted for manifest. Independent HAR compatibility tests remain open. |
| Security-control fidelity | SRI integrity/crossorigin attributes stripped when the resource will be proxied (relative URLs and known upstream/alias origins, where content will be scrubbed), preserved when the resource is external (CDN etc., fetched directly by the browser). CORS ACAO translated to the actual requesting origin. CSP hashes preserved (known limitation: hashes may not match scrubbed inline content). Cache validators remain open. |
| Operator acceptance | Selected browser/scanner workflow, actual OS trust installation, live Tor exit and authorized onion-service requests pass on the supported OS matrix. |

Complete anonymization is not an established property of the current implementation. Keep that distinction explicit when connecting a sensitive target to an untrusted consumer. Use the [proxy engineering review](proxy-engineering-review.md) for the proposed routing and fidelity design, and the [UAT checklist](testing.md) to record acceptance evidence.
