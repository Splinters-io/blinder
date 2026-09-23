# Supported behavior and delivery gates

This is the working-tree implementation status. The [test report](testing-results-2026-09-23.md) separates the previous main baseline from subsequent local fixes. Changes here have not been published by this session.

## Supported workflow

Blinder supports a configured target reached through a local HTTPS reverse proxy, directly or through Tor SOCKS5. Synthetic acceptance covers login/logout and cookies, browser-origin form submissions, JSON, gzip, upstream TLS verification, fragmented WebSocket text, certificate persistence and evidence output. The local functional suite passes 29/29 scenarios.

Origin and Referer translation uses recognized local origins, including scheme and port, for HTTP and WebSocket. Unrelated, opaque, malformed and duplicate origins remain unchanged. This repairs the previous loopback form failure without disabling upstream origin checks. It does not supply multi-origin routing or local alias DNS.

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

HAR remains buffered until shutdown, without a whole-session memory cap or durable journal. Failed upstream transactions and WebSocket upgrades/messages are not fully represented in HAR. External HAR viewer/replay compatibility remains a separate acceptance check, particularly for the request encoding extension.

HTTP manifest entries include success and failure status plus request-local identity/domain replacement counts, isolated across concurrent requests. `scrub_count` measures gate matches, not every structural transformation such as image/title replacement. `leak_count: -1` means residual identity leakage was not measured; it must not be interpreted as zero. The legacy scrub report's `total_leaks` counts recorded matches, not proof that those identities reached the client. Repeated manifest flushes replace the finding snapshot rather than multiplying counts.

WebSocket manifest coverage and complete metadata extraction remain open. Raw evidence, mappings and identity metadata belong only on the operator's side.

## Remaining delivery gates

These are implementation work and acceptance criteria, not waived requirements.

| Workstream | Completion criterion |
| --- | --- |
| Multi-origin browser fidelity | A configured two-origin app completes redirects, API calls and WebSockets through routable aliases with valid local certificates; cookie host/domain/path and SameSite relationships are preserved. |
| Context-aware rewriting | A maintained corpus of HTML entities, JS escapes, embedded data and encoded URLs passes both identity-removal and behavior checks. Arbitrary obfuscated/dynamically constructed identities are not currently covered. |
| Opaque-content policy | Explicit, tested treatment for binary WebSocket data, ping/pong payloads, unknown HTTP bodies and cookie values. These currently preserve data or use limited text scrubbing, so they cannot be considered generally anonymized. |
| Browser network containment | Observed browser resource/fetch/WS traffic remains in the selected route; preserved third-party references and dynamic requests are assessed. SOCKS transport tests alone do not establish this. |
| Evidence durability and completeness | Bounded whole-session capture, durable incremental storage, failed-request/WS evidence, complete metadata and independent HAR compatibility tests. |
| Security-control fidelity | Direct/proxied tests for CSP, integrity-protected resources, CORS, cookie constraints and cache validators identify any behavior changed by rewriting. |
| Operator acceptance | Selected browser/scanner workflow, actual OS trust installation, live Tor exit and authorized onion-service requests pass on the supported OS matrix. |

Complete anonymization is not an established property of the current implementation. Keep that distinction explicit when connecting a sensitive target to an untrusted consumer. Use the [proxy engineering review](proxy-engineering-review.md) for the proposed routing and fidelity design, and the [UAT checklist](testing.md) to record acceptance evidence.
