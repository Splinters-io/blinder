# WebSocket history-navigation follow-up — 2026-09-26

Chrome reported `Page entered Back-Forward Cache` and the synthetic homepage remained at close code 1006 after returning. This identifies a page-lifecycle failure in the fixture: it opened one socket and never reconnected when the suspended document resumed. Closing on `pagehide` and reconnecting on persisted `pageshow` follows the [WebSocket lifecycle guidance](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_client_applications#working_with_the_bfcache).

## Changes

- The synthetic page now closes before navigation and reconnects on history restoration. Stale socket events cannot replace the restored connection's status. The client script is embedded from a separate file and exercised through repeatable JavaScript lifecycle tests for HTTP and HTTPS.
- The synthetic target now acknowledges Close frames, replies to client pings and serializes control writes with its heartbeat. Its reader and shutdown are bounded.
- A separate production defect was reproduced in both directions: the relay closed both transports after forwarding the first Close, losing a delayed peer acknowledgment. The proxy now waits for both Close frames, bounded by five seconds or the shorter configured idle timeout. Invalid traffic, peer EOF and shutdown still terminate promptly. Application messages are withheld while closing.

Lifecycle reconnection remains fixture behaviour; Blinder does not inject it into proxied applications.

## Verification

- Full race suite: **710 top-level tests across 16 packages passed**. Five existing opt-in browser tests skipped; the Chrome check below ran separately.
- Tagged functional suite: **12 top-level tests passed**. Vet with functional tags and static build passed.
- Chrome native UI: initial connection reported `history restores: 0`; Back then Forward/Back reported `1` and `2`, each with the masked live message. This confirms actual back-forward cache restoration, not just a successful reload.
- Independent TLS client: certificate verification enabled, HTTP 101, masked live text, Close **1000 / page hidden** acknowledged, followed by transport EOF.
- Homepage decoded size remained exact: **2,236 original and rewritten bytes**, matching `Content-Length`.

Local evidence is in the task's `blinder-websocket-navigation-2026-09-26` directory. Source digest: `f6476ad3429f27c1af9c973e1364ae04e0f308b9ff70e1c7f595a8c9d0a936b0`; running proxy binary SHA-256: `fd32ca0a56e4bc8718af51e7ab91ffbc028ec81fef822b8b7318317c50307c04`. The corrected processes are `/private/tmp/blinder-navigation-fixed` and `/private/tmp/blinder-target-navigation-fixed`, using the existing local endpoint and certificate.

No push or remote CI run occurred. Certificate/browser trust, live Tor/onion and other unrelated acceptance gates retain their status from the preceding reports.
