# Local fidelity and acceptance checks — 2026-09-26

This records the uncommitted working tree based on `8d381b951679d7207a75556822ca387fed7a1727`. No commit, push, deployment or GitHub CI result is claimed. Machine-readable logs, the synthetic HAR and source hashes are retained in the local task evidence directory `blinder-fidelity-final-2026-09-26`.

## Verification

| Check | Result |
| --- | --- |
| `go test -race -count=1 -timeout 120s -json ./...` | 642 top-level tests passed, zero failures; 15 tested packages passed. Five opt-in browser tests skipped. |
| `go test -tags functional -race -count=1 -timeout 120s -json ./tests/functional` | All 11 top-level functional tests passed, including synthetic SOCKS/Tor and WebSocket scenarios. |
| `go vet -tags functional ./...` | Clean. |
| `CGO_ENABLED=0 go build -o /private/tmp/blinder-fidelity-verified ./cmd/blinder` | Clean. |
| Independent HAR schema/semantic check | Seven synthetic transactions accepted using pinned `har-validator@5.1.5`; binary bytes, partial503, transport0, redirect/cookies and101 checked locally. |
| In-app browser: form/error fixture | Passed separately: configured form values restored upstream; HTTP422 diagnostic displayed. Form page432→432→432bytes; diagnostic277→285→285bytes. |
| In-app browser: synthetic provider/operator | Passed separately:13 provider requests, nested frames, extension methods, original session/CSRF retained; visible server-rendered submission receipt. |

The separate browser runs do not convert the other skipped browser tests into passes. The provider fixture uses a deterministic synthetic token; no live CAPTCHA was solved. The HAR validator runs locally and is not a production dependency; schema acceptance does not establish viewer import or replay compatibility.

## Changes exercised

- JSON edits preserve source order, whitespace, number spelling and existing duplicate members. Malformed response diagnostics remain malformed where string escapes can be scrubbed unambiguously; ambiguous cases retain the safe fallback.
- Form/query restoration changes only affected components. HTTP and WebSocket path restoration share escaped-segment handling. A real reproduction of the theme-path alias404 now returns the intended asset; encoded slashes and reserved characters stay path data. Cache and SRI version/credential constraints remain covered.
- Untouched HTML preserves token source, comments, line endings and entities. Prose size fitting remains limited to generated prose spans. Diagnostics and submitted values are not cut to force a size match.
- Custom diagnostic response headers survive configured redaction. Invalidated framing/digest/range metadata and hop-by-hop fields are excluded.
- Extra-origin WebSockets select the registered transport/origin. Complete registered ws/wss literals rewrite consistently in normal JavaScript and SRI copies. Refused upgrades retain status and scrubbed diagnostics;101 evidence is recorded before the relay ends.
- HTTP, WebSocket and SRI failure evidence retain actual upstream protocol/status details. SRI captures bounded non200/partial bodies and measures encoded/decoded payload sizes without accepting failed resources as verified content.
- HAR exports required schema fields and streams entries. Append/export/removal are serialized within one writer; incomplete tails remain recoverable and retryable append failures roll back their prefix. A process crash between final HAR replacement and journal removal can still replay entries on restart.
- Operator completion uses authenticated native forms, visible receipts/errors and guarded submission state. Cookie-only fetch/XHR authorization remains restricted.

## Live acceptance still requiring operator input

The in-app browser rejected the existing local certificate at `https://127.0.0.1:18099/` with `ERR_CERT_AUTHORITY_INVALID`. No OS trust change or browser warning bypass was performed. Browser HTTPS/WSS acceptance remains pending the operator's trust step. Programmatic TLS checks are not substituted for that result.

An isolated Tor0.4.9.8 process remained at5% bootstrap: relay connections timed out or were refused before TLS. It was stopped cleanly, with no direct fallback. A working SOCKS endpoint or bridge configuration is needed for live exit/onion acceptance; synthetic SOCKS tests do not close that gate.

Live provider human completion, broader browser containment, dynamic/escaped URL construction and selected HAR viewer/replay acceptance remain separately scoped checks. This report does not claim universal anonymization or preservation of every application-security observation. See [capabilities](capabilities.md) and the [repeatable testing guide](testing.md).
