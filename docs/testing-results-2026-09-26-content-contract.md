# Content contract and serving revision — 2026-09-26

The operator still saw generated removal labels after neutral replacements had been implemented. Read-only process inspection found that `127.0.0.1:8099` was running `8d381b9`, while the source checkpoint was `eb681ee`. A certificate-verified request to that listener returned HTTP 200 with 110 generated `[REDACTED:…]` aliases and one `[Blinder: title removed]` label. The current source did not generate those labels.

## Durable requirement and fix

The [content contract](content-contract.md) now records neutral generated prose, reversible functional values, preserved diagnostics/control decisions, actual byte-size goals, explicit provenance and serving-revision checks. Root `AGENTS.md` and `CLAUDE.md` direct both contributors to it; the README and capabilities guide link it.

The audit also found that longer generated prose could reintroduce a configured identity when it matched the filler vocabulary. Revision **`20f7ef5`** preserves unaffected output, filters conflicting words and checks complete generated spans so multiword identities are covered. A bounded sequence of source-dependent alternatives retains the byte budget; alphanumeric candidates cover unavailable prose vocabulary. Exhausting all candidates can still fall back to spaces. The guard is per generated span, not a promise about text concatenated across separate HTML nodes.

New response-level regressions cover pages, titles, image/accessibility attributes, JSON, JavaScript, CSS, custom diagnostic headers and HTTP 503 errors. They reject invented removal labels while retaining functional structure, status, explicit `X-Blinder-View: transformed` provenance and reversible values. A complementary fixture proves that a real upstream diagnostic containing removal words is preserved; there is no response-wide word blacklist.

## Verification

- Full race suite: **925 top-level tests pass across 19 packages**, with zero failures/races and ten opt-in browser skips.
- Functional suite: **12 top-level tests and 26 subtests pass** on the standalone rerun. The initial parallel run failed the occupied-port startup test's three-second deadline with no CLI output; that failure is retained, not relabelled as a pass. The rerun used unchanged source and timeout.
- `go vet -tags functional ./...` and the stamped local build pass.
- Focused prose checks cover configured corpus/case/multiword matches, unavailable vocabulary, 32 distinct source tags, size fitting, deterministic output and finite exhaustion.

These are package, functional and HTTP-wire checks. No new browser acceptance, live Tor or human CAPTCHA result is claimed.

## Runtime correction

The outdated process was stopped gracefully. Its executable, configuration and flushed output were archived before replacement. The local executable and listener now run `20f7ef5`; the preview configuration enables ordinary prose masking and explicitly selects the existing acceptance certificate store. Target and routing configuration are retained.

The already-trusted leaf certificate was verified with macOS and reused unchanged; no trust was installed. Its SHA-256 fingerprint is `e67f6548a29e05e09c24269f0ed57a7bcbb5e28ffb381c487ac6214a368a68e3`. New session mappings require reloading stale browser pages.

A certificate-verified request to the updated listener returned:

| Measurement | Result |
| --- | --- |
| Status | HTTP 200 |
| Case-insensitive `redacted` occurrences | 0 |
| Generated legacy aliases/title-removal labels | 0 / 0 |
| Original decoded body | 232,932 bytes |
| Rewritten and emitted body | 232,932 bytes |
| Content-Length | 232,932 |
| Size measurement | exact |
| Transformation provenance | `X-Blinder-View: transformed` |

This is a result for the measured root response, not every resource or application workflow. No GitHub push was made.

Evidence, including both functional runs, build metadata, source hashes, before/after serving measurements and private rollback files, is stored locally in:

```text
/Users/carroll/.codex/visualizations/2026/09/23/01a0ce57-c07e-79e0-a189-9f6c7c6023dd/blinder-content-contract-2026-09-26/
```
