# Body size and short-text changes — 2026-09-26

This local checkpoint follows `0bbc215` and fixes two differences exposed by the response comparator: fixed-size short titles could lose a content change, and reversible identity aliases could inflate bodies that had no ordinary prose available to resize.

## Changes and evidence

Configured identity matches now receive session-private reversible aliases that fit their matched UTF-8 byte length when at least five bytes are available. The allocator tries every spelling at that width before growing on exhaustion, preserves existing mappings, and restores the exact original case and Unicode spelling. Literal alias-shaped input keeps its escape handling. This changes functional value masking, not ordinary prose into functional aliases.

Real HTTP fixtures verify exact original, rewritten and emitted sizes for plain text, JSON, a quoted HTML input attribute, a 503 SQL-style diagnostic and a 220-byte identity. The JSON fixture retains its large numeric value. Restoring the masked fixtures recovers the original bytes; JSON and form submissions using the arbitrary `vendor.sync` method also reach the upstream with their original values. Error content is not shortened to force a size match.

Ordinary generated display text with an interior budget of one through eight bytes now uses immutable session reservations. All **1,792 distinct two-byte Unicode titles** in the regression retain distinct, same-size outputs; returning to earlier titles produces the same output. The allocator stores private content tags, caps the session at 4,096 reservations, and caps each search at 8,192 candidates. A collision's initial assignment can depend on arrival order; issued reservations do not change.

The safe output alphabet has only 64 one-byte values. A regression deliberately exhausts it and confirms that the offline comparator still reports `lost_change` when distinct originals converge. The response manifest and comparison observations expose `short_text_fallbacks`: the number of generation attempts unable to reserve an exclusive output. This can include intermediate prose later resized; a cache hit makes no new generation attempts. The counter does not certify the uniqueness of longer prose.

## Verification

* Full `go test -race -count=1 -json ./...`: **899 top-level tests passed across 19 packages**, zero failures or race reports. Nine opt-in tests skipped in this run.
* `go test -race -count=1 -tags functional -json ./tests/functional`: **12 top-level functional tests passed**, with no skips or failures.
* `go vet -tags functional ./...`: clean.
* Separate native Chrome runs completed **20 inline CSP pairs and 29 external CSP/SRI pairs**, comparing direct and Blinder execution plus allow/block/report outcomes. These two opt-in browser tests were actually run, not inferred from their suite skips.

The browser checks used local synthetic resources and the existing trusted loopback certificate. They did not change trust, run live Tor/onion or human CAPTCHA acceptance, or replace the user's preview.

## Remaining size boundaries

Identity values shorter than five bytes, exhausted fixed-width namespaces, literal alias escaping, changed JSON/HTML escape spellings and rewritten routing authorities can still change body size. Larger prose retains the existing word generator and can still collide. Short-text saturation returns a deterministic same-size fallback; it does not claim an impossible unbounded one-to-one mapping.

Decoded body size remains the measurement boundary. Compressed transfer size, timing, structural differences and universal application or exploit fidelity are not established by these checks. The comparator retains per-response sizes and original-versus-output change signals so that these remaining differences stay observable.

Local evidence is stored in:

```text
/Users/carroll/.codex/visualizations/2026/09/23/01a0ce57-c07e-79e0-a189-9f6c7c6023dd/blinder-size-signals-2026-09-26/
```

It includes race, functional and vet logs, both browser result sets and a hashed source-input manifest. The source-input manifest SHA-256 is `e627199d29f89b7737b709805bf0b29dfe75e4c89f2ec0828dcadb0d589487fa`. See [response comparisons](response-deltas.md) for capture and interpretation.
