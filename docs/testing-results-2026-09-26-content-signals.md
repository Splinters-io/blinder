# Content masking and application-security signals

Ordinary content should lose its original meaning while the application remains testable. A changed response may reflect a successful injection, different query results, a disclosed file, a changed session, or normal dynamic data. Blinder must preserve observable differences without deciding in advance that only known attack signatures matter. A difference is evidence to investigate, not proof of an exploit.

## Same-size changes

The previous prose generator depended only on byte length: different text of equal length became identical filler. It now selects a word stream using a private session-keyed content tag. Identical input stays stable within one proxy session; changed input selects a different stream. Resizing generated prose retains that source-specific selection. Literal boundary whitespace, valid UTF-8, protected functional content and the existing original decoded byte-size objective remain intact.

Finite short text cannot carry an unlimited number of distinct originals. Each complete main HTTP representation therefore also carries `X-Blinder-Original-Body-Tag`, a full HMAC-SHA256 of its decoded original body under a private random session key. The manifest stores the same `original_body_tag`. This is not a public hash that can be compared against guessed branded pages, and upstream-supplied copies cannot override it. Tags are stable only within the current proxy session; they disclose equality intentionally.

Response and SRI caches retain the original tag. Cache-backed HEAD/304 responses describe their cached representation. An uncached HEAD, unassociated 304, failed/incomplete read or proxy-generated error does not invent an original tag. ETags still describe emitted response bytes; the original tag is a separate comparison signal, including when masking produces identical bytes. No extra baseline request or replay is issued.

Synthetic regressions cover equal-length HTTP 200 result changes, repeated identical responses, title-only changes hidden by existing title normalization, response-cache hits, HEAD, revalidation, conditional responses, real SRI prefetch/cache serving, spoofed upstream tags and unknown originals. SRI tests additionally cover gzip decoding and failed/partial fetches. These checks preserve a comparison signal; they do not restore an erased diagnostic or executable behavior.

## Confirmed behavior defects requiring correction

The source audit also reproduced these independent problems. They remain release gates for equivalent vulnerability testing:

| Transformation | Evidence affected | Required acceptance |
| --- | --- | --- |
| A `javascript:` URL goes through generic domain scrubbing | Member expressions such as `window.audit` become a hostname alias; equivalent inline script/handler behavior differs. | Direct/proxy execution and CSP decisions for JavaScript URL contexts. |
| Image `src` becomes a valid data GIF | The original request and decode outcome disappear; `onerror`/`onload` behavior can change. | Preserve observable fetch/decode success and failure, including event-driven XSS fixtures, while masking image identity. |
| Ordinary HTTP 200 titles become constant text | Unmarked title diagnostics or reflected values lose their meaning. The new tag reports a change but does not recover that evidence. | Source-dependent masked titles plus explicit diagnostic/reflection coverage. |
| Ambiguous identity-bearing malformed comments or incomplete tags are omitted | Parser-boundary and truncation evidence can disappear even when prose fitting restores the total byte count. | Direct/proxy malformed-source and browser-parser comparisons without identity exposure. |

SQL-style diagnostics in marked regions and HTTP error responses, executable script/handler syntax, status codes, request restoration and response-size measurements already have separate regressions. Unmarked HTTP 200 text, successful file disclosures and arbitrary attack effects cannot be classified reliably from a few error patterns. Scanner workflows must compare tags, sizes, structure, controls and browser behavior; the operator's original HAR supplies the unmasked evidence for discrepancies.

## Local validation

Full race suite: **846 top-level tests across 17 packages**, zero failures. Tagged functional suite: **12 top-level tests**, zero failures. Vet passed. Final original-tag capture-before-rewrite placement also passed the focused proxy race tests. No new browser or live-target acceptance is claimed.

Evidence directory: `/Users/carroll/.codex/visualizations/2026/09/23/01a0ce57-c07e-79e0-a189-9f6c7c6023dd/blinder-content-signals-2026-09-26`. Source manifest SHA-256: `0cbf72689411ee0ecd4acb32e459874825cc19ab4efad2af6d44fe1701093e4d`. This batch remains local; the running preview has not been replaced.
