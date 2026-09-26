# Actual response body size — 26 September 2026

The required size comparison is between the original decoded body and the body actually returned by Blinder. A measurement header or keyed content tag does not substitute for matching those bytes in length. Content-Length must always report the actual emitted representation.

This change removes two avoidable sources of size drift:

- A short ordinary title no longer expands to `Transformed view`. Source-dependent filler occupies the title's own byte budget, including long, Unicode, entity-bearing and incomplete titles. `<title>X</title>` now remains **16 bytes**, where the previous constant replacement produced 31. Error titles retain their existing diagnostic treatment.
- Changing an existing quoted attribute no longer needlessly serializes the entire start tag. Where parsing is unambiguous and the attribute list is unchanged, only changed values are edited. Original tag case, whitespace, boolean attributes, quote style and untouched entity spellings remain. The synthetic `<INPUT DISABLED data-note='BrandToken'>` fixture stays **39 bytes**, where whole-tag serialization produced 42. The configured identity is still replaced and parsed attribute values are verified.

Actual proxy-response regressions inspect returned bytes, Content-Length and size measurements, with no spare prose or padding in these fixtures. Unit tests cover same-session stability, title-only differences, malformed-source fallback, duplicate/unquoted attribute rejection, residual identity checks and quoted-value semantics. Existing whole-body fitting still adjusts generated ordinary prose after HTML rewriting; these fixes reduce the work it needs to do.

## Remaining size constraints

Exact length remains unfulfilled when identity or routing replacements expand a body that has no adjustable generated prose. Diagnostic text, scripts and submitted values must not be truncated to hide that mismatch. JSON/plain-text transformations and binary substitution need their own length-preserving designs. A pinned SRI representation may also carry necessary collision-separating whitespace; stripping it would break the associated integrity/control decision.

This checkpoint targets decoded body length. Compressed wire length is a separate constraint because masking changes compressibility; no compressed-length equivalence is claimed. It does not close the JavaScript-URL, image-event or malformed-source evidence defects recorded in the [content-signal audit](testing-results-2026-09-26-content-signals.md). Same-size output is necessary for length comparisons but does not by itself prove equivalent application behavior.

## Validation

**854 top-level tests across 17 packages** passed with the race detector. The **12 functional tests** and vet passed. Chrome passed all **20 paired inline CSP/control cases** (40 browser observations), including event handlers, nonce/hash permissions, denied execution, policy intersection and report-only outcomes. The existing trusted loopback certificate was reused; no trust setting changed.

Evidence: `/Users/carroll/.codex/visualizations/2026/09/23/01a0ce57-c07e-79e0-a189-9f6c7c6023dd/blinder-body-size-2026-09-26`. Source manifest SHA-256: `a4a30743f255b1f187441b73eeff5e259cf93db15704ec029f0c1001a2d35a38`. This batch remains local and the running preview is unchanged.
