# Behavior-preservation checkpoint — 2026-09-26

This local checkpoint follows `07e4c1f`. It addresses three ways the masked response could distort a finding: JavaScript navigation URLs treated as domain text, failed images turned into successful GIF loads, and identity-bearing malformed HTML discarded despite having a preservable source envelope. Implementation and package checks are complete; final browser acceptance remains open.

## Changes

JavaScript navigation attributes now use the JavaScript rewriter. Member expressions and executable syntax remain intact; configured identities in string values follow the existing masking rules. URL preprocessing and percent decoding are separate from serialization. CSP hashes bind the decoded full URL, including `javascript:`, to the corresponding rewritten source. Collision-separating whitespace is percent-encoded in the emitted URL so browser URL preprocessing cannot remove it. Invalid percent-decoded UTF-8 uses Chromium's whole-sequence isomorphic fallback; invalid HTML input is normalized before that decoding step.

Raster image references now make their ordinary routed requests, retaining upstream status and browser policy enforcement. Bounded JPEG, static PNG and GIF content becomes neutral pixels in the original format and dimensions. GIF frame geometry, timing, disposal and loop count are retained; JPEG EXIF is rebuilt with only orientation. Invalid binary remains undecodable instead of becoming a valid GIF. Printable error bodies remain scrubbed diagnostics. Embedded raster data URLs use the same masking.

Legal PNG chunks, JPEG comments and GIF comments fill available gaps toward the original decoded byte size. An encoding larger than the original, or a gap smaller than the format's minimum padding structure, retains its real difference. The proxy never advertises a false Content-Length. Decode budgets are 16,384 pixels per dimension, 16,777,216 cumulative pixels and 256 GIF frames.

Identity edits in unambiguous malformed HTML retain their original raw envelope: ordinary/bogus/unterminated comments and incomplete trailing tags stay malformed in the same way. No new closing delimiter or repaired executable element is invented. Source spelling outside the changed interval remains intact. Cross-delimiter identity cases still use conservative omission; multiple changes can normalize entities inside the interval between the first and last change.

## Verification

* `go test -race -count=1 -json ./...`: **919 top-level tests passed across 19 packages**, zero failures or race reports. Ten opt-in browser tests skipped; these are not acceptance passes.
* `go test -race -count=1 -tags functional -json ./tests/functional`: **12 top-level tests and 26 subtests passed**, no skips or failures.
* `go vet -tags functional ./...`: clean.
* Focused regressions cover URL execution syntax and CSP hash relationships, raster decode/error outcomes and padding boundaries, and malformed-source preservation. HTTP fixtures include real 503 responses, diagnostic text, actual Content-Length and restoration checks.

The initial full-suite run exposed an outdated assertion requiring a broken JPEG response to become a valid GIF. That assertion now requires the decode failure and scrubbed diagnostic to remain visible. Both the initial failure and final passing run are retained in the evidence.

## Browser finding and pending rerun

The first native Chrome run completed **13 direct/proxy pairs: 12 passed and one failed**. A percent-encoded JavaScript URL whose policy hashed only its encoded spelling was blocked directly but allowed after rewriting. This was an introduced permission, not an acceptable rendering difference.

The implementation was corrected to hash the decoded full URL, with regressions for the original decoded hash, encoded-spelling denial, rewritten-only denial and invalid UTF-8 fallback. This matches the decoding in Chromium's [navigation execution/CSP implementation](https://github.com/chromium/chromium/blob/main/third_party/blink/renderer/core/frame/local_dom_window.cc) and [URL decoding implementation](https://github.com/chromium/chromium/blob/main/url/url_util.cc).

The expanded fixture contains **15 pairs**, including explicit expected execution, CSP violations, image load/error events and dimensions, real upstream image request counts, and malformed comment execution boundaries. It does not count two unexpected failures as equivalent success. Incomplete trailing source also has a separate wire-level check because the browser discards it from the DOM.

The final rerun did **not** complete: the Chrome connection became unavailable and the native browser was at its profile picker. The fixture timed out without completed reports. Its evidence is retained separately from the initial finding. No profile was selected on the operator's behalf, certificate warning bypassed, trust installed or browser protection changed. The previous checkpoint's 49 passing CSP pairs apply to that earlier revision; they are not substituted for acceptance of these changes.

## CAPTCHA and Tor readiness

The existing synthetic CAPTCHA browser fixture now records every provider request alongside the requests actually relayed through the configured transport. Successful completion must match the two multisets, preserve the original session and CSRF fields, and show no target/operator credential export. Failure and timeout evidence is also saved. The HTTP fixture's provider aliases now use its actual listener scheme. Dynamically constructed absolute provider URLs remain in the fixture so that direct browser egress cannot be hidden by simplifying the test. This updated browser flow has not yet been run.

A fresh isolated Tor 0.4.9.8 client opened an ephemeral loopback SOCKS endpoint but reached only **5% bootstrap within 60 seconds**. It was stopped cleanly without target requests or changes to system routing/trust. This is incomplete readiness within the bounded check, not evidence of successful live Tor/onion acceptance or a Blinder transport defect. An initial rejected `:0` SOCKS configuration and the corrected `:auto` attempt are retained separately.

## Remaining acceptance

The next browser work is the expanded behavior comparison, the existing inline/external CSP comparisons after these source changes, and the complete synthetic human-completion CAPTCHA flow. That flow must exercise dynamic provider requests, cookies and origin isolation without relaxing CORS or accepting an opaque origin merely to make a test pass. Live onion/human-provider acceptance, extra-origin alias resolution/trust and the selected scanner workflow remain separate gates.

Raster coverage does not include APNG animation, WebP/AVIF/BMP or embedded SVG; these can become undecodable. Network SVG retains the existing XML path. PNG EXIF orientation, decoder tolerance differences and pixel/canvas semantics remain open. Other binary media still use the legacy GIF replacement. Limited JavaScript parsing, source serialization, short-text saturation and conservative malformed-source omissions also prevent a universal claim of application-security fidelity. Exact byte size alone does not establish matching execution or findings.

The user's running preview was not replaced, and no GitHub push was made.

## Evidence

Local logs, both browser attempts, Tor readiness and a hashed source-input manifest are stored in:

```text
/Users/carroll/.codex/visualizations/2026/09/23/01a0ce57-c07e-79e0-a189-9f6c7c6023dd/blinder-behavior-fidelity-2026-09-26/
```

The 243-file Go source/module manifest SHA-256 is `34209e3367a1c30ebf1de148b6bbe1fe5e8a5c69cb65bc11811d8ea47119926a`.
