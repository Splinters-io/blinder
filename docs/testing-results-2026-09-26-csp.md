# CSP control comparison — 26 September 2026

Native Chrome produced matching results for **20 original/proxy case pairs, 40 passing subtests**. The fixture checked execution, computed style and `securitypolicyviolation` events against explicit expectations, then compared Blinder with the direct baseline. This establishes the listed cases; it does not establish equivalent behavior for every CSP policy or application.

## Change and acceptance rule

Blinder must preserve the target's control decisions while masking content and translating registered origins. Inline script/style and attribute hashes now track original and rewritten source. Only a hash matching the original source gains the corresponding rewritten hash. A hash matching only the transformed bytes remains unable to authorize that content, including when `unsafe-inline` is present. Distinct original sources receive distinct transformed hash identities if routing would otherwise collapse their bytes.

Hash input accounts for UTF-8 replacement decoding and HTML text normalization. Base64 padding is validated before digest comparison; invalid padding is not repaired. Nonce values in HTML attributes and CSP headers use the same mapping. Meta policy placement, separate policy fields, comma-delimited policies and report-only disposition are retained. Fixed sandbox and other control keywords retain their grammar; application-defined policy/report names remain masked. Configuring a CAPTCHA provider no longer widens the target's CSP or creates a policy when none existed.

## Observed browser results

Every row had the same result through the direct baseline and Blinder. The fixture's independent reporting script was separately authorized.

| Case | Result in both views |
| --- | --- |
| Valid inline script hash | Script executed; no policy violation. |
| Hash matching only rewritten content | Script blocked; enforcing `script-src-elem` event. |
| Rewritten-content hash with `unsafe-inline` | Script remained blocked; enforcing `script-src-elem` event. |
| Valid hash with CRLF source text | Script executed after browser newline normalization. |
| Valid hash without base64 padding | Script executed. |
| Invalid extra base64 padding | Script stayed blocked; the rewrite did not repair the permission. |
| Malformed UTF-8 byte in a script comment | Script executed using the browser-decoded text hash. |
| Distinct source strings converging during routing | Exactly one execution; the originally denied source remained blocked. |
| Matching nonce | Script executed. |
| Nonmatching nonce | Script blocked; enforcing `script-src-elem` event. |
| Matching identity-bearing nonce | Masked nonce still authorised the script. |
| Different identity-bearing nonces | Masking preserved the mismatch and blocked the script. |
| Valid inline style hash | Computed color was `rgb(1, 2, 3)`. |
| Handler hash with `unsafe-hashes` | Event handler executed. |
| Handler hash without `unsafe-hashes` | Handler blocked; enforcing `script-src-attr` event. |
| Handler declared before a later meta policy | Handler executed under the policy active when invoked. |
| Two enforcing policies | Restrictive policy blocked the script despite permission in the other. |
| Report-only policy | Script executed and produced a report-only `script-src-elem` event. |
| Meta policy placement | Earlier script executed; later script was blocked. |
| Valid hash in a meta policy | Script executed. |

The run used `TestControlFidelityBrowser` in `internal/proxy/control_fidelity_browser_test.go` with `BLINDER_REVIEW_BROWSER=1`. The direct and proxy endpoints were local HTTPS listeners at `127.0.0.1:50433` and `127.0.0.1:50432`; the application fixture was local too. Browser evidence is `/private/tmp/blinder-csp-browser-result.json`, with `passed: true` and both sets of outcomes.

The existing acceptance leaf certificate was reused, SHA-256 `e67f6548a29e05e09c24269f0ed57a7bcbb5e28ffb381c487ac6214a368a68e3`. No certificate trust setting changed and no browser warning was bypassed. This run does not resolve the separate extra-origin certificate acceptance failure recorded in the [routing report](testing-results-2026-09-26-containment.md).

Focused CAPTCHA CSP regressions also passed with the race detector. They cover absent policies, `none`, inherited `default-src`, explicit denial, original provider permissions, report-only headers, multiple policies and ordinary registered-origin translation. Final validation passed 768 top-level tests across 16 packages with the race detector, 12 tagged functional tests in an isolated run, and `go vet -tags functional ./...`. Seven opt-in browser tests skipped in the ordinary suite; this CSP fixture was separately executed in Chrome. Opaque nonce mappings also round-trip through the actual proxy JSON/form request paths, including adjusted Content-Length. Literal nonce-shaped application values are escaped and restore without alias cascades. Work remains local and pushes remain held.

The concurrent functional run hit the existing three-second deadline in `TestAcceptanceOccupiedPortExits`, with no CLI output. The isolated run passed the same case in 0.31 seconds and all 12 functional cases passed. The CLI already binds before certificate preparation. This is retained as an unresolved timing issue; no deadline was relaxed and neither the failed run nor a skipped browser case is counted as passed.

## Remaining work

- Coordinate CSP hashes authorizing external resources with SRI verification and rewritten integrity metadata.
- Translate wildcard, scheme-less and port-expanded source expressions without changing the set of permitted origins.
- Give routed CAPTCHA resources distinct provider origins. The current Tor relay shares the target origin, so `'self'` and provider-specific sources can change meaning; removing automatic grants does not resolve that collapse.
- Preserve dynamically created nonce relationships and coordinate masked Trusted Types policy names with JavaScript creation calls. Identity-bearing named policies currently retain the existing masking behavior, which can make their CSP names invalid; preserving fixed keywords does not close this gap.
- Preserve CSP decisions when image substitution changes a network URL to a `data:` URL.
- Establish browser-equivalent decoding and hashing for non-UTF-8 HTML.

These cases need paired browser acceptance before broader control-fidelity claims. Live Tor/onion and real-provider human completion retain their separate delivery gates.

Policy parsing and matching are checked against the [W3C CSP specification](https://www.w3.org/TR/CSP3/). This report records observed browser decisions; it does not certify controls absent from the matrix.
