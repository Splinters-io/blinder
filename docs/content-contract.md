# Content is part of correctness

Blinder must mask configured identity and ordinary display prose with care. A working reverse proxy is not sufficient if its replacement text damages the observable application or fills a page with notices about removal. This is a delivery requirement, not a cosmetic task to defer.

## Generated display content

Ordinary replaced prose and titles use neutral, session-stable verse/lorem filler within the available byte budget. Short labels need a bounded neutral representation. Blinder must not invent visible labels such as `REDACTED`, `[removed]`, `[image]`, `content hidden` or `Blinder: title removed`. This applies to page text and generated titles, alt text, accessible labels and tooltips, not just the visible paragraph path.

Replacement vocabulary also needs identity checks: a configured brand/name that happens to be a word in the filler corpus must not reappear because Blinder generated it. Content that stays the same should have stable output in the session; a source change should remain observable. Finite output capacity and conservative fallbacks must be recorded rather than described as an unlimited guarantee.

## Preserve the application and its evidence

Functional values are not prose. Submitted fields, cookies, paths, query values and other values that the application expects back need reversible, unambiguous mappings. JavaScript/CSS syntax, markup structure, HTTP statuses, errors, reflected input, malformed responses and security-control allow/block decisions need their appropriate transformation paths and direct/proxy comparisons. Do not make an error into a successful response to make the page look complete.

The words above are forbidden as **invented replacement notices**, not as a global ban on source data. A real error saying “record removed,” an application value containing `[REDACTED]`, or a reflected test string must not silently disappear under a text blacklist. Keep diagnostic and functional values according to their existing context rules. Ordinary prose remains eligible for the configured prose-masking mode.

Each response targets its own original decoded body size. Use valid format-aware padding or adjust generated prose when appropriate; never falsify Content-Length, cut evidence or repair malformed syntax just to meet a byte count. Preserve original/output measurements when exact size cannot be achieved. Equal size alone is not equal behavior.

Explicit `X-Blinder-View: transformed` provenance, size/change measurements and original operator evidence remain available. Neutral filler is a privacy and content-quality requirement, not a claim that the proxy is indistinguishable from the upstream or that another model's assessment or safeguards will be bypassed.

## Acceptance and runtime checks

1. Test generated replacements separately from literal upstream text. Include ordinary pages, titles/attributes, functional values and diagnostic/error responses; retain round-trip and byte-size assertions where applicable.
2. Check both configured identities and invented removal labels in emitted fixture responses. Do not pass a test by suppressing the entire response, hiding a control or erasing the diagnostic that reveals a defect.
3. Verify content and behavior through the actual serving build. Record the listener's executable and revision; recompilation does not replace an existing process or its in-memory caches/mappings.
4. Preserve evidence before an authorized restart. Session-local aliases can change across restarts; a stale browser page is not an acceptance result for the new session.
5. Keep browser, Tor and human CAPTCHA results separate from package tests. Skips, unavailable clients and timed-out attempts do not close delivery gates.

On 2026-09-26, the listener at `127.0.0.1:8099` was confirmed to be running `8d381b9`, while source had reached `eb681ee`. Its root response contained 110 generated `[REDACTED:…]` values and one generated title-removal label. Current source used neutral reversible values and prose already. This runtime mismatch is why future reports must identify what is actually serving, not only what has been fixed in source.
