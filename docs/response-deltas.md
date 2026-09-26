# Comparing response changes

Blinder records both the original response and the bytes written after masking. The local `blinder-diff` command compares deliberately selected baseline and test requests from one session. It checks whether a size or exact-content change survives masking, and whether masking introduces a change that was absent upstream. It does not contact the target or replay any request.

## Capture and compare

Start Blinder with `--output /path/to/private-output`. Make the baseline request more than once, then make the test request using your browser or scanner. Record each response's `X-Blinder-Request-ID` header. Keep the same credentials and proxy entry origin for the comparison. Request IDs are allocated when requests arrive, so concurrent responses can finish in a different order without changing their identity.

Stop Blinder normally to flush `blinder-manifest.json`, then run:

```sh
make build-diff
./blinder-diff \
  -manifest /path/to/private-output/blinder-manifest.json \
  -baseline "$baseline_request_id_1,$baseline_request_id_2" \
  -test "$test_request_id"
```

The variables above contain complete IDs copied from the response headers, including the session prefix. Multiple test IDs can also be comma separated. Select requests explicitly: the tool does not infer which requests belong together from their paths. The manifest is operator-private and still contains target information; the comparison JSON contains opaque request IDs, measurements and findings, without response bodies, URLs, credentials, identity-vault entries or content fingerprints.

Exit status 0 means the report was produced, not that fidelity passed. Invalid input or a read/write failure returns 2. Read the per-response checks and comparisons, including inconclusive reasons, when deciding whether a workflow is ready. Inputs are limited to 64 MiB and selections to 4,096 comparisons, including baseline pairs.

Only complete target HTTP responses obtained by a single upstream attempt are eligible for a fresh-body comparison. Cache hits, revalidation, SRI cache responses, local failures, incomplete writes, HEAD and bodyless statuses remain visible as ineligible evidence. The command neither bypasses the cache nor repeats state-changing requests. Earlier manifests without the new evidence cannot establish a comparison.

## Reading the result

For each selected test and baseline pair, the report compares:

* Original decoded body length and rewritten body length for **each** response.
* Original test-minus-baseline length change, rewritten test-minus-baseline change, and the difference between those changes.
* Whether original content changed and whether the emitted content changed, including changes at identical byte lengths.
* Original and downstream status changes.
* Whether the captured request inputs changed, independently of the response changes.

For example, original bodies of 10,420 and 10,457 bytes should produce rewritten bodies of 10,420 and 10,457 bytes: both changes are +37. Rewritten bodies of 10,430 and 10,467 also have a +37 change, but each is ten bytes too large. The report retains both per-response size checks so that constant overhead cannot disappear in the subtraction.

Changed original content with unchanged output is a lost body change. Unchanged original content with changed output is an introduced body change. When both change, the report establishes only that a change remains visible. It cannot determine whether a diagnostic, reflected payload, parser condition or execution outcome survived.

Each observation also includes `short_text_fallbacks`: the number of short display-text generation attempts in that request that could not reserve a unique output. This can include intermediate prose that was subsequently resized; it is neither a count of affected responses nor proof that the final bodies collided. Cache hits perform no new generation. A nonzero count explains a possible lost signal, while zero does not guarantee that longer prose or other transformations preserved every change.

Short display reservations cover 1–8-byte budgets, remain immutable within the session, and have a 4,096-entry cap and 8,192-probe allocation bound. One byte offers at most 64 outputs; fallback can therefore be unavoidable. Fixed-width identity aliases separately reduce size drift for configured matches of at least five UTF-8 bytes, but short identities, namespace exhaustion, source escapes and routing changes can still alter lengths. Continue checking both per-response sizes and paired content changes.

Repeated baselines are compared separately. Their observed variation is reported, not discarded or automatically classified as harmless noise. Different request fingerprints flag different captured inputs. Matching fingerprints do not freeze server-side session state or prove that a later difference was caused by a test payload.

## Measurement boundary

Body size means **decoded HTTP representation bytes**, excluding HTTP framing, TLS overhead and gzip size. `body_complete` means the full planned representation was accepted by the HTTP response writer without a write error. It does not prove that the client received it. `rewritten_body_tag` fingerprints those accepted bytes; the original tag remains keyed privately to the proxy session.

Context fingerprints bind comparisons to the session, local scheme and authority, configured upstream origin, method, and all Cookie/Authorization header values. Request fingerprints additionally cover the captured local URI, headers, content length and body before restoration. These are equality signals, not an assertion that every application session mechanism is understood.

The first comparator covers ordinary target HTTP responses. Provider/operator traffic, WebSocket messages, individual SRI prefetches, structural diffs, response-header semantics, timing analysis and browser execution need separate evidence. Exact content changes and size matching do not establish exploit success or universal control fidelity. The monitor reports fidelity failures; it does not repair the remaining size or semantic differences.

The [local verification report](testing-results-2026-09-26-delta-monitor.md) records the first real HTTP fixture results, regressions and the functional startup timeout followed by the unchanged passing rerun. The [size and change-signal follow-up](testing-results-2026-09-26-size-signals.md) records compact identity aliases and bounded short-text reservations.
