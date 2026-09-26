# External CSP and SRI comparison — 26 September 2026

Native Chrome passed **29 direct/proxy pairs for external resources** and a rerun of the **20 earlier inline-control pairs**: 98 passing browser subtests. The external fixture compares execution, resource errors and CSP enforcement/report events, and separately records upstream resource requests. This is acceptance of the listed static-document cases, not universal browser or application equivalence.

## What changed

Integrity metadata is now derived per reference from the cached representation. A later SHA-512 reference no longer inherits an earlier SHA-256 reference's hash. Supported weaker entries remain part of CSP membership even when SRI verifies only the strongest algorithm. Original and rewritten metadata participate in the same document policy translation as inline hashes, with separate enforcing/report-only fields and meta position retained.

The proxy evaluates the original enforcing source lists before an SRI prefetch. A denied element stays in the document with its original metadata so Chrome generates the original policy violation and resource error; the proxy does not issue an upstream request on its behalf. Nonces, full URL sources, directive fallback, policy intersection and parser-inserted strict-dynamic are covered by local regressions. Report-only policy does not suppress fetching.

Before rewriting, the document reserves original inline hashes and external integrity identities, including references that will remain untouched. Different originals therefore cannot acquire each other's permissions when their rewritten bytes converge. Collision-only whitespace separates those representations. The selected variant is bound to the existing authenticated resource version and reproduced after no-store, forced revalidation or body-cache eviction; original bytes must first satisfy the stored full digest. Ordinary non-colliding resources receive no such padding, and response Content-Length describes the actual returned bytes.

The static prepass uses the first base href, including when it is empty, invalid or blocked by base-uri; later bases do not override it. Enforcing meta policies are applied in their document scope, templates remain inert, and SRI and opaque-resource URL resolution share the prepared base. Classic nomodule resources are not prefetched for the tested modern Chrome workflow. SRI parsing recognises Chrome's lowercase legacy algorithm aliases and ignores unknown uppercase algorithm names; CSP algorithm parsing remains separate.

## Browser acceptance

| Cases | Direct and Blinder result |
| --- | --- |
| Original SHA-256/SHA-512 authorisation, including both cache orders | Execute with matching integrity; proxy reuses the resource without choosing the wrong algorithm. |
| Padded, unpadded and URL-safe equivalents | Execute with no new policy violation. |
| Chrome legacy sha-256 and an ignored uppercase entry beside valid SHA-512 | Execute with the original supported constraint. |
| Policy hash matching only transformed content | Block and emit an enforcing violation plus resource error; zero upstream resource requests. |
| Multiple integrity entries | All supported entries remain necessary for CSP membership. |
| Invalid weaker entry with valid stronger entry | Execute when CSP contains both; missing weaker permission still produces the original report. |
| Host or nonce permission, including a masked identity nonce | Execute despite a nonmatching hash alternative. |
| Separate intersecting policies | Restrictive policy blocks; zero upstream resource requests. |
| Report-only and malformed extra padding | Execute and retain the original report disposition. |
| Meta policy before/after a resource | Earlier resource executes; the later denied reference stays denied. |
| Inline/external convergence in both orders | Originally denied code remains blocked. |
| Two external resources converging, including no-store refetch | Both execute under report-only and retain the original differing report decisions. |
| Invalid weaker metadata colliding with inline output | Inline code cannot acquire a new permission. |
| Untouched denied reference colliding with an authorised rewrite | Denied reference stays blocked with zero upstream requests. |
| Classic nomodule | No execution, resource error, violation or upstream request in Chrome. |

The final external endpoints were `https://127.0.0.1:62344` (direct) and `https://127.0.0.1:62343` (proxy). The earlier inline fixture was rerun at ports 62477 and 62476. All application traffic was synthetic and local. The existing acceptance leaf certificate was reused; trust settings were unchanged and no certificate warning was bypassed.

The first browser run exposed an overly literal base64 comparison in the prefetch evaluator. Chrome accepts equivalent decoded digests, so that comparison was corrected and the explicit expectations now pass. That run also showed two direct browser requests across different integrity references; browser cache reuse was not made a delivery requirement. Proxy cache reuse remains separately asserted, and zero-request requirements for denied resources were retained. The failed initial run is kept with the evidence.

## Validation and evidence

- `go test -race -count=1 ./...`: 792 top-level tests passed across 16 packages.
- `go test -race -tags functional -count=1 ./tests/functional`: 12 top-level tests passed.
- `go vet -tags functional ./...`: clean.
- Both opt-in control browser fixtures ran in Chrome and passed; eight opt-in browser tests skip in the ordinary suite, and those other skips are not counted as acceptance.
- Version fallback regressions verify no-store, request no-cache and eviction with exact emitted-integrity and Content-Length checks. Cache tests also exercise concurrent reservations, cache-capacity-one documents and immutable previous versions.

Evidence directory: `/Users/carroll/.codex/visualizations/2026/09/23/01a0ce57-c07e-79e0-a189-9f6c7c6023dd/blinder-external-csp-2026-09-26`. It includes browser reports, request counts, full race/functional logs, initial failures and a source manifest. Source manifest SHA-256: `bdb966820cd973dd273fdb67a9520a48dd3e7570a11d4449a320b26d3b94b998`.

## Scope still requiring acceptance

Broader CSP source-expression translation, dynamic DOM/nonce relationships, Trusted Types names, image-to-data-URL substitution and non-UTF-8 HTML remain separate work. The prefetch evaluator is an initial static script/stylesheet check, not an implementation of redirect checks, mixed-content processing, upgrade-insecure-requests or a full HTML tree builder. Other browser engines and legacy browsers need their own paired acceptance. The existing extra-origin certificate gate is unchanged.

Tor CAPTCHA provider origin isolation is next: the current relay shares an embedding origin and changes provider CORS/CSP behaviour. The new external-resource checks do not close that gate, live Tor/onion acceptance or real-provider human completion.

The acceptance rule follows the [CSP specification](https://www.w3.org/TR/CSP3/), with the browser behaviour recorded explicitly when syntax handling differs from a literal reading. This report covers source checkpoint `36b700b`, following the previously published baseline `d659e9c`.
