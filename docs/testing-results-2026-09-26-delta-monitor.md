# Paired response comparison — 2026-09-26

This local checkpoint follows `57a093e` and adds an offline comparator for original-versus-masked response changes. Each ordinary target HTTP response receives a session-scoped request ID. Manifest entries capture private request/context fingerprints, the original-content tag, completed rewritten-body fingerprint and both decoded sizes. Requests are selected explicitly; no target requests are scheduled or replayed by the comparator.

## Verified results

* `go test -race -count=1 -json ./...`: **882 top-level tests passed across 19 packages**, with no race reports. Nine opt-in tests skipped; these are not acceptance passes.
* `go vet -tags functional ./...`: clean.
* `CGO_ENABLED=0 go build` for both `cmd/blinder` and `cmd/blinder-diff`: passed.
* Final `go test -tags functional -race -count=1 -timeout 120s -json ./tests/functional`: **12 top-level functional tests passed**, including synthetic Tor/WebSocket coverage.

The initial functional invocation, run concurrently with the main race suite, hit the occupied-port test's three-second startup deadline without any CLI output. All eleven other top-level tests passed. The occupied-port test then passed in isolation, and the full functional suite passed on unchanged code. Both attempts are retained. The cause of the initial startup delay is not established; the deadline and test were not relaxed.

## Real HTTP comparison

`TestDeltaAcceptancePairedHTTPResponses` uses real loopback HTTP transports and a synthetic upstream. Two identical baselines and three test responses produced:

| Observation | Original decoded bytes | Rewritten bytes | Downstream status |
| --- | ---: | ---: | ---: |
| Baseline 1 | 102 | 102 | 200 |
| Baseline 2 | 102 | 102 | 200 |
| Different prose, same length | 102 | 102 | 200 |
| Longer response | 118 | 118 | 200 |
| Error diagnostic | 43 | 43 | 503 |

All six test/baseline comparisons reported zero length distortion and visible content changes. The baseline pair stayed stable, ordinary source prose and the configured identity were masked, and the diagnostic/error status survived. Running the built `blinder-diff` binary against the saved manifest produced the same JSON as the library comparison.

`TestDeltaAcceptanceDetectsActualMaskingCollision` finds two different short Unicode titles that produce the same fixed-size filler. The comparator reports `lost_change` despite both size deltas being zero and the submitted request being unchanged. This diagnoses a real finite-output collision; it does not claim that all content differences survive masking.

## Regression boundaries

Tests cover lost and introduced changes, constant size/status mismatches hidden by equal pairwise deltas, signed size distortion, baseline variation, changed inputs, credential/origin isolation, source/cache provenance, missing evidence, invalid selections and bounded report inputs. Separate observer tests cover completed empty bodies, gzip error responses, upstream read failures, short/error writes, concurrent request IDs and immutable manifest snapshots.

Request fingerprints use deterministic length-prefixed raw bytes. Invalid UTF-8 header values remain distinct, repeated header values retain their boundaries, and header insertion order does not add variation. This describes the request accepted by Go's HTTP parser, not an archival copy of wire framing.

Reports omit original content, fingerprints, paths, target URLs and identity-vault data. The input manifest remains operator-private. A successful CLI exit means a report was produced; findings and inconclusive reasons still need interpretation.

Structural changes, response-header semantics, timing, browser execution, provider/operator traffic and WebSocket messages are outside this first comparator. It does not fix the remaining representation-size differences, establish exploit success or replace browser control comparisons. No live Tor/onion acceptance, browser UAT, trust installation or preview restart was performed in this checkpoint.

Local machine-readable evidence is stored in:

```text
/Users/carroll/.codex/visualizations/2026/09/23/01a0ce57-c07e-79e0-a189-9f6c7c6023dd/blinder-delta-monitor-2026-09-26/
```

It contains the race/vet/functional results, both startup-test attempts, synthetic fixture inputs, the CLI report and verification metadata. The executable/test source-input manifest has SHA-256 `c0bef2e055a865910eb4a276a1fd55975969e79bc8ad3685c2f1d027082068c7`. The workflow is documented in [response comparisons](response-deltas.md).
