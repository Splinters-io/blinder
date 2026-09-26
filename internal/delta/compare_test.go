package delta

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/manifest"
)

const testSession = "0123456789abcdef0123456789abcdef"

func id(n int) string     { return fmt.Sprintf("%s:%d", testSession, n) }
func tag(s string) string { return strings.Repeat(s, 64) }

func entry(n int, original, rewritten int64, ot, rt string) manifest.RequestEntry {
	return manifest.RequestEntry{
		RequestID: id(n), Method: "GET", ContextTag: tag("a"), RequestTag: tag("b"), StatusCode: 200,
		Response: &manifest.ResponseMetrics{
			Source: "upstream", Upstream: []manifest.BodyRead{{StatusCode: 200, Complete: true, DecodedBytes: original}},
			OriginalBodyTag: tag(ot), RewrittenBodyTag: tag(rt), BodyComplete: true,
			OriginalBodyBytes: original, RewrittenBodyBytes: rewritten, DownstreamBytes: rewritten,
		},
	}
}

func runPair(t *testing.T, a, b manifest.RequestEntry) Report {
	t.Helper()
	r, err := Compare(manifest.ManifestFile{SessionID: testSession, Requests: []manifest.RequestEntry{a, b}}, []string{a.RequestID}, []string{b.RequestID})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestContentSignalsIncludeEqualLengthChanges(t *testing.T) {
	for _, tc := range []struct{ name, oldOriginal, newOriginal, oldMasked, newMasked, want string }{
		{"lost", "a", "b", "c", "c", "lost_change"},
		{"introduced", "a", "a", "b", "c", "introduced_change"},
		{"visible", "a", "b", "c", "d", "change_visible"},
		{"unchanged", "a", "a", "c", "c", "unchanged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runPair(t, entry(1, 50, 50, tc.oldOriginal, tc.oldMasked), entry(2, 50, 50, tc.newOriginal, tc.newMasked))
			c := r.Comparisons[0]
			if !c.Comparable || c.ContentSignal != tc.want || *c.OriginalBodyDeltaBytes != 0 || *c.RewrittenBodyDeltaBytes != 0 {
				t.Fatalf("incorrect same-length comparison: %+v", c)
			}
		})
	}
}

func TestConstantOverheadCannotHidePerBodyMismatch(t *testing.T) {
	r := runPair(t, entry(1, 10420, 10430, "a", "b"), entry(2, 10457, 10467, "c", "d"))
	c := r.Comparisons[0]
	if *c.DistortionBytes != 0 || *c.OriginalBodyDeltaBytes != 37 || *c.RewrittenBodyDeltaBytes != 37 {
		t.Fatalf("wrong deltas: %+v", c)
	}
	for _, o := range []Observation{r.Baselines[0], r.Tests[0]} {
		if o.ExactBodySize == nil || *o.ExactBodySize || *o.RewriteDeltaBytes != 10 {
			t.Fatalf("overhead hidden: %+v", o)
		}
	}
}

func TestSizeDistortionIsSigned(t *testing.T) {
	r := runPair(t, entry(1, 100, 100, "a", "b"), entry(2, 80, 90, "c", "d"))
	c := r.Comparisons[0]
	if *c.OriginalBodyDeltaBytes != -20 || *c.RewrittenBodyDeltaBytes != -10 || *c.DistortionBytes != 10 {
		t.Fatalf("wrong deltas: %+v", c)
	}
}

func TestIncompleteOrIndirectEvidenceIsInconclusive(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*manifest.RequestEntry)
	}{
		{"legacy", func(e *manifest.RequestEntry) { e.Response = &manifest.ResponseMetrics{} }},
		{"missing-response", func(e *manifest.RequestEntry) { e.Response = nil }},
		{"cache", func(e *manifest.RequestEntry) { e.Response.Source = "cache" }},
		{"sri-cache", func(e *manifest.RequestEntry) { e.Response.Source = "sri-cache" }},
		{"proxy", func(e *manifest.RequestEntry) { e.Response.Source = "proxy" }},
		{"multiple-attempts", func(e *manifest.RequestEntry) {
			e.Response.Upstream = append(e.Response.Upstream, e.Response.Upstream[0])
		}},
		{"partial-upstream", func(e *manifest.RequestEntry) { e.Response.Upstream[0].Complete = false }},
		{"read-error", func(e *manifest.RequestEntry) { e.Response.Upstream[0].Error = "private host error" }},
		{"partial-write", func(e *manifest.RequestEntry) { e.Response.DownstreamBytes-- }},
		{"unaccepted-body", func(e *manifest.RequestEntry) { e.Response.BodyComplete = false }},
		{"unknown-size", func(e *manifest.RequestEntry) { e.Response.OriginalBodyBytes = -1 }},
		{"inconsistent-original", func(e *manifest.RequestEntry) { e.Response.Upstream[0].DecodedBytes-- }},
		{"missing-original-tag", func(e *manifest.RequestEntry) { e.Response.OriginalBodyTag = "" }},
		{"missing-rewritten-tag", func(e *manifest.RequestEntry) { e.Response.RewrittenBodyTag = "" }},
		{"missing-context", func(e *manifest.RequestEntry) { e.ContextTag = "" }},
		{"missing-request-tag", func(e *manifest.RequestEntry) { e.RequestTag = "" }},
		{"unknown-method", func(e *manifest.RequestEntry) { e.Method = "" }},
		{"head", func(e *manifest.RequestEntry) { e.Method = "HEAD" }},
		{"upstream-304", func(e *manifest.RequestEntry) { e.Response.Upstream[0].StatusCode = 304 }},
		{"downstream-304", func(e *manifest.RequestEntry) { e.StatusCode = 304 }},
		{"upstream-204", func(e *manifest.RequestEntry) { e.Response.Upstream[0].StatusCode = 204 }},
		{"downstream-204", func(e *manifest.RequestEntry) { e.StatusCode = 204 }},
		{"upstream-101", func(e *manifest.RequestEntry) { e.Response.Upstream[0].StatusCode = 101 }},
		{"downstream-101", func(e *manifest.RequestEntry) { e.StatusCode = 101 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := entry(1, 50, 50, "a", "b"), entry(2, 50, 50, "a", "b")
			tc.mutate(&b)
			r := runPair(t, a, b)
			if r.Tests[0].Comparable || len(r.Tests[0].Reasons) == 0 || r.Comparisons[0].Comparable || r.Comparisons[0].ContentSignal != "inconclusive" || r.Comparisons[0].DistortionBytes != nil {
				t.Fatalf("bad evidence became comparable: %+v", r)
			}
			if tc.name == "legacy" && (r.Tests[0].OriginalBodyBytes != nil || r.Tests[0].ExactBodySize != nil) {
				t.Fatal("missing metadata became zero")
			}
		})
	}
}

func TestCredentialContextMismatchAndChangedInputs(t *testing.T) {
	a, b := entry(1, 50, 50, "a", "b"), entry(2, 50, 50, "c", "d")
	b.ContextTag = tag("c")
	r := runPair(t, a, b)
	if r.Comparisons[0].Comparable || !contains(r.Comparisons[0].Reasons, "request_context_changed") {
		t.Fatal("credential/origin context mismatch accepted")
	}
	b.ContextTag = a.ContextTag
	b.RequestTag = tag("e")
	r = runPair(t, a, b)
	if !r.Comparisons[0].Comparable || r.Comparisons[0].RequestChanged == nil || !*r.Comparisons[0].RequestChanged {
		t.Fatal("changed test inputs not identified")
	}
}

func TestBaselineVariationIsObservedAndNotSuppressed(t *testing.T) {
	a, b, c := entry(1, 50, 50, "a", "b"), entry(2, 60, 60, "c", "d"), entry(3, 70, 70, "e", "f")
	b.RequestTag = tag("f")
	b.Response.Upstream[0].StatusCode = 500
	m := manifest.ManifestFile{SessionID: testSession, Requests: []manifest.RequestEntry{a, b, c}}
	r, err := Compare(m, []string{id(1), id(2)}, []string{id(3)})
	if err != nil {
		t.Fatal(err)
	}
	v := r.BaselineVariation
	if len(r.Comparisons) != 2 || len(r.BaselineComparisons) != 1 || v.ComparablePairs != 1 || v.ChangedRequestPairs != 1 || !*v.OriginalContentVaried || !*v.MaskedContentVaried || !*v.UpstreamStatusVaried || *v.DownstreamStatusVaried {
		t.Fatalf("incorrect observed variation: %+v", r)
	}
	if r.Comparisons[0].ContentSignal != "change_visible" {
		t.Fatal("baseline variation suppressed test result")
	}
}

func TestStatusChangesRemainSeparate(t *testing.T) {
	a, b := entry(1, 50, 50, "a", "b"), entry(2, 50, 50, "a", "b")
	b.Response.Upstream[0].StatusCode = 500
	r := runPair(t, a, b)
	if !*r.Comparisons[0].UpstreamStatusChanged || *r.Comparisons[0].DownstreamStatusChanged {
		t.Fatal("upstream status change conflated with downstream")
	}
	if *r.Tests[0].UpstreamStatus != 500 || *r.Tests[0].DownstreamStatus != 200 {
		t.Fatal("status evidence lost")
	}
	if r.Comparisons[0].StatusSignal != "lost_change" || r.Tests[0].StatusPreserved == nil || *r.Tests[0].StatusPreserved {
		t.Fatal("lost status change not reported")
	}
	a.Response.Upstream[0].StatusCode = 500
	r = runPair(t, a, b)
	if r.Comparisons[0].StatusSignal != "unchanged" || *r.Baselines[0].StatusPreserved || *r.Tests[0].StatusPreserved {
		t.Fatal("constant status drift hidden by unchanged status deltas")
	}
}

func TestSelectionsValidatedWithoutReflectingSensitiveInput(t *testing.T) {
	a, b := entry(1, 50, 50, "a", "b"), entry(2, 50, 50, "a", "b")
	for _, tc := range []struct {
		name             string
		baselines, tests []string
		requests         []manifest.RequestEntry
	}{
		{"empty-baselines", nil, []string{id(2)}, []manifest.RequestEntry{a, b}},
		{"empty-tests", []string{id(1)}, nil, []manifest.RequestEntry{a, b}},
		{"duplicate-selection", []string{id(1), id(1)}, []string{id(2)}, []manifest.RequestEntry{a, b}},
		{"overlap", []string{id(1)}, []string{id(1)}, []manifest.RequestEntry{a, b}},
		{"missing", []string{id(1)}, []string{id(3)}, []manifest.RequestEntry{a, b}},
		{"duplicate-entry", []string{id(1)}, []string{id(2)}, []manifest.RequestEntry{a, a, b}},
		{"sensitive-id", []string{"https://private.example/secret"}, []string{id(2)}, []manifest.RequestEntry{a, b}},
		{"foreign-session", []string{strings.Repeat("a", 32) + ":1"}, []string{id(2)}, []manifest.RequestEntry{a, b}},
		{"leading-zero-counter", []string{testSession + ":01"}, []string{id(2)}, []manifest.RequestEntry{a, b}},
		{"huge-counter", []string{testSession + ":18446744073709551616"}, []string{id(2)}, []manifest.RequestEntry{a, b}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compare(manifest.ManifestFile{SessionID: testSession, Requests: tc.requests}, tc.baselines, tc.tests)
			if err == nil {
				t.Fatal("invalid selection accepted")
			}
			if strings.Contains(err.Error(), "private.example") || strings.Contains(err.Error(), testSession) {
				t.Fatal("error reflected input")
			}
		})
	}
}

func TestUnknownSessionIsInconclusive(t *testing.T) {
	m := manifest.ManifestFile{Requests: []manifest.RequestEntry{entry(1, 0, 0, "a", "b"), entry(2, 0, 0, "a", "b")}}
	r, err := Compare(m, []string{id(1)}, []string{id(2)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Comparisons[0].Comparable || !contains(r.Baselines[0].Reasons, "session_evidence_missing") {
		t.Fatal("missing session evidence accepted")
	}
}

func TestReportDoesNotExportPrivateMetadata(t *testing.T) {
	a, b := entry(1, 50, 50, "a", "b"), entry(2, 50, 50, "c", "d")
	a.Path = "/private-product-and-token"
	a.Timestamp = "private timestamp"
	m := manifest.ManifestFile{SessionID: testSession, TargetURL: "https://private.example", AliasDomain: "secret.alias", Requests: []manifest.RequestEntry{a, b}, IdentityVault: []manifest.IdentityEntry{{Author: "private operator"}}}
	r, err := Compare(m, []string{id(1)}, []string{id(2)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{a.Path, a.Timestamp, m.TargetURL, m.AliasDomain, "private operator", a.ContextTag, a.RequestTag, a.Response.OriginalBodyTag, a.Response.RewrittenBodyTag} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("private metadata exported: %q", forbidden)
		}
	}
}

func TestBoundsAndDistortionOverflow(t *testing.T) {
	_, err := Compare(manifest.ManifestFile{}, make([]string, MaxComparisons+1), []string{id(1)})
	if err == nil {
		t.Fatal("unbounded selection accepted")
	}
	r := runPair(t, entry(1, math.MaxInt64, 0, "a", "b"), entry(2, 0, math.MaxInt64, "c", "d"))
	if r.Comparisons[0].Comparable || !contains(r.Comparisons[0].Reasons, "size_delta_overflow") {
		t.Fatal("overflow accepted")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
