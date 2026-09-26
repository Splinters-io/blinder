// Package delta compares explicitly selected observations from one local
// manifest. It never fetches or replays a request, and its reports omit target
// identities, paths, credentials, and content fingerprints.
package delta

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/Splinters-io/blinder/internal/manifest"
)

const MaxComparisons = 4096

var (
	sessionPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	requestPattern = regexp.MustCompile(`^[0-9a-f]{32}:[1-9][0-9]*$`)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Observation describes one response. Null measurements mean unavailable, not
// zero. Complete means the proxy accepted every representation byte for writing;
// it cannot establish that the client received those bytes.
type Observation struct {
	RequestID          string   `json:"request_id"`
	Comparable         bool     `json:"comparable"`
	Reasons            []string `json:"reasons"`
	UpstreamStatus     *int     `json:"upstream_status"`
	DownstreamStatus   *int     `json:"downstream_status"`
	StatusPreserved    *bool    `json:"status_preserved"`
	ShortTextFallbacks int      `json:"short_text_fallbacks"`
	OriginalBodyBytes  *int64   `json:"original_body_bytes"`
	RewrittenBodyBytes *int64   `json:"rewritten_body_bytes"`
	RewriteDeltaBytes  *int64   `json:"rewrite_delta_bytes"`
	ExactBodySize      *bool    `json:"exact_body_size"`
}

// Comparison describes B minus A. ChangeVisible establishes only inequality,
// never preservation of meaning, exploit behavior, or security controls.
type Comparison struct {
	BaselineID              string   `json:"baseline_id"`
	TestID                  string   `json:"test_id"`
	Comparable              bool     `json:"comparable"`
	Reasons                 []string `json:"reasons"`
	RequestChanged          *bool    `json:"request_changed"`
	OriginalBodyDeltaBytes  *int64   `json:"original_body_delta_bytes"`
	RewrittenBodyDeltaBytes *int64   `json:"rewritten_body_delta_bytes"`
	DistortionBytes         *int64   `json:"distortion_bytes"`
	OriginalContentChanged  *bool    `json:"original_content_changed"`
	MaskedContentChanged    *bool    `json:"masked_content_changed"`
	UpstreamStatusChanged   *bool    `json:"upstream_status_changed"`
	DownstreamStatusChanged *bool    `json:"downstream_status_changed"`
	ContentSignal           string   `json:"content_signal"`
	StatusSignal            string   `json:"status_signal"`
}

type Variation struct {
	ComparablePairs        int   `json:"comparable_pairs"`
	InconclusivePairs      int   `json:"inconclusive_pairs"`
	ChangedRequestPairs    int   `json:"changed_request_pairs"`
	OriginalContentVaried  *bool `json:"original_content_varied"`
	MaskedContentVaried    *bool `json:"masked_content_varied"`
	UpstreamStatusVaried   *bool `json:"upstream_status_varied"`
	DownstreamStatusVaried *bool `json:"downstream_status_varied"`
}

type Report struct {
	Version             int           `json:"version"`
	Baselines           []Observation `json:"baselines"`
	Tests               []Observation `json:"tests"`
	Comparisons         []Comparison  `json:"comparisons"`
	BaselineComparisons []Comparison  `json:"baseline_comparisons"`
	BaselineVariation   Variation     `json:"baseline_variation"`
}

// Compare requires explicit, disjoint selections. Context changes (including
// credentials, origin, method and local view) make a pair inconclusive. Other
// input changes are reported so repeated baselines are not mistaken for proof
// of natural response variation. A legacy manifest can produce an inconclusive
// report, but measurements absent from it are never treated as zero.
func Compare(m manifest.ManifestFile, baselineIDs, testIDs []string) (Report, error) {
	if len(baselineIDs) == 0 || len(testIDs) == 0 {
		return Report{}, errors.New("both baseline and test selections are required")
	}
	if len(baselineIDs) > MaxComparisons || len(testIDs) > MaxComparisons ||
		len(baselineIDs)*len(testIDs)+len(baselineIDs)*(len(baselineIDs)-1)/2 > MaxComparisons {
		return Report{}, errors.New("too many selected comparisons")
	}
	if m.SessionID != "" && !sessionPattern.MatchString(m.SessionID) {
		return Report{}, errors.New("invalid manifest session identifier")
	}
	selected := make(map[string]bool, len(baselineIDs)+len(testIDs))
	for _, ids := range [][]string{baselineIDs, testIDs} {
		for _, id := range ids {
			if !validRequestID(id) || (m.SessionID != "" && !strings.HasPrefix(id, m.SessionID+":")) {
				return Report{}, errors.New("invalid or foreign request identifier")
			}
			if selected[id] {
				return Report{}, errors.New("duplicate or overlapping request selections")
			}
			selected[id] = true
		}
	}
	entries := make(map[string]manifest.RequestEntry, len(selected))
	seen := make(map[string]bool)
	for _, e := range m.Requests {
		if e.RequestID == "" {
			continue
		}
		if seen[e.RequestID] {
			return Report{}, errors.New("duplicate request identifier in manifest")
		}
		seen[e.RequestID] = true
		if selected[e.RequestID] {
			entries[e.RequestID] = e
		}
	}
	if len(entries) != len(selected) {
		return Report{}, errors.New("selected request is missing from manifest")
	}
	r := Report{Version: 1, Baselines: []Observation{}, Tests: []Observation{}, Comparisons: []Comparison{}, BaselineComparisons: []Comparison{}}
	observations := make(map[string]Observation, len(selected))
	for _, id := range baselineIDs {
		o := observe(m.SessionID, entries[id])
		observations[id] = o
		r.Baselines = append(r.Baselines, o)
	}
	for _, id := range testIDs {
		o := observe(m.SessionID, entries[id])
		observations[id] = o
		r.Tests = append(r.Tests, o)
	}
	for _, a := range baselineIDs {
		for _, b := range testIDs {
			r.Comparisons = append(r.Comparisons, compare(entries[a], entries[b], observations[a], observations[b]))
		}
	}
	for i, a := range baselineIDs {
		for _, b := range baselineIDs[i+1:] {
			c := compare(entries[a], entries[b], observations[a], observations[b])
			r.BaselineComparisons = append(r.BaselineComparisons, c)
			r.BaselineVariation.add(c)
		}
	}
	return r, nil
}

func observe(sessionID string, e manifest.RequestEntry) Observation {
	o := Observation{RequestID: e.RequestID, Reasons: []string{}}
	if sessionID == "" {
		o.Reasons = append(o.Reasons, "session_evidence_missing")
	}
	if !digestPattern.MatchString(e.ContextTag) {
		o.Reasons = append(o.Reasons, "context_evidence_missing")
	}
	if !digestPattern.MatchString(e.RequestTag) {
		o.Reasons = append(o.Reasons, "request_evidence_missing")
	}
	if e.StatusCode >= 200 && e.StatusCode <= 599 {
		o.DownstreamStatus = ptr(e.StatusCode)
	} else {
		o.Reasons = append(o.Reasons, "downstream_status_unknown")
	}
	if e.Method == "" {
		o.Reasons = append(o.Reasons, "method_unknown")
	} else if e.Method == "HEAD" {
		o.Reasons = append(o.Reasons, "head_has_no_emitted_body")
	}
	if e.StatusCode == 204 || e.StatusCode == 304 {
		o.Reasons = append(o.Reasons, "status_has_no_emitted_body")
	}
	m := e.Response
	if m == nil {
		o.Reasons = append(o.Reasons, "response_evidence_missing")
		return o
	}
	o.ShortTextFallbacks = m.ShortTextFallbacks
	if m.Source != "upstream" {
		reason := "response_source_unknown"
		switch m.Source {
		case "cache", "sri-cache":
			reason = "cached_response_not_fresh_upstream_evidence"
		case "proxy":
			reason = "proxy_generated_response"
		}
		o.Reasons = append(o.Reasons, reason)
	}
	if len(m.Upstream) != 1 {
		o.Reasons = append(o.Reasons, "single_upstream_attempt_required")
	} else {
		u := m.Upstream[0]
		if u.StatusCode >= 200 && u.StatusCode <= 599 {
			o.UpstreamStatus = ptr(u.StatusCode)
		} else {
			o.Reasons = append(o.Reasons, "upstream_status_unknown")
		}
		if u.StatusCode == 204 || u.StatusCode == 304 {
			o.Reasons = append(o.Reasons, "upstream_status_has_no_body")
		}
		if !u.Complete || u.Error != "" {
			o.Reasons = append(o.Reasons, "upstream_body_incomplete")
		}
		if m.BodyComplete && (u.DecodedBytes < 0 || u.DecodedBytes != m.OriginalBodyBytes) {
			o.Reasons = append(o.Reasons, "original_size_evidence_inconsistent")
		}
	}
	if !m.BodyComplete {
		o.Reasons = append(o.Reasons, "complete_body_evidence_missing")
	} else {
		if m.OriginalBodyBytes >= 0 {
			o.OriginalBodyBytes = ptr(m.OriginalBodyBytes)
		}
		if m.RewrittenBodyBytes >= 0 {
			o.RewrittenBodyBytes = ptr(m.RewrittenBodyBytes)
		}
		if o.OriginalBodyBytes == nil || o.RewrittenBodyBytes == nil {
			o.Reasons = append(o.Reasons, "body_size_unknown")
		} else {
			o.RewriteDeltaBytes = ptr(m.RewrittenBodyBytes - m.OriginalBodyBytes)
			o.ExactBodySize = ptr(m.RewrittenBodyBytes == m.OriginalBodyBytes)
		}
		if m.DownstreamBytes != m.RewrittenBodyBytes {
			o.Reasons = append(o.Reasons, "emitted_body_size_incomplete")
		}
	}
	if !digestPattern.MatchString(m.OriginalBodyTag) || !digestPattern.MatchString(m.RewrittenBodyTag) {
		o.Reasons = append(o.Reasons, "complete_content_fingerprints_missing")
	}
	if o.UpstreamStatus != nil && o.DownstreamStatus != nil {
		o.StatusPreserved = ptr(*o.UpstreamStatus == *o.DownstreamStatus)
	}
	o.Comparable = len(o.Reasons) == 0
	return o
}

func compare(a, b manifest.RequestEntry, oa, ob Observation) Comparison {
	c := Comparison{BaselineID: a.RequestID, TestID: b.RequestID, Reasons: []string{}, ContentSignal: "inconclusive", StatusSignal: "inconclusive"}
	if digestPattern.MatchString(a.RequestTag) && digestPattern.MatchString(b.RequestTag) {
		c.RequestChanged = ptr(a.RequestTag != b.RequestTag)
	}
	if !oa.Comparable {
		c.Reasons = append(c.Reasons, "baseline_evidence_ineligible")
	}
	if !ob.Comparable {
		c.Reasons = append(c.Reasons, "test_evidence_ineligible")
	}
	if a.ContextTag != "" && b.ContextTag != "" && a.ContextTag != b.ContextTag {
		c.Reasons = append(c.Reasons, "request_context_changed")
	}
	if a.Method != b.Method {
		c.Reasons = append(c.Reasons, "request_method_changed")
	}
	if len(c.Reasons) != 0 {
		return c
	}
	originalDelta := *ob.OriginalBodyBytes - *oa.OriginalBodyBytes
	rewrittenDelta := *ob.RewrittenBodyBytes - *oa.RewrittenBodyBytes
	if (originalDelta < 0 && rewrittenDelta > math.MaxInt64+originalDelta) ||
		(originalDelta > 0 && rewrittenDelta < math.MinInt64+originalDelta) {
		c.Reasons = append(c.Reasons, "size_delta_overflow")
		return c
	}
	c.Comparable = true
	c.OriginalBodyDeltaBytes = ptr(originalDelta)
	c.RewrittenBodyDeltaBytes = ptr(rewrittenDelta)
	c.DistortionBytes = ptr(rewrittenDelta - originalDelta)
	c.OriginalContentChanged = ptr(a.Response.OriginalBodyTag != b.Response.OriginalBodyTag)
	c.MaskedContentChanged = ptr(a.Response.RewrittenBodyTag != b.Response.RewrittenBodyTag)
	c.UpstreamStatusChanged = ptr(*oa.UpstreamStatus != *ob.UpstreamStatus)
	c.DownstreamStatusChanged = ptr(*oa.DownstreamStatus != *ob.DownstreamStatus)
	c.ContentSignal = signal(*c.OriginalContentChanged, *c.MaskedContentChanged)
	c.StatusSignal = signal(*c.UpstreamStatusChanged, *c.DownstreamStatusChanged)
	return c
}

func signal(originalChanged, rewrittenChanged bool) string {
	switch {
	case originalChanged && !rewrittenChanged:
		return "lost_change"
	case !originalChanged && rewrittenChanged:
		return "introduced_change"
	case originalChanged:
		return "change_visible"
	default:
		return "unchanged"
	}
}

func (v *Variation) add(c Comparison) {
	if c.RequestChanged != nil && *c.RequestChanged {
		v.ChangedRequestPairs++
	}
	if !c.Comparable {
		v.InconclusivePairs++
		return
	}
	v.ComparablePairs++
	orInto(&v.OriginalContentVaried, *c.OriginalContentChanged)
	orInto(&v.MaskedContentVaried, *c.MaskedContentChanged)
	orInto(&v.UpstreamStatusVaried, *c.UpstreamStatusChanged)
	orInto(&v.DownstreamStatusVaried, *c.DownstreamStatusChanged)
}

func orInto(dst **bool, value bool) {
	if *dst == nil {
		*dst = ptr(value)
	} else if value {
		**dst = true
	}
}

func ptr[T any](v T) *T { return &v }

func validRequestID(id string) bool {
	if len(id) > 53 || !requestPattern.MatchString(id) {
		return false
	}
	_, err := strconv.ParseUint(id[33:], 10, 64)
	return err == nil
}
