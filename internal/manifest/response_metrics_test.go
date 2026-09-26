package manifest

import "testing"

func TestResponseMeasurementsAreImmutableSnapshots(t *testing.T) {
	s := NewSession("alias.local", "https://target.example")
	delta := int64(3)
	m := ResponseMetrics{Source: "upstream", Upstream: []BodyRead{{StatusCode: 422, EncodedBytes: 10, DecodedBytes: 20, Complete: true}}, OriginalBodyBytes: 20, RewrittenBodyBytes: 23, DownstreamBytes: 23, RewriteDeltaBytes: &delta}
	s.RecordRequest("/validate", 422, 1, 0, m)
	m.Upstream[0].EncodedBytes = 999
	delta = 999
	first := s.Requests()[0].Response
	if first.Upstream[0].EncodedBytes != 10 || *first.RewriteDeltaBytes != 3 {
		t.Fatal("record retained caller-owned measurement data")
	}
	first.Upstream[0].EncodedBytes = 888
	*first.RewriteDeltaBytes = 888
	second := s.Requests()[0].Response
	if second.Upstream[0].EncodedBytes != 10 || *second.RewriteDeltaBytes != 3 {
		t.Fatal("read exposes mutable measurement data")
	}
}
