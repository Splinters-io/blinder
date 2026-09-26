package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/delta"
	"github.com/Splinters-io/blinder/internal/manifest"
)

// A real local transport pair verifies that measurement-only comparisons can
// find equal-length changes and size changes without returning original prose.
func TestDeltaAcceptancePairedHTTPResponses(t *testing.T) {
	const first = "<title>First</title><p>AcmeCorp serves the first synthetic record with ordinary descriptive prose.</p>"
	const other = "<title>Other</title><p>AcmeCorp serves the other synthetic record with ordinary descriptive prose.</p>"
	const longer = "<title>Other</title><p>AcmeCorp serves the other synthetic record with ordinary descriptive prose and another row.</p>"
	const diagnostic = "<pre>E_QUERY: expected=1; observed=0.</pre>"
	if len(first) != len(other) {
		t.Fatal("equal-length fixture changed")
	}
	bodies := map[string]string{"/baseline": first, "/equal": other, "/long": longer, "/error": diagnostic}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		io.WriteString(w, bodies[r.URL.Path])
	}))
	defer target.Close()
	s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp"}, nil)
	s.cfg.Paranoid = true
	defer s.transport.(*http.Transport).CloseIdleConnections()
	completed := make(chan struct{}, 1)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r)
		completed <- struct{}{}
	}))
	defer local.Close()
	var ids []string
	for _, path := range []string{"/baseline", "/baseline", "/equal", "/long", "/error"} {
		resp, err := local.Client().Get(local.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		<-completed
		if len(body) != len(bodies[path]) {
			t.Fatalf("fixture did not preserve body length for %s: %d != %d", path, len(body), len(bodies[path]))
		}
		if strings.Contains(string(body), "AcmeCorp") || (path != "/error" && strings.Contains(string(body), "synthetic record")) {
			t.Fatal("fixture prose leaked through masking")
		}
		if path == "/error" && (resp.StatusCode != 503 || string(body) != diagnostic) {
			t.Fatal("upstream error signal was changed")
		}
		ids = append(ids, resp.Header.Get("X-Blinder-Request-ID"))
	}
	m := manifest.ManifestFile{Version: "2.0.0", SessionID: s.manifest.SessionID(), TargetURL: target.URL, Requests: s.manifest.Requests()}
	r, err := delta.Compare(m, ids[:2], ids[2:])
	if err != nil {
		t.Fatal(err)
	}
	if r.BaselineVariation.ComparablePairs != 1 || r.BaselineVariation.OriginalContentVaried == nil || *r.BaselineVariation.OriginalContentVaried ||
		r.BaselineVariation.MaskedContentVaried == nil || *r.BaselineVariation.MaskedContentVaried || r.BaselineVariation.ChangedRequestPairs != 0 {
		t.Fatalf("stable baseline misclassified: %+v", r.BaselineVariation)
	}
	for _, c := range r.Comparisons {
		if !c.Comparable || c.ContentSignal != "change_visible" || c.DistortionBytes == nil || *c.DistortionBytes != 0 {
			t.Fatalf("paired changes not preserved: %+v", c)
		}
		if c.TestID == ids[2] && (*c.OriginalBodyDeltaBytes != 0 || *c.RewrittenBodyDeltaBytes != 0) {
			t.Fatal("equal-length change was treated as a length change")
		}
		if c.TestID == ids[4] && (!*c.UpstreamStatusChanged || !*c.DownstreamStatusChanged) {
			t.Fatal("upstream error status change missing")
		}
	}
	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{target.URL, "AcmeCorp", "/baseline", "synthetic record", m.Requests[0].ContextTag, m.Requests[0].Response.OriginalBodyTag} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("report contains private evidence")
		}
	}
	if dir := os.Getenv("BLINDER_DELTA_EVIDENCE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		selection := struct {
			Baselines []string `json:"baselines"`
			Tests     []string `json:"tests"`
		}{ids[:2], ids[2:]}
		for name, value := range map[string]any{"manifest.json": m, "report.json": r, "selections.json": selection} {
			data, err := json.MarshalIndent(value, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDeltaAcceptanceDetectsActualMaskingCollision(t *testing.T) {
	// A two-byte title has a finite filler vocabulary. Exercise an actual
	// information-loss case, rather than fabricating mismatched fingerprint data.
	current := ""
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		resp := audit267SRIResponse("text/html", current)
		resp.Header.Set("Cache-Control", "no-store")
		return resp, nil
	})
	s.cfg.Paranoid = true
	seen := map[string]string{}
	for ch := rune(0x100); ch < 0x800; ch++ {
		current = "<title>" + string(ch) + "</title>"
		got := audit267CacheRequest(s, "GET", "/", nil)
		id := got.Header().Get("X-Blinder-Request-ID")
		if prior, ok := seen[got.Body.String()]; ok {
			report, err := delta.Compare(manifest.ManifestFile{SessionID: s.manifest.SessionID(), Requests: s.manifest.Requests()}, []string{prior}, []string{id})
			if err != nil {
				t.Fatal(err)
			}
			c := report.Comparisons[0]
			if !c.Comparable || c.ContentSignal != "lost_change" || c.OriginalBodyDeltaBytes == nil || *c.OriginalBodyDeltaBytes != 0 ||
				c.RewrittenBodyDeltaBytes == nil || *c.RewrittenBodyDeltaBytes != 0 || c.RequestChanged == nil || *c.RequestChanged {
				t.Fatalf("actual equal-size lost change missed: %+v", c)
			}
			return
		}
		seen[got.Body.String()] = id
	}
	t.Fatal("synthetic short-title collision not found")
}
