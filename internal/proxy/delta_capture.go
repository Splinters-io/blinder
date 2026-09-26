package proxy

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/Splinters-io/blinder/internal/manifest"
	"github.com/Splinters-io/blinder/internal/scrub"
)

// Request evidence is captured before URL/body restoration and never adds raw
// credentials or request payloads to the delta report. The existing manifest is
// still an operator-private artifact (its other fields contain upstream data).
type requestEvidence struct {
	entry  manifest.RequestEntry
	header string
}

func newRequestEvidence(session *manifest.Session, gate *scrub.Gate, r *http.Request) requestEvidence {
	var encoded evidenceEncoding
	uri := r.RequestURI
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	encoded.fields("blinder/request-headers/v1", r.Method, r.Host, uri, r.URL.RequestURI(), strconv.FormatInt(r.ContentLength, 10))
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	encoded.fields(names...)
	for _, name := range names {
		encoded.fields(r.Header[name]...)
	}
	return requestEvidence{
		entry:  manifest.RequestEntry{RequestID: session.NewRequestID(), Method: r.Method, Timestamp: time.Now().Format(time.RFC3339Nano)},
		header: gate.ContentTag(encoded.Bytes()),
	}
}

func (e *requestEvidence) observeBody(gate *scrub.Gate, body []byte) {
	// Two fixed-length keyed tags avoid retaining or copying the full request body.
	e.entry.RequestTag = gate.ContentTag([]byte("blinder/request/v1\x00" + e.header + gate.ContentTag(body)))
}

func (e *requestEvidence) observeContext(gate *scrub.Gate, r *http.Request, upstream *url.URL) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	var encoded evidenceEncoding
	encoded.fields("blinder/request-context/v1", scheme, r.Host, upstream.Scheme, upstream.Host, r.Method)
	encoded.fields(r.Header.Values("Cookie")...)
	encoded.fields(r.Header.Values("Authorization")...)
	e.entry.ContextTag = gate.ContentTag(encoded.Bytes())
}

// Preserve arbitrary accepted header bytes and value boundaries. JSON string
// encoding would collapse different invalid UTF-8 bytes into the same rune.
type evidenceEncoding struct{ bytes.Buffer }

func (e *evidenceEncoding) fields(values ...string) {
	e.number(uint64(len(values)))
	for _, value := range values {
		e.number(uint64(len(value)))
		e.WriteString(value)
	}
}

func (e *evidenceEncoding) number(n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	e.Write(b[:])
}
