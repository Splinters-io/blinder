package proxy

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Splinters-io/blinder/internal/manifest"
)

// Measures HTTP representations and refused WebSocket upgrades. Successful
// upgrades use ResponseController through Unwrap; frame bytes are not HTTP bodies.
type responseObserver struct {
	http.ResponseWriter
	metrics           manifest.ResponseMetrics
	status            int
	head              bool
	writtenBytes      int64
	beforeFinalHeader func(http.Header)
}

func newResponseObserver(w http.ResponseWriter, method string) *responseObserver {
	return &responseObserver{ResponseWriter: w, head: method == http.MethodHead, metrics: manifest.ResponseMetrics{
		Source: "proxy", Upstream: []manifest.BodyRead{}, OriginalBodyBytes: -1, RewrittenBodyBytes: -1,
	}}
}

func (w *responseObserver) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseObserver) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.status = status
	if w.beforeFinalHeader != nil {
		w.beforeFinalHeader(w.Header())
	}
	w.Header().Set("X-Blinder-View", "transformed")
	// Always overwrite upstream-provided measurements. Unknown is explicit.
	w.Header().Set("X-Blinder-Original-Body-Bytes", strconv.FormatInt(w.metrics.OriginalBodyBytes, 10))
	w.Header().Set("X-Blinder-Rewritten-Body-Bytes", strconv.FormatInt(w.metrics.RewrittenBodyBytes, 10))
	match := "unknown"
	if w.metrics.OriginalBodyBytes >= 0 && w.metrics.RewrittenBodyBytes >= 0 {
		match = "different"
		if w.metrics.OriginalBodyBytes == w.metrics.RewrittenBodyBytes {
			match = "exact"
		}
	}
	w.Header().Set("X-Blinder-Body-Size-Match", match)
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseObserver) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(body)
	w.writtenBytes += int64(n)
	if !w.head && w.status != http.StatusNoContent && w.status != http.StatusNotModified {
		w.metrics.DownstreamBytes += int64(n)
	}
	return n, err
}

func (w *responseObserver) representation(source string, original, rewritten int64) {
	w.metrics.Source = source
	w.metrics.OriginalBodyBytes = original
	w.metrics.RewrittenBodyBytes = rewritten
	w.metrics.RewriteDeltaBytes = nil
	if original >= 0 && rewritten >= 0 {
		delta := rewritten - original
		w.metrics.RewriteDeltaBytes = &delta
	}
}

func observeRepresentation(w http.ResponseWriter, source string, original, rewritten int64) {
	if observed, ok := w.(*responseObserver); ok {
		observed.representation(source, original, rewritten)
	}
}

type countingReader struct {
	io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += int64(n)
	return n, err
}

func readMeasuredResponse(resp *http.Response, method string) (body []byte, measured manifest.BodyRead, err error) {
	measured = manifest.BodyRead{StatusCode: resp.StatusCode, DecodedBytes: -1}
	if method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		measured.DecodedBytes, measured.Complete = 0, true
		return nil, measured, nil
	}
	raw := &countingReader{Reader: resp.Body}
	defer func() {
		measured.EncodedBytes = raw.n
		if resp.Uncompressed {
			measured.EncodedBytes = -1
		}
	}()
	var reader io.Reader = raw
	encoding := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ",")))
	switch encoding {
	case "", "identity":
	case "gzip":
		gz, decodeErr := gzip.NewReader(raw)
		if decodeErr != nil {
			measured.Error = "decode"
			return nil, measured, fmt.Errorf("gzip decode: %w", decodeErr)
		}
		defer gz.Close()
		reader = gz
	default:
		measured.Error = "unsupported_encoding"
		return nil, measured, fmt.Errorf("unsupported response encoding")
	}
	body, err = io.ReadAll(io.LimitReader(reader, maxResponseBody+1))
	measured.DecodedBytes = int64(len(body))
	if err != nil {
		measured.Error = "read"
		return body, measured, err
	}
	if len(body) > maxResponseBody {
		measured.Error = "body_limit"
		return body[:maxResponseBody], measured, fmt.Errorf("response body too large")
	}
	measured.Complete = true
	return body, measured, nil
}
