package proxy

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Splinters-io/blinder/internal/har"
	"github.com/Splinters-io/blinder/internal/manifest"
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/ws"
)

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	gate := s.gate.ForRequest()
	observed := newResponseObserver(w, r.Method)
	recorded := false
	leakCount := 0
	record := func(status int) {
		if recorded {
			return
		}
		recorded = true
		if observed.metrics.Source == "proxy" {
			observed.metrics.RewrittenBodyBytes = observed.writtenBytes
		}
		s.manifest.RecordRequest(r.URL.Path, status, gate.ReplacementCount(), leakCount, observed.metrics)
	}
	defer func() { record(observed.status) }()
	opts := ws.HandleOptions{
		Gate:             gate,
		HandshakeTimeout: time.Duration(s.cfg.UpstreamTimeout) * time.Second,
		RefusedResponse: func(w http.ResponseWriter, upstreamReq *http.Request, resp *http.Response, elapsed time.Duration) error {
			readStart := time.Now()
			body, measured, err := readMeasuredResponse(resp, r.Method)
			elapsed += time.Since(readStart)
			observed.metrics.Upstream = append(observed.metrics.Upstream, measured)
			if err != nil {
				if s.harWriter != nil {
					s.harWriter.RecordFetchFailure(upstreamReq, resp.StatusCode, resp.Header, body, err.Error(), elapsed, har.FetchFailureDetails{EncodedBytes: &measured.EncodedBytes, HTTPVersion: resp.Proto, StatusLine: resp.Status})
				}
				http.Error(w, "upstream error", http.StatusBadGateway)
				return fmt.Errorf("read websocket refusal: %w", err)
			}
			if s.harWriter != nil {
				s.harWriter.Record(upstreamReq, nil, resp, body, elapsed, har.ResponseBodyInfo{EncodedBytes: measured.EncodedBytes})
			}
			outHeaders := rewriter.RewriteResponseHeaders(resp.Header, gate, s.cfg.AliasDomain, upstreamReq.URL.Host, rewriter.ResponseHeaderOpts{OriginMapper: s.origins.Load(), RequestOrigin: r.Header.Get("Origin")})
			for name, values := range outHeaders {
				w.Header()[name] = values
			}
			if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
				original, rewritten := int64(0), int64(0)
				if resp.StatusCode == http.StatusNotModified {
					original, rewritten = -1, -1
				}
				observed.representation("upstream", original, rewritten)
				w.Header()["Content-Length"] = nil
				w.WriteHeader(resp.StatusCode)
				return nil
			}
			// This is the response to the existing upgrade request, not another
			// transaction. Reuse HTTP transformations without scheduling cache,
			// SRI prefetch or CAPTCHA retry work.
			result := rewriter.RewriteBody(body, resp.Header.Get("Content-Type"), r.URL.Path, gate, s.cfg.Paranoid, rewriter.RewriteOpts{StatusCode: resp.StatusCode, Origins: s.origins.Load(), UpstreamBase: upstreamReq.URL})
			leakCount = gate.ResidualLeakCount(string(result.Body))
			observed.representation("upstream", int64(len(body)), int64(len(result.Body)))
			s.stats.Bytes.Add(int64(len(body)))
			s.stats.Scrubbed.Add(1)
			if result.ContentType != "" {
				w.Header().Set("Content-Type", result.ContentType)
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(result.Body)))
			w.WriteHeader(resp.StatusCode)
			_, writeErr := w.Write(result.Body)
			return writeErr
		},
		RewriteUpgradeHeaders: func(upstreamReq *http.Request, resp *http.Response) http.Header {
			headers := resp.Header.Clone()
			// Validation and reconstruction in ws.Handle own these protocol
			// values. They must never pass through arbitrary text replacement.
			for _, name := range []string{"Sec-WebSocket-Accept", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
				headers.Del(name)
			}
			out := rewriter.RewriteResponseHeaders(headers, gate, s.cfg.AliasDomain, upstreamReq.URL.Host, rewriter.ResponseHeaderOpts{OriginMapper: s.origins.Load(), RequestOrigin: r.Header.Get("Origin")})
			out.Set("X-Blinder-View", "transformed")
			out.Set("X-Blinder-Original-Body-Bytes", "0")
			out.Set("X-Blinder-Rewritten-Body-Bytes", "0")
			out.Set("X-Blinder-Body-Size-Match", "exact")
			return out
		},
		ObserveHandshake: func(event ws.HandshakeEvent) {
			if !event.UpstreamAttempted {
				return // Local validation failures are not upstream transactions.
			}
			measured := manifest.BodyRead{}
			if event.Response != nil {
				measured.StatusCode = event.Response.StatusCode
				measured.Complete = true // A 101 has no HTTP representation body.
			}
			if event.Error != nil {
				measured.Error = "transport"
				if event.Response != nil {
					measured.Error = "handshake"
				}
				if s.harWriter != nil {
					var headers http.Header
					details := har.FetchFailureDetails{EncodedBytes: &measured.EncodedBytes}
					if event.Response != nil {
						headers = event.Response.Header
						details.HTTPVersion, details.StatusLine = event.Response.Proto, event.Response.Status
					}
					s.harWriter.RecordFetchFailure(event.Request, measured.StatusCode, headers, nil, event.Error.Error(), event.Elapsed, details)
				}
			} else {
				observed.representation("upstream", 0, 0)
				if s.harWriter != nil {
					s.harWriter.Record(event.Request, nil, event.Response, nil, event.Elapsed, har.ResponseBodyInfo{EncodedBytes: 0})
				}
			}
			observed.metrics.Upstream = append(observed.metrics.Upstream, measured)
			if event.Error == nil {
				// Persist the handshake now, while the frame relay remains active.
				// Frame traffic is not an HTTP body and is not counted here.
				record(http.StatusSwitchingProtocols)
			}
		},
	}
	if err := s.wsProxy.Handle(observed, r, opts); err != nil {
		log.Printf("[error] websocket: %v", err)
		s.stats.Errors.Add(1)
	}
}
