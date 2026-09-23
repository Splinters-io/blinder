package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Splinters-io/blinder/internal/manifest"
)

func TestManifestCountsAreRequestLocalAndFlushIsIdempotent(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "AcmeCorp AcmeCorp")
	}))
	defer target.Close()
	cfg := newTestConfig(t, target.URL)
	cfg.OutputDir = t.TempDir()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		}()
	}
	wg.Wait()
	entries := srv.Manifest().Requests()
	if len(entries) != 20 {
		t.Fatalf("missing requests: %d", len(entries))
	}
	for _, entry := range entries {
		if entry.ScrubCount != 2 || entry.LeakCount != -1 || entry.StatusCode != 200 {
			t.Fatalf("incorrect request outcome: %+v", entry)
		}
	}
	for i := 0; i < 2; i++ {
		if err := srv.FlushManifest(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(cfg.OutputDir, "blinder-scrub-report.json"))
		if err != nil {
			t.Fatal(err)
		}
		var report manifest.ScrubReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if report.TotalLeaks != 40 {
			t.Fatalf("flush %d: findings were lost or duplicated: %d", i, report.TotalLeaks)
		}
	}
}

func TestManifestRecordsHTTPFailure(t *testing.T) {
	cfg := newTestConfig(t, "http://127.0.0.1:1")
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/too-large", nil)
	req.ContentLength = maxRequestBody + 1
	srv.ServeHTTP(httptest.NewRecorder(), req)
	entries := srv.Manifest().Requests()
	if len(entries) != 1 || entries[0].StatusCode != 413 || entries[0].ScrubCount != 0 || entries[0].LeakCount != -1 {
		t.Fatalf("failure outcome missing or invented: %+v", entries)
	}
}
