package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/delta"
	"github.com/Splinters-io/blinder/internal/manifest"
)

const session = "0123456789abcdef0123456789abcdef"

func testManifest(t *testing.T) string {
	t.Helper()
	m := manifest.ManifestFile{SessionID: session, TargetURL: "https://secret-product.example/private", Requests: []manifest.RequestEntry{}}
	for _, n := range []string{"1", "2"} {
		m.Requests = append(m.Requests, manifest.RequestEntry{
			RequestID: session + ":" + n, Method: "GET", ContextTag: strings.Repeat("a", 64), RequestTag: strings.Repeat("b", 64), Path: "/private-token", StatusCode: 200,
			Response: &manifest.ResponseMetrics{
				Source: "upstream", Upstream: []manifest.BodyRead{{StatusCode: 200, DecodedBytes: 50, Complete: true}}, BodyComplete: true,
				OriginalBodyBytes: 50, RewrittenBodyBytes: 50, DownstreamBytes: 50, OriginalBodyTag: strings.Repeat(n, 64), RewrittenBodyTag: strings.Repeat("c", 64),
			},
		})
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private-manifest.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func args(path string) []string {
	return []string{"-manifest", path, "-baseline", session + ":1", "-test", session + ":2"}
}

func TestCLIReportsEvidenceReadOnly(t *testing.T) {
	path := testManifest(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := run(args(path), &out, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	var report delta.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Comparisons[0].ContentSignal != "lost_change" {
		t.Fatalf("missing lost-change evidence: %s", out.String())
	}
	for _, secret := range []string{"secret-product", "private-token", path, strings.Repeat("a", 64), strings.Repeat("c", 64)} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("private data exported: %s", secret)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("manifest was modified")
	}
}

func TestCLIRejectsInvalidInputsWithoutLeakingThem(t *testing.T) {
	path := testManifest(t)
	bad := filepath.Join(t.TempDir(), "secret-product.json")
	if err := os.WriteFile(bad, []byte(`{"target_url":"https://secret-product.example"} trailing-secret`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing-flags", nil},
		{"unknown-flag", []string{"-secret-product"}},
		{"missing-file", args("/secret-product/not-found")},
		{"bad-json", args(bad)},
		{"directory", args(t.TempDir())},
		{"nonopaque-id", []string{"-manifest", path, "-baseline", "secret-product", "-test", session + ":2"}},
		{"empty-id", []string{"-manifest", path, "-baseline", session + ":1,", "-test", session + ":2"}},
		{"overlap", []string{"-manifest", path, "-baseline", session + ":1", "-test", session + ":1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			if code := run(tc.args, &out, &stderr); code != 2 {
				t.Fatalf("exit %d, want 2", code)
			}
			if out.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("unexpected streams: stdout %q stderr %q", out.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "secret-product") || strings.Contains(stderr.String(), path) {
				t.Fatal("error leaked private argument")
			}
		})
	}
}

func TestCLIHelp(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"-help"}, &out, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(out.String(), "No requests are replayed") {
		t.Fatal("help failed")
	}
}

func TestCLIRejectsOversizedManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxManifestBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := run(args(path), &out, &stderr); code != 2 || out.Len() != 0 {
		t.Fatal("oversized input accepted")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("private output failure") }

func TestCLIReportWriteFailure(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(args(testManifest(t)), failWriter{}, &stderr); code != 2 || strings.Contains(stderr.String(), "private output failure") {
		t.Fatal("output failure mishandled")
	}
}
