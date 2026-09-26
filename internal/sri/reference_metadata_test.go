package sri

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func referencePipeline(original, rewritten []byte) (*Pipeline, *int) {
	fetches := 0
	return NewPipeline(PipelineConfig{
		Transport: evidenceTransport(func(r *http.Request) (*http.Response, error) {
			fetches++
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/javascript"}}, Body: io.NopCloser(bytes.NewReader(original))}, nil
		}),
		ScrubFn: func([]byte, string, string) []byte { return append([]byte(nil), rewritten...) },
		Cache:   NewCache(10),
	}), &fetches
}

func processReference(p *Pipeline, attr string) *ProcessResult {
	page, _ := url.Parse("https://example.test/page")
	return p.Process("https://example.test/code.js", attr, "application/javascript", "", page, httptest.NewRequest(http.MethodGet, page.String(), nil))
}

func TestPipelineReferenceAlgorithmIndependentOfCacheOrder(t *testing.T) {
	original, rewritten := []byte(`window.brand="AcmeCorp"`), []byte(`window.brand="masked"`)
	for _, order := range [][]string{{"sha256", "sha384", "sha512"}, {"sha512", "sha384", "sha256"}} {
		t.Run(strings.Join(order, "-"), func(t *testing.T) {
			p, fetches := referencePipeline(original, rewritten)
			for _, algorithm := range order {
				before, after := ComputeIntegrity(original, algorithm), ComputeIntegrity(rewritten, algorithm)
				result := processReference(p, before)
				if result == nil || !result.UpstreamValid || result.ReplacementHash != after {
					t.Fatalf("%s reference reused another reference's algorithm: result=%+v; want=%s", algorithm, result, after)
				}
				want := []IntegrityChange{{Original: before, Replacement: after}}
				if !reflect.DeepEqual(result.IntegrityChanges, want) {
					t.Fatalf("policy bindings=%+v, want=%+v", result.IntegrityChanges, want)
				}
			}
			if *fetches != 1 {
				t.Fatalf("reference changes fetched the same representation %d times", *fetches)
			}
		})
	}
}

func TestPipelineReferenceRetainsAllMetadataAndOptions(t *testing.T) {
	original, rewritten := []byte("original resource"), []byte("masked resource")
	p, _ := referencePipeline(original, rewritten)
	a := ComputeIntegrity(original, "sha256")
	b := ComputeIntegrity(original, "sha384")
	c := ComputeIntegrity(original, "sha512")
	wrong := ComputeIntegrity([]byte("other resource"), "sha256")
	attr := a + "?future=kept " + wrong + " " + b + " " + c + " md5-unknown"
	result := processReference(p, attr)
	want := ComputeIntegrity(rewritten, "sha256") + "?future=kept " + wrong + " " + ComputeIntegrity(rewritten, "sha384") + " " + ComputeIntegrity(rewritten, "sha512") + " md5-unknown"
	if result == nil || !result.UpstreamValid || result.ReplacementHash != want {
		t.Fatalf("metadata collapsed or options lost: %+v; want %s", result, want)
	}
	if len(result.IntegrityChanges) != 4 || result.IntegrityChanges[1] != (IntegrityChange{Original: wrong, Replacement: wrong}) {
		t.Fatalf("invalid weaker entry lost its separate policy membership: %+v", result.IntegrityChanges)
	}
	if ok, _ := Verify(rewritten, ParseIntegrity(result.ReplacementHash)); !ok {
		t.Fatal("rewritten metadata does not validate rewritten bytes")
	}
}

func TestPipelineReferenceInvalidTransformedDigestRemainsDistinct(t *testing.T) {
	original, rewritten := []byte("original resource"), []byte("masked resource")
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		t.Run(algorithm, func(t *testing.T) {
			p, _ := referencePipeline(original, rewritten)
			before, after := ComputeIntegrity(original, algorithm), ComputeIntegrity(rewritten, algorithm)
			// Same-strength entries: the original first hash allows the
			// resource, while the second is invalid until a careless rewrite.
			result := processReference(p, before+" "+after)
			if result == nil || !result.UpstreamValid || result.ReplacementHash != after+" "+before {
				t.Fatalf("digest identities were not swapped: %+v", result)
			}
			if ok, _ := Verify(rewritten, ParseIntegrity(strings.Fields(result.ReplacementHash)[1])); ok {
				t.Fatal("formerly invalid entry became valid for rewritten bytes")
			}
			if len(result.IntegrityChanges) != 2 || result.IntegrityChanges[1] != (IntegrityChange{Original: after, Replacement: before}) {
				t.Fatalf("missing invalid-entry policy binding: %+v", result.IntegrityChanges)
			}
		})
	}
}

func TestPipelineReferenceWeakerCollisionCannotAcquireGrant(t *testing.T) {
	original, rewritten := []byte("original resource"), []byte("masked resource")
	p, _ := referencePipeline(original, rewritten)
	weakBefore, weakAfter := ComputeIntegrity(original, "sha256"), ComputeIntegrity(rewritten, "sha256")
	strongBefore, strongAfter := ComputeIntegrity(original, "sha512"), ComputeIntegrity(rewritten, "sha512")
	result := processReference(p, weakAfter+" "+strongBefore)
	if result == nil || !result.UpstreamValid || result.ReplacementHash != weakBefore+" "+strongAfter {
		t.Fatalf("weaker invalid constraint became valid or disappeared: %+v", result)
	}
}

func TestPipelineReferenceBase64Representations(t *testing.T) {
	original, rewritten := []byte("original resource"), []byte("masked resource")
	for name, encoding := range map[string]*base64.Encoding{"standard": base64.StdEncoding, "unpadded": base64.RawStdEncoding, "url": base64.URLEncoding, "url-unpadded": base64.RawURLEncoding} {
		t.Run(name, func(t *testing.T) {
			p, _ := referencePipeline(original, rewritten)
			before := "sha256-" + encoding.EncodeToString(computeDigest(original, "sha256"))
			result := processReference(p, before+"?future=kept")
			want := ComputeIntegrity(rewritten, "sha256")
			if result == nil || !result.UpstreamValid || result.ReplacementHash != want+"?future=kept" || result.IntegrityChanges[0].Original != before {
				t.Fatalf("base64 spelling was lost or rejected: %+v", result)
			}
		})
	}
}

func TestParseIntegrityDoesNotRepairPaddingOrUnicodeWhitespace(t *testing.T) {
	valid := ComputeIntegrity([]byte("original resource"), "sha256")
	malformed := ParseIntegrity(valid + "=")
	if len(malformed) != 1 || len(malformed[0].Digest) != 0 {
		t.Fatalf("malformed supported assertion was dropped or repaired: %+v", malformed)
	}
	if got := ParseIntegrity(valid + "\u00a0" + valid); len(got) != 0 {
		t.Fatalf("Unicode whitespace separated integrity metadata: %+v", got)
	}
}

func TestPipelineReferenceAlgorithmSyntaxMatchesChromium(t *testing.T) {
	original, rewritten := []byte("/* original */"), []byte("/* rewritten */")
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		t.Run(algorithm, func(t *testing.T) {
			p, fetches := referencePipeline(original, rewritten)
			canonical := ComputeIntegrity(original, algorithm)
			upper := strings.ToUpper(algorithm) + strings.TrimPrefix(canonical, algorithm)
			if result := processReference(p, upper); result != nil || *fetches != 0 {
				t.Fatalf("unknown uppercase assertion invented verification/fetch: %+v, fetches=%d", result, *fetches)
			}
			legacy := strings.Replace(canonical, "sha", "sha-", 1)
			result := processReference(p, legacy+" "+upper)
			want := ComputeIntegrity(rewritten, algorithm) + " " + upper
			if result == nil || !result.UpstreamValid || result.ReplacementHash != want || len(result.IntegrityChanges) != 1 {
				t.Fatalf("legacy alias/unknown uppercase metadata was mishandled: %+v; want=%s", result, want)
			}
		})
	}
}

func TestParseIntegrityMalformedStrongerAssertionIsNotDiscarded(t *testing.T) {
	body := []byte("/* original */")
	weak := ComputeIntegrity(body, "sha256")
	broken := ComputeIntegrity(body, "sha512") + "="
	entries := ParseIntegrity(weak + " " + broken)
	if len(entries) != 2 || StrongestAlgorithm(entries) != "sha512" {
		t.Fatalf("broken supported stronger assertion was ignored: %+v", entries)
	}
	if ok, _ := Verify(body, entries); ok {
		t.Fatal("broken stronger assertion fell back to valid weaker digest")
	}
	p, _ := referencePipeline(body, []byte("/* rewritten */"))
	if result := processReference(p, weak+" "+broken); result == nil || !result.VerificationFailed {
		t.Fatalf("pipeline fabricated success from a weaker assertion: %+v", result)
	}
}

func TestPipelineReferenceConvergingSourcesKeepSeparatePermissions(t *testing.T) {
	for _, mediaType := range []string{"application/javascript", "text/css; charset=utf-8"} {
		t.Run(mediaType, func(t *testing.T) {
			for _, order := range [][]string{{"one", "two"}, {"two", "one"}} {
				cache := NewCache(10)
				originals := map[string][]byte{"one": []byte("/* original one */"), "two": []byte("/* original two */")}
				common := []byte("/* same transformed source */")
				p := NewPipeline(PipelineConfig{
					Transport: evidenceTransport(func(r *http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {mediaType}}, Body: io.NopCloser(bytes.NewReader(originals[strings.TrimPrefix(r.URL.Path, "/")]))}, nil
					}),
					ScrubFn: func([]byte, string, string) []byte { return common },
					Cache:   cache,
				})
				page, _ := url.Parse("https://example.test/page")
				req := httptest.NewRequest(http.MethodGet, page.String(), nil)
				results := make(map[string]*ProcessResult)
				published := make(map[string][]byte)
				for _, name := range order {
					original := originals[name]
					result := p.Process("https://example.test/"+name, ComputeIntegrity(original, "sha384"), mediaType, "", page, req)
					results[name] = result
					if result == nil || !result.UpstreamValid {
						t.Fatalf("reference failed: %+v", result)
					}
					entry, _ := cache.Get(CacheKey("https://example.test/"+name, req))
					published[name] = append([]byte(nil), entry.ScrubbedBody...)
					digestKey := CacheKey("https://example.test/"+name, req) + "\x01" + result.BodyVersion
					if !cache.HasDigest(digestKey) || !cache.CheckBodyIntegrity(digestKey, original) {
						t.Fatal("selected representation version lacks its original-body constraint")
					}
					if !bytes.Equal(bytes.TrimSpace(entry.ScrubbedBody), common) {
						t.Fatalf("source semantics changed: %q", entry.ScrubbedBody)
					}
					if ok, _ := Verify(entry.ScrubbedBody, ParseIntegrity(result.ReplacementHash)); !ok {
						t.Fatal("integrity did not bind the published collision-safe bytes")
					}
					if result.OriginalSHA256 != base64.StdEncoding.EncodeToString(computeDigest(original, "sha256")) || result.RewrittenSHA256 != base64.StdEncoding.EncodeToString(computeDigest(entry.ScrubbedBody, "sha256")) {
						t.Fatal("document ledger identities do not describe the published representation")
					}
				}
				if results["one"].ReplacementHash == results["two"].ReplacementHash {
					t.Fatal("distinct originals acquired the same external CSP permission")
				}
				cache.Clear()
				for name, result := range results {
					if restored := ApplyBodyVersion(originals[name], common, result.BodyVersion); !bytes.Equal(restored, published[name]) {
						t.Fatalf("version could not reproduce bytes after eviction: %q != %q", restored, published[name])
					}
				}
				if !bytes.Equal(common, []byte("/* same transformed source */")) {
					t.Fatal("collision resolution mutated the scrubber's shared byte slice")
				}
			}
		})
	}
}

func TestApplyBodyVersionRejectsMalformedOrUnrelatedVersions(t *testing.T) {
	original, rewritten := []byte("original resource"), []byte("masked resource")
	hash := sha256.Sum256(original)
	base := "bl" + hex.EncodeToString(hash[:8])
	for _, version := range []string{base + ".c0", base + ".c-1", base + ".c65537", base + ".c999999999999999999999999999", base + ".c1.c1", "bl0000000000000000.c1"} {
		if got := ApplyBodyVersion(original, rewritten, version); !bytes.Equal(got, rewritten) {
			t.Errorf("invalid or unrelated version changed representation: %s", version)
		}
	}
}

func TestCacheConcurrentConvergingSourceReservations(t *testing.T) {
	cache := NewCache(16)
	const count = 12
	entries := make([]*CacheEntry, count)
	var wg sync.WaitGroup
	for i := range entries {
		name := strings.Repeat("x", i+1)
		entries[i] = &CacheEntry{ScrubbedBody: []byte("/* same */"), OriginalDigests: computeAllDigests([]byte(name)), ContentType: "application/javascript"}
		wg.Add(1)
		go func(entry *CacheEntry) {
			defer wg.Done()
			cache.PutResource(name, entry)
		}(entries[i])
	}
	wg.Wait()
	seen := make(map[string]bool)
	for _, entry := range entries {
		body := string(entry.ScrubbedBody)
		if seen[body] {
			t.Fatal("concurrent reservations published the same source for distinct originals")
		}
		seen[body] = true
	}
	if cache.Len() != count {
		t.Fatalf("cache lost a reservation: %d", cache.Len())
	}
}

func TestPipelineDocumentReservationsSurviveCacheEviction(t *testing.T) {
	cache := NewCache(1)
	common := []byte("/* transformed source */")
	p := NewPipeline(PipelineConfig{
		Transport: evidenceTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/javascript"}}, Body: io.NopCloser(strings.NewReader("/* original " + r.URL.Path + " */"))}, nil
		}),
		ScrubFn: func([]byte, string, string) []byte { return common },
		Cache:   cache,
	})
	page, _ := url.Parse("https://example.test/page")
	req := httptest.NewRequest(http.MethodGet, page.String(), nil)
	document := make(map[string]string)
	for _, name := range []string{"first", "middle", "last"} {
		body := []byte("/* original /" + name + " */")
		priorSize := len(document)
		result := p.Process("https://example.test/"+name, ComputeIntegrity(body, "sha384"), "application/javascript", "", page, req, document)
		if result == nil || !result.UpstreamValid {
			t.Fatalf("reference failed: %+v", result)
		}
		if len(document) != priorSize {
			t.Fatal("cache mutated caller-owned document reservation map")
		}
		if _, collision := document[result.RewrittenSHA256]; collision {
			t.Fatalf("%s acquired an earlier document hash grant after that entry was evicted", name)
		}
		document[result.RewrittenSHA256] = result.OriginalSHA256
	}
	if cache.Len() != 1 || len(document) != 3 {
		t.Fatal("cache capacity or document reservation lifetime changed")
	}
}

func TestPipelineCacheHitReselectsDocumentCollisionWithoutStackingSuffix(t *testing.T) {
	original, common := []byte("/* original */"), []byte("/* rewritten */")
	p, fetches := referencePipeline(original, common)
	initial := processReference(p, ComputeIntegrity(original, "sha384"))
	page, _ := url.Parse("https://example.test/page")
	req := httptest.NewRequest(http.MethodGet, page.String(), nil)
	key := CacheKey("https://example.test/code.js", req)
	published, _ := p.cache.Get(key)
	foreign := base64.StdEncoding.EncodeToString(computeDigest([]byte("other original"), "sha256"))
	document := map[string]string{initial.RewrittenSHA256: foreign}
	first := p.Process("https://example.test/code.js", ComputeIntegrity(original, "sha384"), "application/javascript", "", page, req, document)
	if first == nil || !strings.HasSuffix(first.BodyVersion, ".c1") {
		t.Fatalf("cache hit skipped the document reservation: %+v", first)
	}
	if !bytes.Equal(published.ScrubbedBody, common) || published.BodyVersion != initial.BodyVersion {
		t.Fatal("cache hit mutated a previously published entry")
	}
	firstEntry, _ := p.cache.Get(key)
	firstBytes := append([]byte(nil), firstEntry.ScrubbedBody...)
	document[first.RewrittenSHA256] = foreign
	second := p.Process("https://example.test/code.js", ComputeIntegrity(original, "sha384"), "application/javascript", "", page, req, document)
	if second == nil || !strings.HasSuffix(second.BodyVersion, ".c2") || strings.Count(second.BodyVersion, ".c") != 1 {
		t.Fatalf("already-suffixed entry stacked variants: %+v", second)
	}
	secondEntry, _ := p.cache.Get(key)
	if !bytes.Equal(ApplyBodyVersion(original, common, second.BodyVersion), secondEntry.ScrubbedBody) {
		t.Fatal("reselected variant cannot be reproduced on authenticated refetch")
	}
	if !bytes.Equal(firstEntry.ScrubbedBody, firstBytes) || firstEntry.BodyVersion != first.BodyVersion {
		t.Fatal("reselection mutated the prior suffixed entry")
	}
	for _, version := range []string{initial.BodyVersion, first.BodyVersion, second.BodyVersion} {
		digestKey := key + "\x01" + version
		if !p.cache.HasDigest(digestKey) || !p.cache.CheckBodyIntegrity(digestKey, original) {
			t.Errorf("reselection lost original-body constraint for %s", version)
		}
	}
	if *fetches != 1 {
		t.Fatalf("cache reselection fetched the upstream %d times", *fetches)
	}
}

func TestPipelineDocumentReservationsProtectEveryDigestAlgorithm(t *testing.T) {
	original, common := []byte("/* original */"), []byte("/* rewritten */")
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		t.Run(algorithm, func(t *testing.T) {
			p, _ := referencePipeline(original, common)
			page, _ := url.Parse("https://example.test/page")
			req := httptest.NewRequest(http.MethodGet, page.String(), nil)
			// Reserve a denied source's original integrity identity even
			// though that resource was never fetched by the proxy.
			identity := base64.StdEncoding.EncodeToString(computeDigest(common, algorithm))
			document := map[string]string{algorithm + "-" + identity: identity}
			result := p.Process("https://example.test/code.js", ComputeIntegrity(original, "sha384"), "application/javascript", "", page, req, document)
			if result == nil || !result.UpstreamValid || !strings.Contains(result.BodyVersion, ".c") {
				t.Fatalf("%s-only original identity was not protected: %+v", algorithm, result)
			}
			entry, _ := p.cache.Get(CacheKey("https://example.test/code.js", req))
			if ComputeIntegrity(entry.ScrubbedBody, algorithm) == algorithm+"-"+identity {
				t.Fatal("rewritten resource acquired another source's original permission")
			}
		})
	}
}

func TestPipelineDocumentPrefillKeepsWeakerMetadataUnchanged(t *testing.T) {
	original, common := []byte("/* original */"), []byte("/* rewritten */")
	p, _ := referencePipeline(original, common)
	page, _ := url.Parse("https://example.test/page")
	req := httptest.NewRequest(http.MethodGet, page.String(), nil)
	weak := ComputeIntegrity(common, "sha256")
	strong := ComputeIntegrity(original, "sha512")
	document := map[string]string{
		weak:   strings.TrimPrefix(weak, "sha256-"),
		strong: strings.TrimPrefix(strong, "sha512-"),
	}
	result := p.Process("https://example.test/code.js", weak+" "+strong, "application/javascript", "", page, req, document)
	if result == nil || !result.UpstreamValid || !strings.Contains(result.BodyVersion, ".c") {
		t.Fatalf("original invalid metadata identity was not protected: %+v", result)
	}
	if len(result.IntegrityChanges) != 2 || result.IntegrityChanges[0] != (IntegrityChange{Original: weak, Replacement: weak}) {
		t.Fatalf("preseeded weak metadata unexpectedly needed a swap: %+v", result.IntegrityChanges)
	}
	entry, _ := p.cache.Get(CacheKey("https://example.test/code.js", req))
	if ok, _ := Verify(entry.ScrubbedBody, ParseIntegrity(weak)); ok {
		t.Fatal("previously invalid weaker integrity became valid")
	}
}
