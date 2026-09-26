package captcha

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestProviderRelayRestoresMethodWithoutChangingCORSDecision(t *testing.T) {
	const alias = "host-9fdf9424.target.test"
	const original = "vendor.sync"
	for _, tc := range []struct {
		name        string
		allow, want []string
	}{
		{"exact-grant", []string{original}, []string{alias}},
		{"wrong-case-denied", []string{"VENDOR.sync"}, []string{"VENDOR.sync"}},
		{"missing-grant-denied", nil, nil},
		{"unrelated-grant-denied", []string{"OTHER"}, []string{"OTHER"}},
		{"literal-alias-does-not-gain-permission", []string{alias}, []string{original}},
		{"list-format-and-membership", []string{" GET,\t" + original + " , " + alias + ",OTHER ", "*"}, []string{" GET,\t" + alias + " , " + original + ",OTHER ", "*"}},
		{"wildcard-unchanged", []string{"*"}, []string{"*"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "OPTIONS" || r.Header.Get("Access-Control-Request-Method") != original {
					t.Fatalf("upstream method changed: %s %v", r.Method, r.Header)
				}
				headers := http.Header{"Access-Control-Allow-Origin": {"*"}}
				if tc.allow != nil {
					headers["Access-Control-Allow-Methods"] = tc.allow
				}
				return providerRelayResponse(204, headers, ""), nil
			}))
			h.cfg.RestoreMethod = func(v string) string {
				if v == alias {
					return original
				}
				return v
			}
			request := providerRelayRequest(t, routes, "OPTIONS", "https://provider.test/widget/api", "")
			request.Header.Set("Access-Control-Request-Method", alias)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request)
			if w.Code != 204 || calls != 1 || !reflect.DeepEqual(w.Header().Values("Access-Control-Allow-Methods"), tc.want) {
				t.Fatalf("CORS decision changed: %d %v want %v", w.Code, w.Header(), tc.want)
			}
			if request.Header.Get("Access-Control-Request-Method") != alias {
				t.Fatal("original browser request mutated")
			}
		})
	}
	for _, method := range []string{alias, "GET", "Other.Custom"} {
		t.Run("actual-"+method, func(t *testing.T) {
			h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
				want := method
				if method == alias {
					want = original
				}
				if r.Method != want {
					t.Fatalf("method got %q want %q", r.Method, want)
				}
				return providerRelayResponse(500, http.Header{"Content-Type": {"text/plain"}}, "upstream error"), nil
			}))
			h.cfg.RestoreMethod = func(v string) string {
				if v == alias {
					return original
				}
				return v
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, providerRelayRequest(t, routes, method, "https://provider.test/widget/api", ""))
			if w.Code != 500 || w.Body.String() != "upstream error" {
				t.Fatalf("upstream error changed: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestProviderRelayRejectsInvalidRestoredMethods(t *testing.T) {
	for _, restored := range []string{"", "two words", "GET\r\nX-Test: injected", "METHOD,OTHER"} {
		for _, preflight := range []bool{false, true} {
			t.Run(strings.ReplaceAll(restored, "\n", "_")+map[bool]string{false: "-method", true: "-preflight"}[preflight], func(t *testing.T) {
				calls := 0
				h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					return providerRelayResponse(200, nil, ""), nil
				}))
				h.cfg.RestoreMethod = func(v string) string {
					if v == "alias" {
						return restored
					}
					return v
				}
				method := "alias"
				if preflight {
					method = "OPTIONS"
				}
				request := providerRelayRequest(t, routes, method, "https://provider.test/widget/api", "")
				if preflight {
					request.Header.Set("Access-Control-Request-Method", "alias")
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, request)
				if w.Code != 400 || calls != 0 {
					t.Fatalf("invalid restored method reached transport: %d calls=%d", w.Code, calls)
				}
			})
		}
	}
}

func TestProviderRelayRejectsMultiplePreflightMethods(t *testing.T) {
	calls := 0
	h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return providerRelayResponse(200, nil, ""), nil
	}))
	request := providerRelayRequest(t, routes, "OPTIONS", "https://provider.test/widget/api", "")
	request.Header["Access-Control-Request-Method"] = []string{"GET", "POST"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != 400 || calls != 0 {
		t.Fatalf("ambiguous preflight sent upstream: %d calls=%d", w.Code, calls)
	}
}

func TestProviderRelayOriginTranslationKeepsLiteralAliasDenied(t *testing.T) {
	const local = "https://127.0.0.1:8099"
	const original = "https://target.test"
	for _, tc := range []struct {
		name        string
		allow, want []string
	}{
		{"original-grant", []string{original}, []string{local}},
		{"literal-local-is-not-original-grant", []string{local}, []string{original}},
		{"wildcard", []string{"*"}, []string{"*"}},
		{"null", []string{"null"}, []string{"null"}},
		{"duplicates-still-invalid", []string{original, local}, []string{local, original}},
		{"missing", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Origin") != original {
					t.Fatalf("upstream Origin=%q", r.Header.Get("Origin"))
				}
				headers := make(http.Header)
				if tc.allow != nil {
					headers["Access-Control-Allow-Origin"] = tc.allow
				}
				return providerRelayResponse(200, headers, "provider"), nil
			}))
			h.cfg.MapTargetOrigin = func(value string, upstream bool) string {
				if upstream && value == local {
					return original
				}
				if !upstream && value == original {
					return local
				}
				return value
			}
			request := providerRelayRequest(t, routes, "GET", "https://provider.test/widget/api", "")
			request.Header.Set("Origin", local)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request)
			if w.Code != 200 || !reflect.DeepEqual(w.Header().Values("Access-Control-Allow-Origin"), tc.want) {
				t.Fatalf("origin permission changed: %d %v want %v", w.Code, w.Header(), tc.want)
			}
		})
	}
}
