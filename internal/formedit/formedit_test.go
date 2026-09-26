package formedit

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestRewritePreservesUnchangedSource(t *testing.T) {
	for _, input := range []string{
		"", "&", "&&", "=", "bare", "bare=&bare&",
		"&&a=1&a=2&%61=03&empty=&bare&=empty-key&space=a+b&plus=a%2bb&path=%2f%2F&x=a=b&&",
		"query=1%27+OR+1%3d1--&query=1%27%20OR%201%3D1--",
		"a=one;two&b;part=x;y&escaped=%3b&raw=é&bytes=%ff%00",
	} {
		t.Run(input, func(t *testing.T) {
			for _, replace := range []func(string) string{nil, func(s string) string { return s }} {
				got, err := Rewrite(input, replace, nil)
				if err != nil || got != input {
					t.Fatalf("got %q, error %v; want %q", got, err, input)
				}
			}
		})
	}
}

func TestRewriteOnlyChangedComponents(t *testing.T) {
	input := "&&%61lias=untouched%2f&keep=a%6cias&keep=%61lias&plus=a+b&literal=a%2bb&bare&&"
	var seen []string
	got, err := Rewrite(input, func(s string) string {
		seen = append(seen, s)
		if s == "alias" {
			return "restored /+é"
		}
		return s
	}, nil)
	want := "&&restored+%2F%2B%C3%A9=untouched%2f&keep=restored+%2F%2B%C3%A9&keep=restored+%2F%2B%C3%A9&plus=a+b&literal=a%2bb&bare&&"
	if err != nil || got != want {
		t.Fatalf("got %q, error %v; want %q", got, err, want)
	}
	if want := []string{"alias", "untouched/", "keep", "alias", "keep", "alias", "plus", "a b", "literal", "a+b", "bare", ""}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("decoded callbacks = %q; want %q", seen, want)
	}
}

func TestRewritePreservesDuplicateAndNewlyCollidingKeys(t *testing.T) {
	input := "a=one&b=two&a=three&%62=four&a&b=&"
	got, err := Rewrite(input, func(s string) string {
		if s == "a" {
			return "b"
		}
		return s
	}, nil)
	want := "b=one&b=two&b=three&%62=four&b&b=&"
	if err != nil || got != want {
		t.Fatalf("got %q, error %v; want %q", got, err, want)
	}
}

func TestRewriteOpaqueValueUsesRestoredKey(t *testing.T) {
	input := "opaque-alias=alias%2f%20keep&normal=alias&opaque=alias+keep&opaque-alias"
	var seen, checked []string
	got, err := Rewrite(input, func(s string) string {
		seen = append(seen, s)
		switch s {
		case "opaque-alias":
			return "opaque"
		case "alias":
			return "restored"
		}
		return s
	}, func(key string) bool {
		checked = append(checked, key)
		return key == "opaque"
	})
	want := "opaque=alias%2f%20keep&normal=restored&opaque=alias+keep&opaque"
	if err != nil || got != want {
		t.Fatalf("got %q, error %v; want %q", got, err, want)
	}
	if want := []string{"opaque-alias", "normal", "alias", "opaque", "opaque-alias"}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("replace callbacks = %q; want %q", seen, want)
	}
	if want := []string{"opaque", "normal", "opaque", "opaque"}; !reflect.DeepEqual(checked, want) {
		t.Fatalf("skip callbacks = %q; want %q", checked, want)
	}
}

func TestRewriteBareKeysAndEmptySegments(t *testing.T) {
	got, err := Rewrite("&&bare&empty=&=value&&", func(s string) string {
		if s == "" {
			return "new"
		}
		return s
	}, nil)
	want := "&&bare=new&empty=new&new=value&&"
	if err != nil || got != want {
		t.Fatalf("got %q, error %v; want %q", got, err, want)
	}
	got, err = Rewrite("bare&equals=&", func(s string) string {
		if s == "bare" {
			return "changed"
		}
		return s
	}, nil)
	if err != nil || got != "changed&equals=&" {
		t.Fatalf("key-only edit changed pair shape: %q, %v", got, err)
	}
	got, err = Rewrite("bare&&", func(s string) string {
		if s == "bare" {
			return ""
		}
		return s
	}, nil)
	if err != nil || got != "=&&" {
		t.Fatalf("empty restored key lost the parameter: %q, %v", got, err)
	}
}

func TestRewriteSemicolonsAreComponentData(t *testing.T) {
	input := "a=one;two&b;part=x;y&encoded=%3b"
	var seen []string
	got, err := Rewrite(input, func(s string) string {
		seen = append(seen, s)
		if s == "one;two" {
			return "changed;two"
		}
		return s
	}, nil)
	want := "a=changed%3Btwo&b;part=x;y&encoded=%3b"
	if err != nil || got != want {
		t.Fatalf("got %q, error %v; want %q", got, err, want)
	}
	if want := []string{"a", "one;two", "b;part", "x;y", "encoded", ";"}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("decoded components = %q; want %q", seen, want)
	}
}

func TestRewriteValidatesAllEscapesBeforeCallbacks(t *testing.T) {
	for _, input := range []string{
		"%", "a=%", "%0=value", "a=%0", "%zz=value", "a=%xz",
		"good=alias&bad=%g0", "good=alias&opaque=%", "a=1&&late%XX=2",
	} {
		t.Run(input, func(t *testing.T) {
			called := false
			got, err := Rewrite(input, func(s string) string {
				called = true
				return "new"
			}, func(string) bool {
				called = true
				return true
			})
			if !errors.Is(err, ErrInvalidEncoding) || got != "" || called {
				t.Fatalf("got %q, error %v, callbacks called %v", got, err, called)
			}
		})
	}
}

func FuzzRewriteIdentityAndChangedComponents(f *testing.F) {
	for _, seed := range []string{"", "&&a=1&a=2&bare&", "q=one+two&q=one%20two", "a=%2f%3b%00%ff&semi=x;y", "bad=%q"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got, err := Rewrite(input, func(s string) string { return s }, nil)
		_, validErr := url.QueryUnescape(input)
		if validErr != nil {
			if !errors.Is(err, ErrInvalidEncoding) || got != "" {
				t.Fatalf("malformed source returned %q, %v", got, err)
			}
			return
		}
		if err != nil || got != input {
			t.Fatalf("identity changed source: %q -> %q, %v", input, got, err)
		}
		got, err = Rewrite(input, func(s string) string { return "edited:" + s }, nil)
		if err != nil {
			t.Fatal(err)
		}
		before, after := strings.Split(input, "&"), strings.Split(got, "&")
		if len(before) != len(after) {
			t.Fatalf("pair count changed: %q -> %q", input, got)
		}
		for i, original := range before {
			if original == "" {
				if after[i] != "" {
					t.Fatalf("empty segment became %q", after[i])
				}
				continue
			}
			key, value, _ := strings.Cut(original, "=")
			key, _ = url.QueryUnescape(key)
			value, _ = url.QueryUnescape(value)
			newKey, newValue, hasEquals := strings.Cut(after[i], "=")
			newKey, keyErr := url.QueryUnescape(newKey)
			newValue, valueErr := url.QueryUnescape(newValue)
			if keyErr != nil || valueErr != nil || !hasEquals || newKey != "edited:"+key || newValue != "edited:"+value {
				t.Fatalf("component edit changed semantics: %q -> %q", original, after[i])
			}
		}
	})
}
