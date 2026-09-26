package jsonedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestRewritePreservesUnchangedBytes(t *testing.T) {
	inputs := []string{
		" \r\n{\t\"duplicate\":1, \"duplicate\":2, \"\\u0064uplicate\":3,\n\"n\": [9007199254740993123456789, -0, 1.2300, 1e+02, 2E-3], \"s\":\"\\u0061\\/\\ud83d\\ude00 <tag> café\"}\t ",
		`[null,true,false,{},[],"\\\"\n\t",{"k":"\u0061"}]`,
		`"\u0061"`,
		"  1.2300e+0002\r\n",
		`null`,
	}
	for _, input := range inputs {
		got, err := Rewrite([]byte(input), func(s string) string { return s }, nil)
		if err != nil || string(got) != input {
			t.Fatalf("identity rewrite: got %q, error %v; want %q", got, err, input)
		}
		got, err = Rewrite([]byte(input), nil, nil)
		if err != nil || string(got) != input {
			t.Fatalf("nil rewrite: got %q, error %v; want %q", got, err, input)
		}
	}
}

func TestRewriteChangesOnlySelectedStringSpans(t *testing.T) {
	input := []byte(" { \"\\u006bey\" : \"alias\", \"number\" : 9007199254740993123456789, \"keep\":\"\\u0061\\/\", \"array\":[\"a\\u006cias\",{\"dup\":1,\"dup\":2}] }\n")
	before := bytes.Clone(input)
	got, err := Rewrite(input, func(s string) string {
		switch s {
		case "key":
			return "restored-key"
		case "alias":
			return "restored\"\nvalue"
		default:
			return s
		}
	}, nil)
	want := " { \"restored-key\" : \"restored\\\"\\nvalue\", \"number\" : 9007199254740993123456789, \"keep\":\"\\u0061\\/\", \"array\":[\"restored\\\"\\nvalue\",{\"dup\":1,\"dup\":2}] }\n"
	if err != nil || string(got) != want {
		t.Fatalf("got %q, error %v; want %q", got, err, want)
	}
	if !bytes.Equal(input, before) {
		t.Fatal("rewrite modified input")
	}
	if !json.Valid(got) {
		t.Fatalf("rewrite produced invalid JSON: %q", got)
	}
}

func TestRewritePreservesExistingDuplicateKeysAfterReplacement(t *testing.T) {
	input := []byte(`{"a":1,"\u0061":2,"a":3,"nested":{"a":"a"}}`)
	got, err := Rewrite(input, func(s string) string {
		if s == "a" {
			return "renamed"
		}
		return s
	}, nil)
	want := `{"renamed":1,"renamed":2,"renamed":3,"nested":{"renamed":"renamed"}}`
	if err != nil || string(got) != want {
		t.Fatalf("got %s, error %v; want %s", got, err, want)
	}
}

func TestRewriteOpaqueSubtreeUsesFinalKey(t *testing.T) {
	input := []byte("{\"outer\":[{\"opaque-alias\" : { \"a\":\"secret\", \"b\":\"\\u0073ecret\", \"a\":2, \"array\":[\"secret\",1e+02] },\"normal\":\"visible\"}],\"opaque\":\"secret\"}")
	var replaced, checked []string
	got, err := Rewrite(input, func(s string) string {
		replaced = append(replaced, s)
		switch s {
		case "opaque-alias":
			return "opaque"
		case "visible":
			return "changed"
		case "a", "b":
			return "collision-if-visited"
		case "secret":
			t.Fatal("opaque string was passed to replace")
		}
		return s
	}, func(key string) bool {
		checked = append(checked, key)
		return key == "opaque"
	})
	want := strings.Replace(string(input), `"opaque-alias"`, `"opaque"`, 1)
	want = strings.Replace(want, `"visible"`, `"changed"`, 1)
	if err != nil || string(got) != want {
		t.Fatalf("got %q, error %v; want %q", got, err, want)
	}
	if want := []string{"outer", "opaque-alias", "normal", "visible", "opaque"}; !reflect.DeepEqual(replaced, want) {
		t.Fatalf("replace callbacks = %q; want %q", replaced, want)
	}
	if want := []string{"outer", "opaque", "normal", "opaque"}; !reflect.DeepEqual(checked, want) {
		t.Fatalf("skip callbacks = %q; want %q", checked, want)
	}
}

func TestRewriteRejectsNewCollisionsAtomically(t *testing.T) {
	for _, input := range []string{
		`{"a":"changed before error","b":2}`,
		`{"b":2,"a":"changed before error"}`,
		`{"unchanged":[{"a":1,"b":2}]}`,
		`{"a":1,"a":2,"b":3}`,
		`{"\u0061":1,"b":2}`,
	} {
		t.Run(input, func(t *testing.T) {
			data := []byte(input)
			got, err := Rewrite(data, func(s string) string {
				if s == "a" {
					return "b"
				}
				if s == "changed before error" {
					return "new value"
				}
				return s
			}, nil)
			if !errors.Is(err, ErrKeyCollision) || got != nil {
				t.Fatalf("got %q, error %v; want nil, ErrKeyCollision", got, err)
			}
			if string(data) != input {
				t.Fatal("failed rewrite modified input")
			}
		})
	}
}

func TestRewriteCollisionScopeIsEachObject(t *testing.T) {
	input := []byte(`{"left":{"a":1},"right":{"b":2},"array":[{"a":3},{"b":4}]}`)
	got, err := Rewrite(input, func(s string) string {
		if s == "a" || s == "b" {
			return "common"
		}
		return s
	}, nil)
	want := `{"left":{"common":1},"right":{"common":2},"array":[{"common":3},{"common":4}]}`
	if err != nil || string(got) != want {
		t.Fatalf("got %s, error %v; want %s", got, err, want)
	}
}

func TestRewriteValidatesWholeDocumentBeforeCallbacks(t *testing.T) {
	for _, input := range []string{
		"", " \n", `{"a":"x"`, `{"a":"x",}`, `{"a":"x"} null`,
		`{"a":"x"} trailing`, `{"a":"x","later":[1,]}`, `{"a":"\q"}`,
		`[01]`, `{"a":NaN}`, "{\"a\":\"bad\nstring\"}",
	} {
		t.Run(input, func(t *testing.T) {
			called := false
			got, err := Rewrite([]byte(input), func(s string) string {
				called = true
				return s
			}, func(string) bool {
				called = true
				return false
			})
			if !errors.Is(err, ErrInvalidJSON) || got != nil || called {
				t.Fatalf("got %q, error %v, callbacks called %v", got, err, called)
			}
		})
	}
}

func TestRewriteReplacementUsesActualDecodedKeyForCollisions(t *testing.T) {
	got, err := Rewrite([]byte(`{"a":1,"b":2}`), func(s string) string {
		if s == "a" {
			return "\xff"
		}
		if s == "b" {
			return "\ufffd"
		}
		return s
	}, nil)
	if !errors.Is(err, ErrKeyCollision) || got != nil {
		t.Fatalf("got %q, error %v; want nil, ErrKeyCollision", got, err)
	}
}

func FuzzRewriteIdentityPreservesBytes(f *testing.F) {
	for _, seed := range []string{
		`{"a":1,"a":2}`, `{"a":"\u0061","n":1.00e+02}`, `[[{"opaque":[true,null,"s"]}]]`,
		"\n\t{\"s\":\"<tag> café \\ud83d\\ude00\"}\r\n", `"\\\""`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := Rewrite(input, func(s string) string { return s }, nil)
		if !json.Valid(input) {
			if !errors.Is(err, ErrInvalidJSON) || got != nil {
				t.Fatalf("invalid input returned %q, %v", got, err)
			}
			return
		}
		if err != nil || !bytes.Equal(got, input) {
			t.Fatalf("identity rewrite changed valid input: %q -> %q, %v", input, got, err)
		}
		// An injective replacement changes every string token, exercising span
		// boundaries while preserving the complete token sequence otherwise.
		got, err = Rewrite(input, func(s string) string { return "edited:" + s }, nil)
		if err != nil || !json.Valid(got) {
			t.Fatalf("string rewrite failed: %q -> %q, %v", input, got, err)
		}
		before := json.NewDecoder(bytes.NewReader(input))
		after := json.NewDecoder(bytes.NewReader(got))
		before.UseNumber()
		after.UseNumber()
		for {
			original, originalErr := before.Token()
			rewritten, rewrittenErr := after.Token()
			if originalErr == io.EOF && rewrittenErr == io.EOF {
				break
			}
			if originalErr != nil || rewrittenErr != nil {
				t.Fatalf("token streams differ: before %v, after %v", originalErr, rewrittenErr)
			}
			if str, ok := original.(string); ok {
				original = "edited:" + str
			}
			if !reflect.DeepEqual(original, rewritten) {
				t.Fatalf("token = %#v; want %#v", rewritten, original)
			}
		}
	})
}
