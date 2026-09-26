package rewriter

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

func TestCSPUTF8MalformedSequenceReplacement(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"invalid-lead", []byte{0xff}, "\ufffd"},
		{"adjacent-invalid-leads", []byte{0xff, 0xff}, "\ufffd\ufffd"},
		{"incomplete-prefix-then-invalid-lead", []byte{0xe2, 0x82, 0xff}, "\ufffd\ufffd"},
		{"truncated-two-byte", []byte{0xc2}, "\ufffd"},
		{"truncated-three-byte", []byte{0xe2, 0x82}, "\ufffd"},
		{"truncated-four-byte", []byte{0xf0, 0x90, 0x80}, "\ufffd"},
		{"prefix-then-ascii", []byte{0xe2, 0x82, '"'}, "\ufffd\""},
		{"prefix-then-valid-sequence", []byte{0xe2, 0x82, 0xc3, 0xa9}, "\ufffdé"},
		{"stray-continuations", []byte{0x80, 0xbf}, "\ufffd\ufffd"},
		{"two-byte-overlong", []byte{0xc0, 0xaf}, "\ufffd\ufffd"},
		{"three-byte-overlong", []byte{0xe0, 0x80, 0xaf}, "\ufffd\ufffd\ufffd"},
		{"four-byte-overlong", []byte{0xf0, 0x80, 0x80, 0xaf}, "\ufffd\ufffd\ufffd\ufffd"},
		{"surrogate", []byte{0xed, 0xa0, 0x80}, "\ufffd\ufffd\ufffd"},
		{"above-unicode-range", []byte{0xf4, 0x90, 0x80, 0x80}, "\ufffd\ufffd\ufffd\ufffd"},
		{"forbidden-lead", []byte{0xf5, 0x80, 0x80, 0x80}, "\ufffd\ufffd\ufffd\ufffd"},
		{"bounds-reset-after-error", []byte{0xe0, 0x9f, 0xc2, 0x80, 0xed, 0x9f, 0xbf}, "\ufffd\ufffd\u0080\ud7ff"},
		{"bounds-reset-after-first-continuation", []byte{0xff, 0xf4, 0x8f, 0xbf, 0xbf}, "\ufffd\U0010ffff"},
		{"leave-html-preprocessing-to-caller", []byte{'\r', '\n', 0, 0xff}, "\r\n\x00\ufffd"},
		{"retain-bom-codepoint", []byte{0xef, 0xbb, 0xbf, 0xff}, "\ufeff\ufffd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := bytes.Clone(tc.input)
			got := cspUTF8(tc.input)
			if string(got) != tc.want || !utf8.Valid(got) {
				t.Fatalf("decode %x: got %q (%x), want %q", tc.input, got, got, tc.want)
			}
			if !bytes.Equal(tc.input, original) {
				t.Fatal("decoder mutated source bytes")
			}
		})
	}
}

func TestCSPUTF8ValidInputUsesOriginalBytes(t *testing.T) {
	for _, input := range [][]byte{nil, {}, []byte("ASCII\x00\r\n"), []byte("\ufeffé \u0080 \u07ff \u0800 \ud7ff \ue000 \ufffd \U00010000 \U0010ffff")} {
		got := cspUTF8(input)
		if !bytes.Equal(got, input) {
			t.Fatalf("valid input changed: %q => %q", input, got)
		}
		if len(input) > 0 && &got[0] != &input[0] {
			t.Fatal("valid input did not use allocation-free fast path")
		}
	}
}
