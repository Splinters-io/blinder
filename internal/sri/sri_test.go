package sri

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"testing"
)

func TestParseIntegrity_SingleHash(t *testing.T) {
	data := []byte("hello world")
	h := sha256.Sum256(data)
	attr := "sha256-" + base64.StdEncoding.EncodeToString(h[:])

	entries := ParseIntegrity(attr)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Algorithm != "sha256" {
		t.Errorf("algorithm = %q, want sha256", entries[0].Algorithm)
	}
}

func TestParseIntegrity_MultipleHashes(t *testing.T) {
	h256 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	h384 := base64.StdEncoding.EncodeToString(make([]byte, 48))
	h512 := base64.StdEncoding.EncodeToString(make([]byte, 64))
	attr := "sha256-" + h256 + " sha384-" + h384 + " sha512-" + h512
	entries := ParseIntegrity(attr)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func TestParseIntegrity_WithOptions(t *testing.T) {
	h := base64.StdEncoding.EncodeToString(make([]byte, 32))
	attr := "sha256-" + h + "?ct=application/javascript"
	entries := ParseIntegrity(attr)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Options != "ct=application/javascript" {
		t.Errorf("options = %q", entries[0].Options)
	}
}

func TestParseIntegrity_InvalidIgnored(t *testing.T) {
	h := base64.StdEncoding.EncodeToString(make([]byte, 32))
	attr := "md5-notvalid sha256-" + h
	entries := ParseIntegrity(attr)
	if len(entries) != 1 {
		t.Errorf("expected 1 valid entry (sha256), got %d", len(entries))
	}
}

func TestVerify_ValidSHA256(t *testing.T) {
	data := []byte("test content for SRI verification")
	h := sha256.Sum256(data)
	attr := "sha256-" + base64.StdEncoding.EncodeToString(h[:])
	entries := ParseIntegrity(attr)

	ok, err := Verify(data, entries)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Error("verification should pass for correct hash")
	}
}

func TestVerify_ValidSHA384(t *testing.T) {
	data := []byte("test content for SRI verification")
	h := sha512.Sum384(data)
	attr := "sha384-" + base64.StdEncoding.EncodeToString(h[:])
	entries := ParseIntegrity(attr)

	ok, err := Verify(data, entries)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Error("verification should pass for correct sha384 hash")
	}
}

func TestVerify_InvalidHash(t *testing.T) {
	data := []byte("actual content")
	attr := "sha256-" + base64.StdEncoding.EncodeToString([]byte("wrong hash value padding!"))
	entries := ParseIntegrity(attr)

	ok, err := Verify(data, entries)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if ok {
		t.Error("verification should fail for wrong hash")
	}
}

func TestVerify_StrongestAlgorithmWins(t *testing.T) {
	data := []byte("multi-hash content")
	h384 := sha512.Sum384(data)
	correctSHA384 := "sha384-" + base64.StdEncoding.EncodeToString(h384[:])
	wrongSHA256 := "sha256-" + base64.StdEncoding.EncodeToString([]byte("wrong hash value pad!!"))

	entries := ParseIntegrity(wrongSHA256 + " " + correctSHA384)
	ok, err := Verify(data, entries)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Error("strongest algorithm (sha384) is correct, verification should pass")
	}
}

func TestVerify_MultipleHashesSameAlgorithm(t *testing.T) {
	data := []byte("content for multi")
	h := sha256.Sum256(data)
	correct := "sha256-" + base64.StdEncoding.EncodeToString(h[:])
	wrong := "sha256-" + base64.StdEncoding.EncodeToString([]byte("pad wrong hash value!!"))

	entries := ParseIntegrity(wrong + " " + correct)
	ok, err := Verify(data, entries)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Error("at least one hash matches, verification should pass")
	}
}

func TestVerify_EmptyEntries(t *testing.T) {
	ok, err := Verify([]byte("data"), nil)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if ok {
		t.Error("empty entries should not verify")
	}
}

func TestComputeIntegrity_SHA384(t *testing.T) {
	data := []byte("compute hash test")
	result := ComputeIntegrity(data, "sha384")
	if result == "" {
		t.Fatal("should return non-empty")
	}
	if !hasPrefix(result, "sha384-") {
		t.Errorf("should start with sha384-, got %q", result)
	}

	entries := ParseIntegrity(result)
	ok, _ := Verify(data, entries)
	if !ok {
		t.Error("computed integrity should verify against the same data")
	}
}

func TestComputeIntegrity_SHA256(t *testing.T) {
	data := []byte("compute hash test")
	result := ComputeIntegrity(data, "sha256")
	entries := ParseIntegrity(result)
	ok, _ := Verify(data, entries)
	if !ok {
		t.Error("computed sha256 integrity should verify")
	}
}

func TestStrongestAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		input []HashEntry
		want  string
	}{
		{[]HashEntry{{Algorithm: "sha256"}}, "sha256"},
		{[]HashEntry{{Algorithm: "sha256"}, {Algorithm: "sha384"}}, "sha384"},
		{[]HashEntry{{Algorithm: "sha256"}, {Algorithm: "sha512"}}, "sha512"},
		{[]HashEntry{{Algorithm: "sha384"}, {Algorithm: "sha512"}}, "sha512"},
	} {
		got := StrongestAlgorithm(tc.input)
		if got != tc.want {
			t.Errorf("StrongestAlgorithm(%v) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
