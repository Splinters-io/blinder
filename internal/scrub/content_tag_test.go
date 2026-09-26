package scrub

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
)

func TestContentTagIsPrivateStableAndRequestShared(t *testing.T) {
	gate := NewGate([]string{"target.example"}, []string{"AcmeCorp"}, "alias.local")
	body := []byte("AcmeCorp's confidential original representation")
	tag := gate.ContentTag(body)
	decoded, err := hex.DecodeString(tag)
	if err != nil || len(decoded) != 32 || tag != strings.ToLower(tag) {
		t.Fatalf("tag is not full SHA256 hex: %q", tag)
	}
	public := sha256.Sum256(body)
	if tag == hex.EncodeToString(public[:]) {
		t.Fatal("content tag exposes the public source digest")
	}
	if tag != gate.ContentTag(append([]byte(nil), body...)) || tag != gate.ForRequest().ForRequest().ContentTag(body) {
		t.Fatal("same session bytes have inconsistent tags")
	}
	changed := append([]byte(nil), body...)
	changed[len(changed)-1] ^= 1
	if tag == gate.ContentTag(changed) {
		t.Fatal("same-length original content change disappeared")
	}
	other := NewGate([]string{"target.example"}, []string{"AcmeCorp"}, "alias.local")
	if string(gate.Seed()) != string(other.Seed()) {
		t.Fatal("private content key changed the public alias seed")
	}
	if tag == other.ContentTag(body) {
		t.Fatal("independent sessions share a content tag")
	}
}

func TestContentTagSupportsConcurrentRequestViews(t *testing.T) {
	gate := NewGate(nil, nil, "alias.local")
	body := []byte("stable original content")
	want := gate.ContentTag(body)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := gate.ForRequest()
			for range 100 {
				if got := request.ContentTag(body); got != want {
					t.Errorf("concurrent tag %q want %q", got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}
