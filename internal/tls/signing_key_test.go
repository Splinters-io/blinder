package tls

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSigningKeyConcurrentPersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	var keys [8][32]byte
	var errs [8]error
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func(i int) { defer wg.Done(); keys[i], errs[i] = SigningKey(dir) }(i)
	}
	wg.Wait()
	for i := range keys {
		if errs[i] != nil || keys[i] != keys[0] || keys[i] == [32]byte{} {
			t.Fatalf("different ownership keys: %d %v", i, errs[i])
		}
	}
	info, err := os.Stat(filepath.Join(dir, "version-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("key permissions are not private")
	}
}

func TestSigningKeyRejectsUnsafeOrCorruptStore(t *testing.T) {
	for _, mode := range []string{"corrupt", "permissions", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			if _, err := SigningKey(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "version-signing.key")
			switch mode {
			case "corrupt":
				if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := SigningKey(dir); err == nil {
				t.Fatal("unsafe key accepted or silently replaced")
			}
		})
	}
}
