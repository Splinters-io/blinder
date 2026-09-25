package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Separate OS processes ensure a package global or other in-memory key cache
// cannot accidentally make restart coverage pass.
func TestVersionRegistryProcessPersistence(t *testing.T) {
	if mode := os.Getenv("BLINDER_TEST_VERSION_PHASE"); mode != "" {
		dir := os.Getenv("BLINDER_TEST_VERSION_DIR")
		vr, err := persistentVersionRegistry(1, filepath.Join(dir, "private"))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "issued-token")
		if mode == "issue" {
			token := vr.Register("https://target.test/asset", "version1")
			if err := os.WriteFile(path, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, owned, found := vr.VerifyAndLookup(string(data)); !owned || found {
			t.Fatal("restart did not authenticate the expired reference")
		}
		app := "1-" + strings.Repeat("a", 16) + "-" + strings.Repeat("b", 32)
		if _, owned, _ := vr.VerifyAndLookup(app); owned {
			t.Fatal("unissued application value claimed by shape")
		}
		fresh := vr.Register("https://target.test/asset", "version2")
		if _, owned, found := vr.VerifyAndLookup(fresh); !owned || !found {
			t.Fatal("fresh reference unavailable")
		}
		vr.Register("https://target.test/other", "version3")
		if _, owned, found := vr.VerifyAndLookup(fresh); !owned || found {
			t.Fatal("eviction lost ownership")
		}
		return
	}
	dir := t.TempDir()
	for _, phase := range []string{"issue", "restart"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestVersionRegistryProcessPersistence$")
		cmd.Env = append(os.Environ(), "BLINDER_TEST_VERSION_PHASE="+phase, "BLINDER_TEST_VERSION_DIR="+dir)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", phase, err, output)
		}
	}
}
