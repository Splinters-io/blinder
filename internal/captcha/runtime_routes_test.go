package captcha

import (
	"os/exec"
	"testing"
)

func TestProviderRuntimeOriginRecovery(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for resource runtime tests")
	}
	if output, err := exec.Command(node, "runtime_routes_test.js").CombinedOutput(); err != nil {
		t.Fatalf("runtime: %v\n%s", err, output)
	}
}
