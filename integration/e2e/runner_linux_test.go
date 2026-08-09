//go:build linux

package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunnerRejectsNonRootBeforeMutation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged caller")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate runner test source")
	}
	script := filepath.Join(filepath.Dir(source), "..", "..", "scripts", "verify-e2e.sh")
	command := exec.Command("bash", script, "--preflight-only")
	output, err := command.CombinedOutput()
	if err == nil || string(output) != "e2e: root is required\n" {
		t.Fatalf("runner output = %q, %v", output, err)
	}
}
