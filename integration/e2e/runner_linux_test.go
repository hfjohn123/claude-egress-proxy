//go:build linux

package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

func TestRunnerRejectsNonRootBeforeMutation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged caller")
	}
	script := runnerPath(t)
	command := exec.Command("bash", script, "--preflight-only")
	output, err := command.CombinedOutput()
	if err == nil || string(output) != "e2e: root is required\n" {
		t.Fatalf("runner output = %q, %v", output, err)
	}
}

func TestRunnerTreatsLeakedNamespaceProcessAsFailure(t *testing.T) {
	raw, err := os.ReadFile(runnerPath(t))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?s)if \[\[ \$\{#pids\[@\]\} -gt 0 \]\]; then\s+cleanup_failed=1\s+kill -TERM`)
	if !pattern.Match(raw) {
		t.Fatal("runner does not fail after detecting a leaked namespace process")
	}
}

func runnerPath(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate runner test source")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "scripts", "verify-e2e.sh")
}
