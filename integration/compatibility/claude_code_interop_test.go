package compatibility_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeCodeGateContract(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "verify-claude-code-interop.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{"HTTPS_PROXY", "NO_PROXY", "proxy-side DNS", "sanitized", "opt-in", "Claude Code"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(required)) {
			t.Errorf("gate missing %q", required)
		}
	}
	for _, forbidden := range []string{"Install-Module", "setx", "$env:ANTHROPIC_API_KEY"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Errorf("gate must not contain %q", forbidden)
		}
	}
}
