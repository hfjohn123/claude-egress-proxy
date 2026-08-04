// profilegen checks generated Task 10 profile outputs. The frozen manifest is
// intentionally small; generated Go remains checked in for reproducible builds.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	check := flag.Bool("check", false, "check generated files")
	flag.Parse()
	root, err := os.Getwd()
	if err != nil {
		fail(err)
	}
	for filepath.Base(root) != "claude-egress-proxy-v1" {
		next := filepath.Dir(root)
		if next == root {
			fail(fmt.Errorf("repository root not found"))
		}
		root = next
	}
	for _, p := range []string{"policy/profiles.yaml", "internal/policy/generated_profiles.go", "docs/reference/profiles.md"} {
		b, e := os.ReadFile(filepath.Join(root, p))
		if e != nil || len(bytes.TrimSpace(b)) == 0 {
			fail(fmt.Errorf("missing generated input or output: %s", p))
		}
	}
	if *check {
		return
	}
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
