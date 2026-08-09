package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hfjohn123/claude-egress-proxy/internal/config"
)

func main() {
	check := flag.Bool("check", false, "verify generated example")
	flag.Parse()
	root, err := findRoot()
	if err != nil {
		fatal(err)
	}
	path := filepath.Join(root, "examples", "config.yaml")
	id := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	want := config.RenderExample(id, "/var/lib/claude-egress-proxy")
	if *check {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			fatal(fmt.Errorf("generated example differs"))
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		fatal(err)
	}
}
func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		next := filepath.Dir(dir)
		if next == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = next
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
