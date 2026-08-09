//go:build !cep_testcontrol

// Package testcontrol has no runtime behavior in ordinary builds. Tagged
// controls are intentionally isolated so release binaries cannot read a pipe,
// environment variable, or test-only networking configuration.
package testcontrol

// Enabled reports whether this binary was compiled for the external test
// harness. It performs no I/O in an ordinary build.
func Enabled() bool { return false }
