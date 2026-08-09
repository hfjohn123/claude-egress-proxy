//go:build !windows

package service

// WindowsServiceName is stable across install, Event Log, and SCM operations.
const WindowsServiceName = "ClaudeEgressProxy"
