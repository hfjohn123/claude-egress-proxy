//go:build !windows

package telemetry

import "errors"

var ErrEventLogUnsupported = errors.New("telemetry: event log unsupported")

// OpenEventLogSink is unavailable outside Windows.
func OpenEventLogSink(string) (Sink, error) { return nil, ErrEventLogUnsupported }
