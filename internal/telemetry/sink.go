package telemetry

import "errors"

// Sink delivers complete, bare telemetry records.
type Sink interface {
	WriteRecord(json []byte) error
	Close() error
}

var ErrInvalidSink = errors.New("telemetry: invalid sink")
