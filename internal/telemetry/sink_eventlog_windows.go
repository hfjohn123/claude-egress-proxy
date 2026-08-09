//go:build windows

package telemetry

import (
	"encoding/json"
	"errors"
	"sync"
)

const eventLogSource = "claude-egress-proxy"

var ErrEventLogUnsupported = errors.New("telemetry: event log unsupported")

type eventLog interface {
	Info(uint32, string) error
	Warning(uint32, string) error
	Error(uint32, string) error
	Close() error
}

// OpenEventLogSink opens the preinstalled Application event source.
func OpenEventLogSink(source string) (Sink, error) {
	if source != eventLogSource {
		return nil, ErrInvalidSink
	}
	log, err := openEventLog(source)
	if err != nil {
		return nil, err
	}
	return &eventLogSink{log: log}, nil
}

type eventLogSink struct {
	mu     sync.Mutex
	log    eventLog
	failed error
	closed bool
}

func (s *eventLogSink) WriteRecord(raw []byte) error {
	if !canonicalRecord(raw) {
		return ErrInvalidRecord
	}
	var record struct {
		Level string `json:"level"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return ErrInvalidRecord
	}

	s.mu.Lock()
	if s.failed != nil {
		err := s.failed
		s.mu.Unlock()
		return err
	}
	if s.closed || s.log == nil {
		s.mu.Unlock()
		return ErrInvalidSink
	}
	log := s.log
	s.mu.Unlock()
	var err error
	switch record.Level {
	case "info":
		err = log.Info(1, string(raw))
	case "warn":
		err = log.Warning(1, string(raw))
	case "error":
		err = log.Error(1, string(raw))
	default:
		return ErrInvalidRecord
	}
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return err
		}
		s.failed = err
	}
	return err
}

func (s *eventLogSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.log == nil {
		s.mu.Unlock()
		return nil
	}
	log := s.log
	s.log = nil
	s.mu.Unlock()
	return log.Close()
}
