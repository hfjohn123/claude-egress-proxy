//go:build windows && cep_testcontrol

package telemetry

import (
	"errors"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

type capturedEvent struct {
	level string
	id    uint32
	text  string
}

type testEventLog struct {
	events    []capturedEvent
	reportErr error
	closed    int
}

func (l *testEventLog) Info(id uint32, text string) error {
	l.events = append(l.events, capturedEvent{"info", id, text})
	return l.reportErr
}
func (l *testEventLog) Warning(id uint32, text string) error {
	l.events = append(l.events, capturedEvent{"warn", id, text})
	return l.reportErr
}
func (l *testEventLog) Error(id uint32, text string) error {
	l.events = append(l.events, capturedEvent{"error", id, text})
	return l.reportErr
}
func (l *testEventLog) Close() error { l.closed++; return nil }

func TestEventLogSinkFramesCanonicalRecords(t *testing.T) {
	log := &testEventLog{}
	restore := setEventLogOpenForTest(func(source string) (eventLog, error) {
		if source != "claude-egress-proxy" {
			t.Fatalf("source = %q", source)
		}
		return log, nil
	})
	defer restore()

	sink, err := OpenEventLogSink("claude-egress-proxy")
	if err != nil {
		t.Fatalf("OpenEventLogSink: %v", err)
	}
	records := []struct {
		raw   []byte
		level string
	}{
		{mustServiceState(t, "started"), "info"},
		{mustServiceState(t, "not_ready"), "warn"},
		{mustServiceState(t, "startup_failed"), "error"},
	}
	for _, tc := range records {
		if err := sink.WriteRecord(tc.raw); err != nil {
			t.Fatalf("WriteRecord(%s): %v", tc.level, err)
		}
	}
	if len(log.events) != len(records) {
		t.Fatalf("events = %d, want %d", len(log.events), len(records))
	}
	for i, got := range log.events {
		if got.level != records[i].level || got.id != 1 || got.text != string(records[i].raw) {
			t.Fatalf("event %d = %#v, want level=%q id=1 text=%q", i, got, records[i].level, records[i].raw)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if log.closed != 1 {
		t.Fatalf("Close calls = %d, want 1", log.closed)
	}
}

func TestEventLogSinkRejectsInvalidAndPermanentlyFails(t *testing.T) {
	log := &testEventLog{reportErr: errors.New("report failed")}
	restore := setEventLogOpenForTest(func(string) (eventLog, error) { return log, nil })
	defer restore()

	if _, err := OpenEventLogSink("other"); !errors.Is(err, ErrInvalidSink) {
		t.Fatalf("bad source error = %v, want ErrInvalidSink", err)
	}
	sink, err := OpenEventLogSink("claude-egress-proxy")
	if err != nil {
		t.Fatalf("OpenEventLogSink: %v", err)
	}
	if err := sink.WriteRecord([]byte("{}")); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("invalid record error = %v, want ErrInvalidRecord", err)
	}
	record := mustServiceState(t, "started")
	if err := sink.WriteRecord(record); !errors.Is(err, log.reportErr) {
		t.Fatalf("report error = %v, want %v", err, log.reportErr)
	}
	if err := sink.WriteRecord(record); !errors.Is(err, log.reportErr) {
		t.Fatalf("failed sink error = %v, want %v", err, log.reportErr)
	}
}

func mustServiceState(t *testing.T, name string) []byte {
	t.Helper()
	reason, ok := contract.ParseServiceStateReason(name)
	if !ok {
		t.Fatalf("ParseServiceStateReason(%q)", name)
	}
	r, err := ServiceState(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), reason)
	if err != nil {
		t.Fatalf("ServiceState(%s): %v", reason, err)
	}
	return []byte(r.JSON())
}
