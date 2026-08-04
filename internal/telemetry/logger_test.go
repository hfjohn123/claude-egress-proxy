//go:build cep_testcontrol

package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestLoggerAPIExists(t *testing.T) {
	var _ *Logger
}

func TestLoggerNilSinkAndInvalidInputTerminalize(t *testing.T) {
	m := loggerMetrics(t)
	l := NewLogger(manualClock{now: time.Unix(0, 0)}, m, nil)
	l.Submit(Record{json: `{}`})
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_sink_failed"); got != 1 {
		t.Fatalf("failed=%v", got)
	}
	mustPanicRecord(t, func() { l.Submit(Record{}) })
	l.Shutdown(context.Background())
}

func TestLoggerCapacityAndFIFOOwnCopiedBytes(t *testing.T) {
	m := loggerMetrics(t)
	sink := newGateSink()
	l := NewLogger(manualClock{now: time.Unix(0, 0)}, m, sink)
	first := []byte(`{"n":0}`)
	l.Submit(Record{json: string(first)})
	<-sink.started
	for i := 1; i < 256; i++ {
		l.Submit(Record{json: `{"n":1}`})
	}
	l.Submit(Record{json: `{"overflow":true}`})
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_queue_full"); got != 1 {
		t.Fatalf("queue full=%v", got)
	}
	sink.unblock()
	l.Shutdown(context.Background())
	l.WaitQuiescent()
	if len(sink.records) != 256 || string(sink.records[0]) != string(first) {
		t.Fatalf("records=%d first=%q", len(sink.records), sink.records[0])
	}
}

func TestLoggerDependenciesPanic(t *testing.T) {
	m := loggerMetrics(t)
	mustPanicLogger(t, func() { NewLogger(nil, m, newGateSink()) })
	mustPanicLogger(t, func() { NewLogger(manualClock{}, nil, newGateSink()) })
	l := NewLogger(manualClock{}, m, nil)
	mustPanicLogger(t, func() { l.Shutdown(nil) })
}

type manualClock struct{ now time.Time }

func (c manualClock) Now() time.Time                          { return c.now }
func (c manualClock) NewTimer(time.Duration) timebase.Timer   { return manualTimer{} }
func (c manualClock) NewTicker(time.Duration) timebase.Ticker { panic("unused") }

type manualTimer struct{}

func (manualTimer) C() <-chan time.Time      { return nil }
func (manualTimer) Stop() bool               { return true }
func (manualTimer) Reset(time.Duration) bool { return true }

type gateSink struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	records [][]byte
	once    sync.Once
	first   bool
}

func newGateSink() *gateSink {
	return &gateSink{started: make(chan struct{}, 1), release: make(chan struct{})}
}
func (s *gateSink) WriteRecord(b []byte) error {
	s.mu.Lock()
	s.records = append(s.records, append([]byte(nil), b...))
	s.mu.Unlock()
	s.mu.Lock()
	first := !s.first
	s.first = true
	s.mu.Unlock()
	if first {
		select {
		case s.started <- struct{}{}:
		default:
		}
		<-s.release
	}
	return nil
}
func (s *gateSink) unblock()     { s.once.Do(func() { close(s.release) }) }
func (s *gateSink) Close() error { s.unblock(); return nil }
func loggerMetrics(t *testing.T) *Metrics {
	t.Helper()
	m, e := NewMetrics(manualClock{}, func() (time.Time, bool) { return time.Time{}, false })
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func mustPanicLogger(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() != loggerInvalid {
			t.Fatalf("panic=%v", recover())
		}
	}()
	f()
}
func mustPanicRecord(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() != ErrInvalidRecord {
			t.Fatalf("panic=%v", recover())
		}
	}()
	f()
}
