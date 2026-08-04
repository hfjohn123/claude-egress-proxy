//go:build cep_testcontrol

package telemetry

import (
	"context"
	"errors"
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
	l := NewLogger(newManualClock(time.Unix(0, 0)), m, nil)
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
	l := NewLogger(newManualClock(time.Unix(0, 0)), m, sink)
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
	mustPanicLogger(t, func() { NewLogger(newManualClock(time.Time{}), nil, newGateSink()) })
	l := NewLogger(newManualClock(time.Time{}), m, nil)
	mustPanicLogger(t, func() { l.Shutdown(nil) })
}

func TestLoggerWritesCompletionObservedBeforeDeadline(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	l.Submit(Record{json: `{"a":1}`})
	<-sink.started
	clock.Advance(249 * time.Millisecond)
	sink.result <- nil
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "written"); got != 1 {
		t.Fatalf("written=%v", got)
	}
	l.Shutdown(context.Background())
}

func TestLoggerExactCallDeadlineFailsActiveAndQueue(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	l.Submit(Record{json: `{"a":1}`})
	<-sink.started
	l.Submit(Record{json: `{"a":2}`})
	clock.Advance(250 * time.Millisecond)
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_sink_failed"); got != 2 {
		t.Fatalf("failed=%v", got)
	}
	l.Submit(Record{json: `{"a":3}`})
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_sink_failed"); got != 3 {
		t.Fatalf("future=%v", got)
	}
	if sink.calls() != 1 || sink.closeCalls() != 1 {
		t.Fatalf("calls=%d closes=%d", sink.calls(), sink.closeCalls())
	}
}

func TestLoggerSinkErrorPermanentlyFails(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	l.Submit(Record{json: `{"a":1}`})
	<-sink.started
	l.Submit(Record{json: `{"a":2}`})
	sink.result <- errors.New("sink failed")
	l.WaitQuiescent()
	l.Submit(Record{json: `{"a":3}`})
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_sink_failed"); got != 3 {
		t.Fatalf("failed=%v", got)
	}
	if sink.calls() != 1 || sink.closeCalls() != 1 {
		t.Fatalf("calls=%d closes=%d", sink.calls(), sink.closeCalls())
	}
}

func TestLoggerShutdownFailureKeepsFrozenLaterResult(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	l.Submit(Record{json: `{"a":1}`})
	<-sink.started
	<-clock.created
	l.Submit(Record{json: `{"a":2}`})
	shutdownDone := make(chan struct{})
	go func() { l.Shutdown(context.Background()); close(shutdownDone) }()
	<-clock.created
	clock.Advance(100 * time.Millisecond)
	sink.result <- errors.New("failed")
	l.WaitQuiescent()
	l.Submit(Record{json: `{"later":true}`})
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_sink_failed"); got != 2 {
		t.Fatalf("failed=%v", got)
	}
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_shutdown_deadline"); got != 1 {
		t.Fatalf("frozen=%v", got)
	}
	<-shutdownDone
}

func TestLoggerShutdownDeadlineWinsExactTie(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	l.Submit(Record{json: `{"a":1}`})
	<-sink.started
	<-clock.created
	l.Submit(Record{json: `{"a":2}`})
	done := make(chan struct{})
	go func() { l.Shutdown(context.Background()); close(done) }()
	<-clock.created
	clock.Advance(time.Second)
	l.WaitQuiescent()
	<-done
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_shutdown_deadline"); got != 2 {
		t.Fatalf("shutdown=%v", got)
	}
	if sink.closeCalls() != 1 {
		t.Fatalf("closes=%d", sink.closeCalls())
	}
}

type manualClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*manualTimer
	created chan time.Duration
}

func newManualClock(now time.Time) *manualClock {
	return &manualClock{now: now, created: make(chan time.Duration, 8)}
}
func (c *manualClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *manualClock) NewTimer(d time.Duration) timebase.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &manualTimer{clock: c, due: c.now.Add(d), ch: make(chan time.Time, 1), active: true}
	c.timers = append(c.timers, t)
	select {
	case c.created <- d:
	default:
	}
	return t
}
func (c *manualClock) NewTicker(time.Duration) timebase.Ticker { panic("unused") }
func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	timers := append([]*manualTimer(nil), c.timers...)
	c.mu.Unlock()
	for _, t := range timers {
		t.fire(now)
	}
}

type manualTimer struct {
	clock  *manualClock
	mu     sync.Mutex
	due    time.Time
	ch     chan time.Time
	active bool
}

func (t *manualTimer) C() <-chan time.Time { return t.ch }
func (t *manualTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	was := t.active
	t.active = false
	return was
}
func (t *manualTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	now := t.clock.now
	t.clock.mu.Unlock()
	t.mu.Lock()
	was := t.active
	t.due = now.Add(d)
	t.active = true
	t.mu.Unlock()
	return was
}
func (t *manualTimer) fire(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active && !now.Before(t.due) {
		t.active = false
		select {
		case t.ch <- now:
		default:
		}
	}
}

type gateSink struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	records [][]byte
	once    sync.Once
	first   bool
}

type scriptedSink struct {
	started chan struct{}
	result  chan error
	mu      sync.Mutex
	records [][]byte
	closes  int
}

func newScriptedSink() *scriptedSink {
	return &scriptedSink{started: make(chan struct{}, 1), result: make(chan error, 1)}
}
func (s *scriptedSink) WriteRecord(b []byte) error {
	s.mu.Lock()
	s.records = append(s.records, append([]byte(nil), b...))
	s.mu.Unlock()
	s.started <- struct{}{}
	return <-s.result
}
func (s *scriptedSink) Close() error    { s.mu.Lock(); defer s.mu.Unlock(); s.closes++; return nil }
func (s *scriptedSink) calls() int      { s.mu.Lock(); defer s.mu.Unlock(); return len(s.records) }
func (s *scriptedSink) closeCalls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.closes }

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
	m, e := NewMetrics(newManualClock(time.Time{}), func() (time.Time, bool) { return time.Time{}, false })
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
