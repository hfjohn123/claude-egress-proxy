//go:build cep_testcontrol

package telemetry

import (
	"context"
	"errors"
	gobuild "go/build"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestLoggerConcurrentAdmissionUsesAllCapacity(t *testing.T) {
	m := loggerMetrics(t)
	sink := newGateSink()
	l := NewLogger(newManualClock(time.Unix(0, 0)), m, sink)
	l.Submit(Record{json: `{"n":0}`})
	<-sink.started
	const total = 260
	start := make(chan struct{})
	done := make(chan struct{}, total)
	for i := 1; i < total; i++ {
		go func() { <-start; l.Submit(Record{json: `{"n":1}`}); done <- struct{}{} }()
	}
	close(start)
	for i := 1; i < total; i++ {
		<-done
	}
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_queue_full"); got != 4 {
		t.Fatalf("queue full=%v", got)
	}
	sink.unblock()
	l.Shutdown(context.Background())
	l.WaitQuiescent()
	if got := len(sink.records); got != 256 {
		t.Fatalf("written=%d", got)
	}
}

func TestLoggerSubmitHasNoProducerLockOrGoroutine(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(strings.TrimSuffix(file, "_test.go") + ".go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	start := strings.Index(s, "func (l *Logger) Submit")
	end := strings.Index(s[start:], "\nfunc (l *Logger) Shutdown") + start
	body := s[start:end]
	for _, forbidden := range []string{"stateMu.Lock", "sync.Mutex", "sync.RWMutex", "sync.Cond", "go func"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("Submit contains %q", forbidden)
		}
	}
}

func TestLoggerProducerHelpersHaveNoRetryLoops(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for _, check := range []struct{ file, name string }{
		{filepath.Join(dir, "publish_ticket.go"), "joinEpoch"},
		{filepath.Join(dir, "logger.go"), "publishTicketCore"},
	} {
		b, err := os.ReadFile(check.file)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		name := check.name
		start := strings.Index(s, "func (l *Logger) "+name)
		if start < 0 {
			t.Fatalf("missing %s", name)
		}
		body := s[start:]
		if end := strings.Index(body, "\nfunc "); end >= 0 {
			body = body[:end]
		}
		if strings.Contains(body, "for ") || strings.Contains(body, "CompareAndSwap") {
			t.Fatalf("%s retries", name)
		}
	}
}

func TestLoggerShutdownWaitsForReservedProducerPublication(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newGateSink()
	l := NewLogger(clock, m, sink)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	installTicketPause(t, l, entered, release)
	submitted := make(chan struct{})
	go func() { l.Submit(Record{json: `{"a":1}`}); close(submitted) }()
	<-entered
	shutdown := make(chan struct{})
	go func() { l.Shutdown(context.Background()); close(shutdown) }()
	select {
	case <-shutdown:
		t.Fatal("shutdown completed before reserved ticket published")
	default:
	}
	close(release)
	<-submitted
	<-sink.started
	sink.unblock()
	<-shutdown
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "written"); got != 1 {
		t.Fatalf("written=%v", got)
	}
	l.Submit(Record{json: `{"later":true}`})
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_shutdown_deadline"); got != 1 {
		t.Fatalf("frozen=%v", got)
	}
}

func TestLoggerWaitQuiescentSnapshotsTailOnce(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newGateSink()
	l := NewLogger(clock, m, sink)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	installTicketPause(t, l, entered, release)
	firstDone := make(chan struct{})
	go func() { l.Submit(Record{json: `{"first":true}`}); close(firstDone) }()
	<-entered
	quiescent := make(chan struct{})
	go func() { l.WaitQuiescent(); close(quiescent) }()
	close(release)
	<-firstDone
	<-sink.started
	sink.unblock()
	<-quiescent

	// Hook was one-shot. This later submission must not join the old snapshot.
	l.Submit(Record{json: `{"later":true}`})
	l.WaitQuiescent()
}

func TestLoggerWaitQuiescentExcludesLaterEpoch(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	installTicketPause(t, l, entered, release)
	oldLane := uint32(l.handoff.Load() & 1)
	firstDone := make(chan struct{})
	go func() { l.Submit(Record{json: `{"first":true}`}); close(firstDone) }()
	<-entered
	quiescent := make(chan struct{})
	go func() { l.WaitQuiescent(); close(quiescent) }()
	for uint32(l.handoff.Load()&1) == oldLane {
		runtime.Gosched()
	}
	l.Submit(Record{json: `{"later":true}`})
	close(release)
	<-firstDone
	<-sink.started
	sink.result <- nil
	<-sink.started // later record is now blocked in WriteRecord
	<-quiescent
	if got := sink.calls(); got != 2 {
		t.Fatalf("calls=%d", got)
	}
	sink.result <- nil
	l.WaitQuiescent()
	l.Shutdown(context.Background())
}

func TestLoggerWaitQuiescentWaitsForClassifiedJoin(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	installJoinPause(t, l, entered, release)
	submitted := make(chan struct{})
	go func() { l.Submit(Record{json: `{"joined":true}`}); close(submitted) }()
	<-entered
	oldLane := uint32(l.handoff.Load() & 1)
	quiescent := make(chan struct{})
	go func() { l.WaitQuiescent(); close(quiescent) }()
	for uint32(l.handoff.Load()&1) == oldLane {
		runtime.Gosched()
	}
	select {
	case <-quiescent:
		t.Fatal("quiescent before classified join registered")
	default:
	}
	close(release)
	<-submitted
	<-sink.started
	select {
	case <-quiescent:
		t.Fatal("quiescent before admitted record completed")
	default:
	}
	sink.result <- nil
	<-quiescent
	l.Shutdown(context.Background())
}

func TestLoggerSourceHasNoBusyTailSpin(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(strings.TrimSuffix(file, "_test.go") + ".go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "runtime.Gosched") {
		t.Fatal("busy tail spin")
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

func TestLoggerShutdownDeadlineDropsActiveAndQueuedInFIFO(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	for i := 0; i < 255; i++ {
		l.Submit(Record{json: `{"n":1}`})
	}
	l.Submit(Record{json: `{"stopped":true}`})
	if got := l.tail.Load(); got != 256 {
		t.Fatalf("tail=%d", got)
	}
	if got := string(l.slots[255][:l.lens[255].Load()]); got != `{"stopped":true}` {
		t.Fatalf("last record=%q", got)
	}
	<-sink.started
	<-clock.created // first call timer
	shutdown := make(chan struct{})
	go func() { l.Shutdown(context.Background()); close(shutdown) }()
	<-clock.created // shutdown timer
	for i := 0; i < 4; i++ {
		clock.Advance(249 * time.Millisecond)
		sink.result <- nil
		<-sink.started
	}
	clock.Advance(4 * time.Millisecond)
	l.WaitQuiescent()
	<-shutdown
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "written"); got != 4 {
		t.Fatalf("written=%v", got)
	}
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_shutdown_deadline"); got != 252 {
		t.Fatalf("shutdown=%v", got)
	}
	if sink.calls() != 5 || sink.closeCalls() != 1 {
		t.Fatalf("calls=%d closes=%d", sink.calls(), sink.closeCalls())
	}
	l.Submit(Record{json: `{"after":true}`})
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_shutdown_deadline"); got != 253 {
		t.Fatalf("post-gate shutdown=%v", got)
	}
}

func TestLoggerDeadlineDoesNotMutateBlockedWriterBytes(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newRetainedBlockedSink()
	l := NewLogger(clock, m, sink)
	const record = `{"immutable":true}`
	l.Submit(Record{json: record})
	<-sink.started
	<-clock.created
	clock.Advance(250 * time.Millisecond)
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_sink_failed"); got != 1 {
		t.Fatalf("failed=%v", got)
	}
	if got := sink.retainedString(); got != record {
		t.Fatalf("retained=%q", got)
	}
	if sink.calls() != 1 || sink.closeCalls() != 1 {
		t.Fatalf("calls=%d closes=%d", sink.calls(), sink.closeCalls())
	}
	l.Submit(Record{json: `{"later":true}`})
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_sink_failed"); got != 2 {
		t.Fatalf("later failed=%v", got)
	}
	if sink.calls() != 1 {
		t.Fatalf("calls=%d", sink.calls())
	}
	sink.releaseCall()
	<-sink.returned
	if got := sink.retainedString(); got != record {
		t.Fatalf("retained after return=%q", got)
	}
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_sink_failed"); got != 2 || sink.closeCalls() != 1 {
		t.Fatalf("failed=%v closes=%d", got, sink.closeCalls())
	}
}

func TestLoggerConcurrentShutdownSharesDeadlineCloseAndResult(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newRetainedBlockedSink()
	l := NewLogger(clock, m, sink)
	l.Submit(Record{json: `{"active":true}`})
	<-sink.started
	<-clock.created // call deadline
	const callers = 4
	done := make(chan struct{}, callers)
	for range callers {
		go func() { l.Shutdown(context.Background()); done <- struct{}{} }()
	}
	<-clock.created // shared shutdown deadline
	clock.Advance(time.Second)
	for range callers {
		<-done
	}
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_shutdown_deadline"); got != 1 {
		t.Fatalf("shutdown=%v", got)
	}
	if sink.closeCalls() != 1 || sink.calls() != 1 {
		t.Fatalf("calls=%d closes=%d", sink.calls(), sink.closeCalls())
	}
	select {
	case d := <-clock.created:
		t.Fatalf("unexpected timer=%v", d)
	default:
	}
	sink.releaseCall()
	<-sink.returned
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "dropped_shutdown_deadline"); got != 1 || sink.closeCalls() != 1 {
		t.Fatalf("shutdown=%v closes=%d", got, sink.closeCalls())
	}
}

func TestLoggerTestControlSourceIsTaggedAndLimited(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := strings.TrimSuffix(file, "logger_test.go")
	control, err := os.ReadFile(dir + "quiescence_cep_testcontrol.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(control), "//go:build cep_testcontrol\n") {
		t.Fatal("missing exact cep_testcontrol build tag")
	}
	if got := strings.Count(string(control), "func (l *Logger) "); got != 1 || !strings.Contains(string(control), "func (l *Logger) WaitQuiescent()") {
		t.Fatalf("test-control methods=%d", got)
	}
	pkg, err := gobuild.Default.ImportDir(filepath.Clean(dir), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range pkg.GoFiles {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(b))
		if strings.Contains(string(b), "WaitQuiescent") || strings.Contains(string(b), "TestControl") || strings.Contains(lower, "pause") || strings.Contains(lower, "hook") {
			t.Fatalf("ordinary source %s exposes test control", name)
		}
	}
	logger, err := os.ReadFile(dir + "logger.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"loggerTicketHook", "ticketHook", "loggerTicketPause"} {
		if strings.Contains(string(logger), forbidden) {
			t.Fatalf("ordinary logger contains %q", forbidden)
		}
	}
}

func TestLoggerCanceledShutdownKeepsDraining(t *testing.T) {
	clock := newManualClock(time.Unix(0, 0))
	m := loggerMetrics(t)
	sink := newScriptedSink()
	l := NewLogger(clock, m, sink)
	l.Submit(Record{json: `{"a":1}`})
	<-sink.started
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.Shutdown(ctx); close(done) }()
	<-clock.created
	cancel()
	<-done
	clock.Advance(249 * time.Millisecond)
	sink.result <- nil
	l.WaitQuiescent()
	if got := counterValue(t, m, "claude_proxy_log_records_total", "result", "written"); got != 1 {
		t.Fatalf("written=%v", got)
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

type retainedBlockedSink struct {
	started  chan struct{}
	release  chan struct{}
	returned chan struct{}
	mu       sync.Mutex
	retained []byte
	callsN   int
	closes   int
	once     sync.Once
}

func newRetainedBlockedSink() *retainedBlockedSink {
	return &retainedBlockedSink{started: make(chan struct{}, 1), release: make(chan struct{}), returned: make(chan struct{}, 1)}
}
func (s *retainedBlockedSink) WriteRecord(b []byte) error {
	s.mu.Lock()
	s.retained = b // Deliberately retain the logger-owned slice without copying.
	s.callsN++
	s.mu.Unlock()
	s.started <- struct{}{}
	<-s.release
	s.returned <- struct{}{}
	return nil
}
func (s *retainedBlockedSink) Close() error { s.mu.Lock(); defer s.mu.Unlock(); s.closes++; return nil }
func (s *retainedBlockedSink) releaseCall() { s.once.Do(func() { close(s.release) }) }
func (s *retainedBlockedSink) retainedString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.retained)
}
func (s *retainedBlockedSink) calls() int      { s.mu.Lock(); defer s.mu.Unlock(); return s.callsN }
func (s *retainedBlockedSink) closeCalls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.closes }

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
