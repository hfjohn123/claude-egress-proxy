//go:build cep_testcontrol

package telemetry

import (
	"sync"
	"sync/atomic"
	"testing"
)

type admissionNode struct {
	next   atomic.Pointer[admissionNode]
	done   atomic.Bool
	target atomic.Uint64
}

type loggerSnapshotState struct {
	stub      admissionNode
	tail      atomic.Pointer[admissionNode]
	mu        sync.Mutex
	cursor    *admissionNode
	quiescent chan struct{}
	capture   chan<- struct{}
}

type ticketPause struct {
	entered chan<- struct{}
	release <-chan struct{}
}

type joinPause struct {
	entered chan<- struct{}
	release <-chan struct{}
}

var loggerSnapshots sync.Map
var loggerPauses sync.Map
var loggerJoinPauses sync.Map

func snapshotState(l *Logger) *loggerSnapshotState {
	if actual, ok := loggerSnapshots.Load(l); ok {
		return actual.(*loggerSnapshotState)
	}
	state := &loggerSnapshotState{quiescent: make(chan struct{}, 1)}
	state.tail.Store(&state.stub)
	state.cursor = &state.stub
	actual, _ := loggerSnapshots.LoadOrStore(l, state)
	return actual.(*loggerSnapshotState)
}

func installTicketPause(t *testing.T, l *Logger, entered chan<- struct{}, release <-chan struct{}) {
	t.Helper()
	if _, loaded := loggerPauses.LoadOrStore(l, &ticketPause{entered: entered, release: release}); loaded {
		t.Fatal("ticket pause unavailable")
	}
}

func installJoinPause(t *testing.T, l *Logger, entered chan<- struct{}, release <-chan struct{}) {
	t.Helper()
	if _, loaded := loggerJoinPauses.LoadOrStore(l, &joinPause{entered: entered, release: release}); loaded {
		t.Fatal("join pause unavailable")
	}
}

func installSnapshotCapture(t *testing.T, l *Logger, capture chan<- struct{}) {
	t.Helper()
	state := snapshotState(l)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.capture != nil {
		t.Fatal("snapshot capture unavailable")
	}
	state.capture = capture
}

func (l *Logger) Submit(record Record) {
	b := record.JSON()
	if !validLoggerRecord(b) {
		panic(ErrInvalidRecord)
	}
	state := snapshotState(l)
	node := &admissionNode{}
	predecessor := state.tail.Swap(node)
	if value, ok := loggerJoinPauses.LoadAndDelete(l); ok {
		pause := value.(*joinPause)
		pause.entered <- struct{}{}
		<-pause.release
	}
	predecessor.next.Store(node)
	l.signal(state.quiescent)
	defer func() {
		node.done.Store(true)
		l.signal(state.quiescent)
	}()
	if gate := l.gate.Load(); gate != loggerAccepting {
		l.record(l.gateResult(gate))
		return
	}
	select {
	case l.capacity <- struct{}{}:
	default:
		l.record(delivery("dropped_queue_full"))
		return
	}
	l.publication.Add(1)
	defer func() { l.publication.Add(^uint32(0)); l.signal(l.notify); l.signal(l.progress) }()
	if gate := l.gate.Load(); gate != loggerAccepting {
		<-l.capacity
		l.record(l.gateResult(gate))
		return
	}
	ticket := l.tail.Add(1) - 1
	node.target.Store(ticket + 1)
	if value, ok := loggerPauses.LoadAndDelete(l); ok {
		pause := value.(*ticketPause)
		pause.entered <- struct{}{}
		<-pause.release
	}
	l.publishTicketCore(ticket, b)
}
