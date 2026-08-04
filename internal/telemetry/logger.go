package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

const loggerInvalid = "telemetry: invalid logger"

// Logger is a fixed-capacity, asynchronous record delivery queue.
type Logger struct {
	clock   timebase.Clock
	metrics *Metrics
	sink    Sink

	mu                                                sync.Mutex
	slots                                             [256][2048]byte
	lens                                              [256]int
	fifo                                              [256]int
	free                                              [256]int
	head, tail, queued, freeHead, freeTail, freeCount int
	active                                            int
	accepting, failed, shutting                       bool
	frozen                                            contract.DeliveryResult
	callDeadline, shutdownDeadline                    time.Time
	callTimer, shutdownTimer                          timebase.Timer
	callDone                                          chan error
	notify                                            chan struct{}
	done                                              chan struct{}
	closed                                            bool
	submitted, delivered                              uint64
	quiescent                                         chan struct{}
}

func NewLogger(clock timebase.Clock, metrics *Metrics, sink Sink) *Logger {
	if clock == nil || metrics == nil {
		panic(loggerInvalid)
	}
	l := &Logger{clock: clock, metrics: metrics, sink: sink, active: -1, accepting: sink != nil,
		notify: make(chan struct{}, 1), done: make(chan struct{}), quiescent: make(chan struct{}), callDone: make(chan error, 1)}
	for i := range l.free {
		l.free[i] = i
	}
	l.freeCount, l.freeTail = 256, 256
	if sink == nil {
		l.failed = true
		l.frozen = delivery("dropped_sink_failed")
		close(l.done)
		return l
	}
	go l.supervise()
	return l
}

func (l *Logger) Submit(record Record) {
	b := record.JSON()
	if !validLoggerRecord(b) {
		panic(ErrInvalidRecord)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.submitted++
	if !l.accepting {
		l.recordLocked(l.frozen)
		return
	}
	if l.freeCount == 0 {
		l.recordLocked(delivery("dropped_queue_full"))
		return
	}
	i := l.free[l.freeHead]
	l.freeHead = (l.freeHead + 1) % 256
	l.freeCount--
	copy(l.slots[i][:], b)
	l.lens[i] = len(b)
	l.fifo[l.tail] = i
	l.tail = (l.tail + 1) % 256
	l.queued++
	l.signalLocked()
}

func (l *Logger) Shutdown(ctx context.Context) {
	if ctx == nil {
		panic(loggerInvalid)
	}
	l.mu.Lock()
	if !l.shutting && !l.failed {
		l.accepting = false
		l.shutting = true
		l.frozen = delivery("dropped_shutdown_deadline")
		l.shutdownDeadline = l.clock.Now().Add(time.Second)
		l.shutdownTimer = l.clock.NewTimer(time.Second)
		l.signalLocked()
	} else if !l.shutting {
		l.accepting = false
	}
	done := l.done
	l.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (l *Logger) supervise() {
	defer close(l.done)
	for {
		l.mu.Lock()
		if l.failed {
			l.mu.Unlock()
			return
		}
		if l.active < 0 && l.queued > 0 {
			l.startLocked()
		}
		if l.shutting && l.active < 0 && l.queued == 0 {
			l.closeLocked()
			l.mu.Unlock()
			return
		}
		callDone, callTimer, shutdownTimer, active := l.callDone, l.callTimer, l.shutdownTimer, l.active
		l.mu.Unlock()
		var callC <-chan error
		var timerC, shutdownC <-chan time.Time
		if active >= 0 {
			callC = callDone
			timerC = callTimer.C()
		}
		if shutdownTimer != nil {
			shutdownC = shutdownTimer.C()
		}
		var callResult error
		gotCall := false
		select {
		case <-l.notify:
		case <-timerC:
		case <-shutdownC:
		case callResult = <-callC:
			gotCall = true
		}
		l.mu.Lock()
		now := l.clock.Now()
		if l.shutting && !now.Before(l.shutdownDeadline) {
			l.shutdownExpireLocked()
			l.mu.Unlock()
			return
		}
		if l.active >= 0 && !now.Before(l.callDeadline) {
			l.failLocked()
			l.mu.Unlock()
			return
		}
		if l.active >= 0 && gotCall {
			if callResult != nil {
				l.failLocked()
			} else {
				l.completeActiveLocked(delivery("written"))
			}
		}
		l.mu.Unlock()
	}
}

func (l *Logger) startLocked() {
	i := l.fifo[l.head]
	l.head = (l.head + 1) % 256
	l.queued--
	l.active = i
	l.callDeadline = l.clock.Now().Add(250 * time.Millisecond)
	l.callTimer = l.clock.NewTimer(250 * time.Millisecond)
	bytes := l.slots[i][:l.lens[i]]
	go func(done chan<- error, json []byte) { done <- l.sink.WriteRecord(json) }(l.callDone, bytes)
}

func (l *Logger) completeActiveLocked(result contract.DeliveryResult) {
	l.callTimer.Stop()
	l.recordLocked(result)
	i := l.active
	l.active = -1
	l.callTimer = nil
	l.free[l.freeTail%256] = i
	l.freeTail++
	l.freeCount++
}
func (l *Logger) failLocked() {
	l.accepting = false
	l.failed = true
	failure := delivery("dropped_sink_failed")
	if !l.shutting {
		l.frozen = failure
	}
	if l.active >= 0 {
		l.callTimer.Stop()
		l.recordLocked(failure)
		l.active = -1
		l.callTimer = nil
	}
	for l.queued > 0 {
		l.head = (l.head + 1) % 256
		l.queued--
		l.recordLocked(failure)
	}
	l.closeLocked()
}
func (l *Logger) shutdownExpireLocked() {
	l.accepting = false
	l.frozen = delivery("dropped_shutdown_deadline")
	if l.active >= 0 {
		l.callTimer.Stop()
		l.recordLocked(l.frozen)
		l.active = -1
		l.callTimer = nil
	}
	for l.queued > 0 {
		l.head = (l.head + 1) % 256
		l.queued--
		l.recordLocked(l.frozen)
	}
	l.closeLocked()
}
func (l *Logger) closeLocked() {
	if !l.closed {
		l.closed = true
		if l.shutdownTimer != nil {
			l.shutdownTimer.Stop()
		}
		if l.sink != nil {
			_ = l.sink.Close()
		}
	}
}
func (l *Logger) recordLocked(v contract.DeliveryResult) {
	l.metrics.RecordDelivery(v)
	l.delivered++
	close(l.quiescent)
	l.quiescent = make(chan struct{})
}
func (l *Logger) signalLocked() {
	select {
	case l.notify <- struct{}{}:
	default:
	}
}
func delivery(s string) contract.DeliveryResult {
	v, ok := contract.ParseDeliveryResult(s)
	if !ok {
		panic(loggerInvalid)
	}
	return v
}
func validLoggerRecord(s string) bool {
	return len(s) > 0 && len(s) <= 2047 && !containsInvalidStreamByte([]byte(s))
}
