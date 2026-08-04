package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

const loggerInvalid = "telemetry: invalid logger"

const (
	loggerAccepting uint32 = iota
	loggerShutdown
	loggerFailed
)

// Logger is a fixed-capacity, asynchronous record delivery queue.
type Logger struct {
	clock   timebase.Clock
	metrics *Metrics
	sink    Sink

	slots     [256][2048]byte
	lens      [256]atomic.Uint32
	published [256]atomic.Uint64
	capacity  chan struct{}
	notify    chan struct{}
	progress  chan struct{}
	quiescent chan struct{}
	callDone  chan error
	done      chan struct{}

	gate        atomic.Uint32
	publication atomic.Uint32
	epoch       atomic.Pointer[loggerEpoch]
	tail        atomic.Uint64
	terminal    atomic.Uint64

	stateMu          sync.Mutex // Shutdown, failure, and supervisor only; Submit never takes it.
	waitMu           sync.Mutex // Auxiliary callers only; Submit never takes it.
	shutdown         bool
	shutdownDeadline time.Time
	shutdownTimer    timebase.Timer
	closed           bool
}

type loggerEpoch struct {
	active atomic.Uint32
	target atomic.Uint64
	closed atomic.Bool
}

func NewLogger(clock timebase.Clock, metrics *Metrics, sink Sink) *Logger {
	if clock == nil || metrics == nil {
		panic(loggerInvalid)
	}
	l := &Logger{clock: clock, metrics: metrics, sink: sink, capacity: make(chan struct{}, 256), notify: make(chan struct{}, 1), progress: make(chan struct{}, 1), quiescent: make(chan struct{}, 1), callDone: make(chan error, 1), done: make(chan struct{})}
	l.epoch.Store(&loggerEpoch{})
	if sink == nil {
		l.gate.Store(loggerFailed)
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
	epoch := l.joinEpoch()
	defer l.leaveEpoch(epoch)
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
	l.publishTicket(ticket, b, epoch)
}

func (l *Logger) Shutdown(ctx context.Context) {
	if ctx == nil {
		panic(loggerInvalid)
	}
	l.stateMu.Lock()
	if l.gate.Load() == loggerAccepting {
		l.gate.Store(loggerShutdown)
		l.shutdown = true
		l.shutdownDeadline = l.clock.Now().Add(time.Second)
		l.shutdownTimer = l.clock.NewTimer(time.Second)
		l.stateMu.Unlock()
		l.signal(l.notify)
	} else {
		l.stateMu.Unlock()
	}
	select {
	case <-l.done:
	case <-ctx.Done():
	}
}

func (l *Logger) supervise() {
	defer close(l.done)
	var active uint64 = ^uint64(0)
	var callTimer timebase.Timer
	var callDeadline time.Time
	defer func() {
		if callTimer != nil {
			callTimer.Stop()
		}
		l.stateMu.Lock()
		if l.shutdownTimer != nil {
			l.shutdownTimer.Stop()
		}
		l.stateMu.Unlock()
	}()
	for {
		l.stateMu.Lock()
		gate := l.gate.Load()
		shutdown := l.shutdown
		deadline := l.shutdownDeadline
		timer := l.shutdownTimer
		l.stateMu.Unlock()
		if gate != loggerAccepting && l.publication.Load() == 0 {
			tail := l.tail.Load()
			if gate == loggerFailed {
				l.terminalize(l.gateResult(gate), tail)
				return
			}
			expired := shutdown && !l.clock.Now().Before(deadline)
			if expired {
				l.terminalize(delivery("dropped_shutdown_deadline"), tail)
				return
			}
			if active == ^uint64(0) && l.terminal.Load() == tail {
				if timer != nil {
					timer.Stop()
				}
				l.closeSink()
				return
			}
		}
		if active == ^uint64(0) {
			head := l.terminal.Load()
			if l.published[head%256].Load() == head+1 {
				active = head
				callDeadline = l.clock.Now().Add(250 * time.Millisecond)
				callTimer = l.clock.NewTimer(250 * time.Millisecond)
				bytes := l.slots[head%256][:l.lens[head%256].Load()]
				go func(json []byte) { l.callDone <- l.sink.WriteRecord(json) }(bytes)
				continue
			}
		}
		var callC <-chan error
		var callDeadlineC <-chan time.Time
		var shutdownC <-chan time.Time
		if active != ^uint64(0) {
			callC = l.callDone
			callDeadlineC = callTimer.C()
		}
		l.stateMu.Lock()
		if l.shutdownTimer != nil {
			shutdownC = l.shutdownTimer.C()
		}
		l.stateMu.Unlock()
		var callResult error
		gotCall := false
		select {
		case callResult = <-callC:
			gotCall = true
		case <-callDeadlineC:
		case <-shutdownC:
		case <-l.notify:
		}
		now := l.clock.Now()
		l.stateMu.Lock()
		shutdownExpired := l.shutdown && !now.Before(l.shutdownDeadline)
		l.stateMu.Unlock()
		if shutdownExpired {
			l.terminalize(delivery("dropped_shutdown_deadline"), l.waitTail())
			return
		}
		if active != ^uint64(0) && !now.Before(callDeadline) {
			l.failGate()
			l.terminalize(delivery("dropped_sink_failed"), l.waitTail())
			return
		}
		if gotCall {
			if callResult == nil {
				callTimer.Stop()
				l.record(delivery("written"))
				l.terminal.Add(1)
				<-l.capacity
				l.signal(l.progress)
				l.signal(l.quiescent)
				active = ^uint64(0)
				continue
			}
			l.failGate()
			l.terminalize(delivery("dropped_sink_failed"), l.waitTail())
			return
		}
	}
}

func (l *Logger) waitTail() uint64 {
	for l.publication.Load() != 0 {
		<-l.progress
	}
	return l.tail.Load()
}
func (l *Logger) failGate() {
	l.stateMu.Lock()
	if l.gate.Load() == loggerAccepting {
		l.gate.Store(loggerFailed)
	}
	l.stateMu.Unlock()
}
func (l *Logger) joinEpoch() *loggerEpoch {
	epoch := l.epoch.Load()
	epoch.active.Add(1)
	if !epoch.closed.Load() {
		return epoch
	}
	epoch.active.Add(^uint32(0))
	epoch = l.epoch.Load()
	epoch.active.Add(1)
	return epoch
}
func (l *Logger) leaveEpoch(epoch *loggerEpoch) {
	epoch.active.Add(^uint32(0))
	l.signal(l.quiescent)
}
func (l *Logger) publishTicketCore(ticket uint64, b string, epoch *loggerEpoch) {
	for target := epoch.target.Load(); target < ticket+1; {
		if epoch.target.CompareAndSwap(target, ticket+1) {
			break
		}
		target = epoch.target.Load()
	}
	i := ticket % 256
	copy(l.slots[i][:], b)
	l.lens[i].Store(uint32(len(b)))
	l.published[i].Store(ticket + 1)
	l.signal(l.notify)
}
func (l *Logger) terminalize(result contract.DeliveryResult, tail uint64) {
	for head := l.terminal.Load(); head < tail; head++ {
		l.record(result)
	}
	l.terminal.Store(tail)
	l.signal(l.progress)
	l.signal(l.quiescent)
	l.closeSink()
}
func (l *Logger) closeSink() {
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	if !l.closed {
		l.closed = true
		_ = l.sink.Close()
	}
}
func (l *Logger) record(v contract.DeliveryResult) { l.metrics.RecordDelivery(v) }
func (l *Logger) signal(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
func (l *Logger) gateResult(gate uint32) contract.DeliveryResult {
	if gate == loggerShutdown {
		return delivery("dropped_shutdown_deadline")
	}
	return delivery("dropped_sink_failed")
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
