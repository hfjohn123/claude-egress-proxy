//go:build !cep_testcontrol

package telemetry

func (l *Logger) Submit(record Record) {
	b := record.JSON()
	if !validLoggerRecord(b) {
		panic(ErrInvalidRecord)
	}
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
	l.publishTicketCore(ticket, b)
}
