//go:build !cep_testcontrol

package telemetry

func (l *Logger) joinEpoch() uint32 {
	state := l.handoff.Add(2)
	lane := uint32(state & 1)
	l.active[lane].Add(1)
	l.handoff.Add(^uint64(1))
	l.signal(l.quiescent)
	return lane
}

func (l *Logger) publishTicket(ticket uint64, b string, lane uint32) {
	l.publishTicketCore(ticket, b, lane)
}
