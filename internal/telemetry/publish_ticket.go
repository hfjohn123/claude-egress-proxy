//go:build !cep_testcontrol

package telemetry

func (l *Logger) publishTicket(ticket uint64, b string, epoch *loggerEpoch) {
	l.publishTicketCore(ticket, b, epoch)
}
