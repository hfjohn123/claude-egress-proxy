//go:build cep_testcontrol

package telemetry

import (
	"sync"
	"testing"
)

type ticketPause struct {
	entered chan<- struct{}
	release <-chan struct{}
}

var loggerPauses sync.Map

func installTicketPause(t *testing.T, l *Logger, entered chan<- struct{}, release <-chan struct{}) {
	t.Helper()
	if _, loaded := loggerPauses.LoadOrStore(l, &ticketPause{entered: entered, release: release}); loaded {
		t.Fatal("ticket pause unavailable")
	}
}

func (l *Logger) publishTicket(ticket uint64, b string, epoch *loggerEpoch) {
	if value, ok := loggerPauses.LoadAndDelete(l); ok {
		pause := value.(*ticketPause)
		pause.entered <- struct{}{}
		<-pause.release
	}
	l.publishTicketCore(ticket, b, epoch)
}
