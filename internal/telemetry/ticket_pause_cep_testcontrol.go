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

type joinPause struct {
	entered chan<- struct{}
	release <-chan struct{}
}

var loggerPauses sync.Map
var loggerJoinPauses sync.Map

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

func (l *Logger) joinEpoch() uint32 {
	state := l.handoff.Add(2)
	lane := uint32(state & 1)
	if value, ok := loggerJoinPauses.LoadAndDelete(l); ok {
		pause := value.(*joinPause)
		pause.entered <- struct{}{}
		<-pause.release
	}
	l.active[lane].Add(1)
	l.handoff.Add(^uint64(1))
	l.signal(l.quiescent)
	return lane
}

func (l *Logger) publishTicket(ticket uint64, b string, lane uint32) {
	if value, ok := loggerPauses.LoadAndDelete(l); ok {
		pause := value.(*ticketPause)
		pause.entered <- struct{}{}
		<-pause.release
	}
	l.publishTicketCore(ticket, b, lane)
}
