//go:build cep_testcontrol

package telemetry

import (
	"sync/atomic"
	"testing"
)

type ticketPause struct {
	entered chan<- struct{}
	release <-chan struct{}
}

var loggerPause atomic.Pointer[ticketPause]

func installTicketPause(t *testing.T, entered chan<- struct{}, release <-chan struct{}) {
	t.Helper()
	if !loggerPause.CompareAndSwap(nil, &ticketPause{entered: entered, release: release}) {
		t.Fatal("ticket pause unavailable")
	}
}

func loggerTicketPause() {
	if pause := loggerPause.Swap(nil); pause != nil {
		pause.entered <- struct{}{}
		<-pause.release
	}
}
