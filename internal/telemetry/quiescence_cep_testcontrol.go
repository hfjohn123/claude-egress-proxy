//go:build cep_testcontrol

package telemetry

import "errors"

// WaitQuiescent waits for records admitted or rejected before its snapshot.
func (l *Logger) WaitQuiescent() {
	for {
		for l.inFlight.Load() != 0 {
			<-l.progress
		}
		target := l.tail.Load()
		if l.terminal.Load() >= target {
			return
		}
		<-l.progress
	}
}

// PauseAfterTicketForTest pauses one producer after it owns a ticket.
func (l *Logger) PauseAfterTicketForTest(entered chan<- struct{}, release <-chan struct{}) error {
	if entered == nil || release == nil || !l.ticketHook.CompareAndSwap(nil, &loggerTicketHook{entered: entered, release: release}) {
		return errors.New("logger ticket hook unavailable")
	}
	return nil
}
