//go:build cep_testcontrol

package telemetry

// WaitQuiescent waits for records admitted or rejected before its snapshot.
func (l *Logger) WaitQuiescent() {
	for l.inFlight.Load() != 0 {
		<-l.quiescent
	}
	target := l.tail.Load()
	for l.terminal.Load() < target {
		<-l.quiescent
	}
}
