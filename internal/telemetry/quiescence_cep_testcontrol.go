//go:build cep_testcontrol

package telemetry

// WaitQuiescent waits for records admitted or rejected before its snapshot.
func (l *Logger) WaitQuiescent() {
	l.waitMu.Lock()
	defer l.waitMu.Unlock()
	old := l.epoch.Swap(&loggerEpoch{})
	old.closed.Store(true)
	for old.active.Load() != 0 {
		<-l.quiescent
	}
	target := old.target.Load()
	for l.terminal.Load() < target {
		<-l.quiescent
	}
}
