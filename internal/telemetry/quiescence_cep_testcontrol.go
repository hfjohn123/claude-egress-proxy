//go:build cep_testcontrol

package telemetry

// WaitQuiescent waits for records admitted or rejected before its snapshot.
func (l *Logger) WaitQuiescent() {
	l.waitMu.Lock()
	defer l.waitMu.Unlock()
	old := l.epoch.Swap(&loggerEpoch{})
	for l.joining.Load() != 0 {
		<-l.quiescent
	}
	for old.active.Load() != 0 {
		<-l.quiescent
	}
	var target uint64
	for i := range l.owners {
		owner := l.owners[i].Load()
		published := l.published[i].Load()
		if owner == old && owner == l.owners[i].Load() && published > target {
			target = published
		}
	}
	for l.terminal.Load() < target {
		<-l.quiescent
	}
}
