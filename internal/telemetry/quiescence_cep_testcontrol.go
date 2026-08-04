//go:build cep_testcontrol

package telemetry

// WaitQuiescent waits for records admitted or rejected before its snapshot.
func (l *Logger) WaitQuiescent() {
	l.mu.Lock()
	target := l.submitted
	for l.delivered < target {
		l.quiescent.Wait()
	}
	l.mu.Unlock()
}
