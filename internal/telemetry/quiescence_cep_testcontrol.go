//go:build cep_testcontrol

package telemetry

// WaitQuiescent waits for records admitted or rejected before its snapshot.
func (l *Logger) WaitQuiescent() {
	l.waitMu.Lock()
	defer l.waitMu.Unlock()
	slot := flipAdmission(l)
	for admissionCount(l, slot) != 0 {
		<-l.quiescent
	}
	target := l.tail.Load()
	for l.terminal.Load() < target {
		<-l.quiescent
	}
}

func flipAdmission(l *Logger) uint64 {
	for {
		state := l.admission.Load()
		if l.admission.CompareAndSwap(state, state^1) {
			return state & 1
		}
	}
}

func admissionCount(l *Logger, slot uint64) uint64 {
	shift := uint(1)
	if slot != 0 {
		shift = 32
	}
	return (l.admission.Load() >> shift) & 0x7fffffff
}
