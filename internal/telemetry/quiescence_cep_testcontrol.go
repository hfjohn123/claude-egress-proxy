//go:build cep_testcontrol

package telemetry

// WaitQuiescent waits for records admitted or rejected before its snapshot.
func (l *Logger) WaitQuiescent() {
	l.waitMu.Lock()
	defer l.waitMu.Unlock()
	state := l.handoff.Load()
	oldLane := uint32(state & 1)
	if oldLane == 0 {
		l.handoff.Add(1)
	} else {
		l.handoff.Add(^uint64(0))
	}
	for l.handoff.Load()>>1 != 0 {
		<-l.quiescent
	}
	for l.active[oldLane].Load() != 0 {
		<-l.quiescent
	}
	target := l.terminal.Load()
	for i := range l.owners {
		owner := l.owners[i].Load()
		published := l.published[i].Load()
		if owner == oldLane+1 && owner == l.owners[i].Load() && published > target {
			target = published
		}
	}
	for l.terminal.Load() < target {
		<-l.quiescent
	}
}
