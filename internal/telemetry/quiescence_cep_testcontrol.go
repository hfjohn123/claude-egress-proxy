//go:build cep_testcontrol

package telemetry

// WaitQuiescent waits for records admitted or rejected before its snapshot.
func (l *Logger) WaitQuiescent() {
	state := snapshotState(l)
	state.mu.Lock()
	defer state.mu.Unlock()
	targetNode := state.tail.Load()
	if capture := state.capture; capture != nil {
		state.capture = nil
		capture <- struct{}{}
	}
	node := state.cursor
	target := l.terminal.Load()
	for node != targetNode {
		next := node.next.Load()
		for next == nil {
			<-state.quiescent
			next = node.next.Load()
		}
		node = next
		for !node.done.Load() {
			<-state.quiescent
		}
		if accepted := node.target.Load(); accepted > target {
			target = accepted
		}
	}
	if state.cursor != targetNode {
		state.cursor.next.Store(nil)
		state.cursor = targetNode
	}
	for l.terminal.Load() < target {
		<-l.progress
	}
}
