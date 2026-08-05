package credential

import "context"

// Observation is a candidate read. The watcher retains no accepted snapshot.
type Observation struct {
	Snapshot  ValidatedSnapshot
	Available bool
	Err       error
}

// Watcher reads and validates one candidate at a time; installation belongs to session.
type Watcher struct {
	read func(context.Context) (ValidatedSnapshot, error)
}

func NewWatcher(read func(context.Context) (ValidatedSnapshot, error)) *Watcher {
	return &Watcher{read: read}
}
func (w *Watcher) Initial(ctx context.Context) Observation  { return w.observe(ctx) }
func (w *Watcher) PollOnce(ctx context.Context) Observation { return w.observe(ctx) }
func (w *Watcher) observe(ctx context.Context) Observation {
	if w == nil || w.read == nil {
		return Observation{Err: ErrUnavailable}
	}
	s, err := w.read(ctx)
	if err != nil {
		return Observation{Err: err}
	}
	return Observation{Snapshot: s, Available: true}
}
