package admission

import (
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"sync"
)

type Admin struct {
	mu              sync.Mutex
	clock           timebase.Clock
	starts          bucket
	active, metrics int
	limits          contract.Limits
}

func NewAdmin(clock timebase.Clock) *Admin {
	l := contract.V1()
	return &Admin{clock: clock, starts: newBucket(clock, l.AdminRatePerSecond, l.AdminBurst), limits: l}
}

type AdminLease struct {
	owner *Admin
	once  sync.Once
}

func (a *Admin) Acquire() (AdminLease, Decision) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active == a.limits.AdminActive {
		return AdminLease{}, DecisionCapacity
	}
	if !a.starts.take(a.clock.Now()) {
		return AdminLease{}, DecisionThrottled
	}
	a.active++
	return AdminLease{owner: a}, DecisionAllowed
}
func (l *AdminLease) Release() {
	if l == nil || l.owner == nil {
		return
	}
	l.once.Do(func() {
		l.owner.mu.Lock()
		defer l.owner.mu.Unlock()
		if l.owner.active > 0 {
			l.owner.active--
		}
	})
}

type MetricsWorkLease struct {
	owner *Admin
	once  sync.Once
}

func (a *Admin) AcquireMetricsWork() (MetricsWorkLease, Decision) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.metrics == a.limits.AdminMetricsWorkSlots {
		return MetricsWorkLease{}, DecisionCapacity
	}
	a.metrics++
	return MetricsWorkLease{owner: a}, DecisionAllowed
}
func (l *MetricsWorkLease) Release() {
	if l == nil || l.owner == nil {
		return
	}
	l.once.Do(func() {
		l.owner.mu.Lock()
		defer l.owner.mu.Unlock()
		if l.owner.metrics > 0 {
			l.owner.metrics--
		}
	})
}
