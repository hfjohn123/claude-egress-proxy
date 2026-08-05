// Package proxy contains the HTTP-facing proxy adapters.
package proxy

import (
	"sync"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
)

// Readiness aggregates the five independent serving predicates. It delegates
// their publication to the coordinator so ownership and readiness have one
// synchronization point.
type Readiness struct {
	mu     sync.RWMutex
	c      *session.Coordinator
	values map[contract.ReadinessPredicate]bool
}

func NewReadiness(c *session.Coordinator) *Readiness {
	return &Readiness{c: c, values: make(map[contract.ReadinessPredicate]bool)}
}

func (r *Readiness) Set(predicate contract.ReadinessPredicate, ready bool) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	changed := r.values[predicate] != ready
	r.values[predicate] = ready
	r.mu.Unlock()
	if r.c != nil {
		r.c.SetReadiness(predicate, ready)
	}
	return changed
}

func (r *Readiness) Ready() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, value := range contract.AllReadinessPredicates() {
		predicate, ok := contract.ParseReadinessPredicate(value)
		if !ok || !r.values[predicate] {
			return false
		}
	}
	return true
}
