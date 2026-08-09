// Package proxy contains the HTTP-facing proxy adapters.
package proxy

import (
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
)

// Readiness aggregates the five independent serving predicates. It delegates
// their publication to the coordinator so ownership and readiness have one
// synchronization point.
type Readiness struct {
	c *session.Coordinator
}

func NewReadiness(c *session.Coordinator) *Readiness {
	return &Readiness{c: c}
}

func (r *Readiness) Set(predicate contract.ReadinessPredicate, ready bool) bool {
	if r == nil {
		return false
	}
	if r.c == nil {
		return false
	}
	return r.c.SetReadiness(predicate, ready)
}

func (r *Readiness) Ready() bool {
	if r == nil {
		return false
	}
	return r.c.ReadinessReady()
}
