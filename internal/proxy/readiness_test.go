package proxy

import (
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
)

func TestReadinessRequiresEveryPredicate(t *testing.T) {
	c := session.NewCoordinator(credential.Verifier{}, nil)
	r := NewReadiness(c)
	for _, predicate := range contract.AllReadinessPredicates() {
		p, _ := contract.ParseReadinessPredicate(predicate)
		r.Set(p, true)
	}
	if !r.Ready() {
		t.Fatal("all predicates should be ready")
	}
	for _, predicate := range contract.AllReadinessPredicates() {
		p, _ := contract.ParseReadinessPredicate(predicate)
		r.Set(p, false)
		if r.Ready() {
			t.Fatalf("ready with %s false", predicate)
		}
		r.Set(p, true)
	}
}
