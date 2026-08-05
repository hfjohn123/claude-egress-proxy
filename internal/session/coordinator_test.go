package session

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time                          { return c.now }
func (c fixedClock) NewTimer(time.Duration) timebase.Timer   { panic("unused") }
func (c fixedClock) NewTicker(time.Duration) timebase.Ticker { panic("unused") }

func TestCoordinatorUnavailableRejectsAndReleasesLease(t *testing.T) {
	c := NewCoordinator(credential.Verifier{}, nil)
	le, decision := admission.NewPublic(fixedClock{time.Unix(0, 0)}).Acquire(admission.Prefix{})
	if !decision.Allowed() {
		t.Fatal("acquire")
	}
	_, _, _ = c.Authenticate(nil, le, time.Unix(0, 0))
	if c.Snapshot().PreAuthConnections != 0 {
		t.Fatal("lease retained")
	}
}

func TestCoordinatorRevocationClosesCommittedTunnel(t *testing.T) {
	var instance [16]byte
	var id credential.RecordID
	id[0] = 1
	record := credential.Record{ID: id, Device: "laptop", CreatedAt: time.Unix(0, 0).UTC(), State: credential.Active, Verifier: sha256.Sum256(nil)}
	snap, err := credential.NewValidatedSnapshot(instance, 1, []credential.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	c := NewCoordinator(credential.Verifier{}, nil)
	if got := c.InstallCredentials(snap); got != InstallInstalled {
		t.Fatalf("install = %v", got)
	}
	if c.Snapshot().CredentialGeneration != 1 {
		t.Fatal("generation")
	}
	if !c.SetCredentialUnavailable(1) {
		t.Fatal("unavailable transition")
	}
	if c.Snapshot().CredentialGeneration != 0 {
		t.Fatal("gauge not cleared")
	}
}
