package session

import (
	"crypto/sha256"
	"net/netip"
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
	_, _, _ = c.Authenticate(nil, false, admission.Prefix{}, le, time.Unix(0, 0))
	if c.Snapshot().PreAuthConnections != 0 {
		t.Fatal("lease retained")
	}
}

func TestAuthenticateMissingChallengesWithoutSpendingInvalidLimiter(t *testing.T) {
	clock := fixedClock{time.Unix(0, 0)}
	auth := admission.NewAuthentication(clock)
	c := NewCoordinator(credential.Verifier{}, auth)
	snapshot, _ := credential.NewValidatedSnapshot([16]byte{}, 1, nil)
	c.InstallCredentials(snapshot)
	prefix := admission.Aggregate(netip.MustParseAddr("198.51.100.2"))
	for range 20 {
		_, outcome, _ := c.Authenticate(nil, false, prefix, admission.PublicLease{}, clock.Now())
		if outcome.String() != "challenge" {
			t.Fatalf("missing auth outcome=%s", outcome)
		}
	}
	if auth.Entries() != 0 {
		t.Fatalf("missing auth allocated %d limiter entries", auth.Entries())
	}
}

func TestAuthenticatePresentInvalidUsesFailureLimiter(t *testing.T) {
	clock := fixedClock{time.Unix(0, 0)}
	c := NewCoordinator(credential.Verifier{}, admission.NewAuthentication(clock))
	snapshot, _ := credential.NewValidatedSnapshot([16]byte{}, 1, nil)
	c.InstallCredentials(snapshot)
	prefix := admission.Aggregate(netip.MustParseAddr("198.51.100.3"))
	for i := range 11 {
		_, outcome, _ := c.Authenticate([]byte("Basic bad"), true, prefix, admission.PublicLease{}, clock.Now())
		want := "invalid"
		if i == 10 {
			want = "throttled"
		}
		if outcome.String() != want {
			t.Fatalf("attempt %d outcome=%s want=%s", i+1, outcome, want)
		}
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
