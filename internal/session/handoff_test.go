package session

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
)

type countLease struct{ releases int }

func (l *countLease) Release() bool {
	if l.releases != 0 {
		return false
	}
	l.releases++
	return true
}

func TestCoordinatorRejectsRevocationReactivation(t *testing.T) {
	var instance [16]byte
	var id credential.RecordID
	id[0] = 7
	record := credential.Record{ID: id, Device: "laptop", CreatedAt: time.Unix(0, 0).UTC(), State: credential.Revoked}
	revoked, err := credential.NewValidatedSnapshot(instance, 1, []credential.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	c := NewCoordinator(credential.Verifier{}, nil)
	if c.InstallCredentials(revoked) != InstallInstalled {
		t.Fatal("initial install")
	}
	record.State = credential.Active
	active, err := credential.NewValidatedSnapshot(instance, 2, []credential.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	if c.InstallCredentials(active) != InstallRejected {
		t.Fatal("reactivated revoked record")
	}
}

func TestCoordinatorRejectsInstanceChange(t *testing.T) {
	var first, second [16]byte
	second[0] = 1
	one, err := credential.NewValidatedSnapshot(first, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := credential.NewValidatedSnapshot(second, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCoordinator(credential.Verifier{}, nil)
	if c.InstallCredentials(one) != InstallInstalled {
		t.Fatal("initial install")
	}
	if c.InstallCredentials(two) != InstallRejected {
		t.Fatal("instance replacement accepted")
	}
}

func TestTransferRejectsRepeatedHandoff(t *testing.T) {
	var instance [16]byte
	var id credential.RecordID
	id[0] = 1
	record := credential.Record{ID: id, Device: "laptop", CreatedAt: time.Unix(0, 0).UTC(), State: credential.Active}
	snapshot, _ := credential.NewValidatedSnapshot(instance, 1, []credential.Record{record})
	c := NewCoordinator(credential.Verifier{}, nil)
	c.InstallCredentials(snapshot)
	handle, _ := snapshot.AuthHandle(id)
	h := newHandoff(c, &countLease{}, &attempt{handle: handle})
	c.handoffs[h] = struct{}{}
	client, peer := net.Pipe()
	defer peer.Close()
	if err := h.Attach(client, bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))); err != nil {
		t.Fatal(err)
	}
	if _, got := c.Transfer(h); got.String() != "established" {
		t.Fatalf("first transfer = %s", got)
	}
	if _, got := c.Transfer(h); got.String() != "client_disconnected" {
		t.Fatalf("second transfer = %s", got)
	}
}

func TestBeginFixedAllowsAlreadyAdmittedResponseDuringDrain(t *testing.T) {
	c := NewCoordinator(credential.Verifier{}, nil)
	c.BeginDrain()
	if _, ok := c.BeginFixed(&countLease{}); !ok {
		t.Fatal("drain rejected admitted terminal response")
	}
}

func TestInstallRevocationClosesMatchingPendingAndTunnel(t *testing.T) {
	var instance [16]byte
	var id credential.RecordID
	id[0] = 9
	record := credential.Record{ID: id, Device: "laptop", CreatedAt: time.Unix(0, 0).UTC(), State: credential.Active}
	active, err := credential.NewValidatedSnapshot(instance, 1, []credential.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	c := NewCoordinator(credential.Verifier{}, nil)
	c.InstallCredentials(active)
	pendingHandoff := newHandoff(c, &countLease{}, &attempt{handle: credential.AuthHandle{RecordID: id}})
	pendingHandoff.attached = true
	c.handoffs[pendingHandoff] = struct{}{}
	pending := &reservation{coordinator: c, handoff: pendingHandoff, handle: credential.AuthHandle{RecordID: id}}
	c.pending[pending] = struct{}{}
	tunnelHandoff := newHandoff(c, &countLease{}, &attempt{handle: credential.AuthHandle{RecordID: id}})
	tunnelHandoff.attached = true
	c.handoffs[tunnelHandoff] = struct{}{}
	client, peer := net.Pipe()
	defer peer.Close()
	tun := &tunnel{coordinator: c, handoff: tunnelHandoff, origin: client}
	c.tunnels[tun] = struct{}{}
	record.State = credential.Revoked
	revoked, err := credential.NewValidatedSnapshot(instance, 2, []credential.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	c.InstallCredentials(revoked)
	if len(c.pending) != 0 || len(c.tunnels) != 0 || len(c.handoffs) != 0 {
		t.Fatalf("owners remain: pending=%d tunnels=%d handoffs=%d", len(c.pending), len(c.tunnels), len(c.handoffs))
	}
}

func TestForceCloseHijackedRemovesPendingAndCommitRejectsReleasedHandoff(t *testing.T) {
	c := NewCoordinator(credential.Verifier{}, nil)
	h := newHandoff(c, &countLease{}, &attempt{})
	h.attached = true
	c.handoffs[h] = struct{}{}
	r := &reservation{coordinator: c, handoff: h}
	c.pending[r] = struct{}{}
	c.ForceCloseHijacked()
	if len(c.pending) != 0 || len(c.handoffs) != 0 {
		t.Fatal("force close retained owner")
	}
	client, peer := net.Pipe()
	defer peer.Close()
	if _, got := c.Commit(r, client); got.String() != "credential_changed" {
		t.Fatalf("commit result = %s", got)
	}
}

func TestForceCloseHijackedClassifiesTunnelAsShutdownDeadline(t *testing.T) {
	c := NewCoordinator(credential.Verifier{}, nil)
	h := newHandoff(c, &countLease{}, &attempt{})
	h.attached = true
	c.handoffs[h] = struct{}{}
	client, peer := net.Pipe()
	defer peer.Close()
	tun := &tunnel{coordinator: c, handoff: h, origin: client}
	c.tunnels[tun] = struct{}{}
	var got string
	c.SetTerminalObserver(func(event TerminalEvent) { got = event.CloseResult.String() })
	c.ForceCloseHijacked()
	if got != "shutdown_deadline" || !tun.released || len(c.tunnels) != 0 {
		t.Fatalf("close=%q released=%v tunnels=%d", got, tun.released, len(c.tunnels))
	}
}

func TestInstallRejectsPurgedAttemptAndObserverRunsOnce(t *testing.T) {
	var instance [16]byte
	var id credential.RecordID
	id[0] = 4
	record := credential.Record{ID: id, Device: "laptop", CreatedAt: time.Unix(0, 0).UTC(), State: credential.Active}
	first, _ := credential.NewValidatedSnapshot(instance, 1, []credential.Record{record})
	c := NewCoordinator(credential.Verifier{}, nil)
	c.InstallCredentials(first)
	second, _ := credential.NewValidatedSnapshot(instance, 2, nil)
	c.InstallCredentials(second)
	a := &attempt{coordinator: c, live: true, handle: credential.AuthHandle{RecordID: id, Generation: 1}}
	c.snapshot = &second
	if _, got := c.BeginSetup(a); got.String() != "credential_changed" {
		t.Fatalf("stale setup = %s", got)
	}
	var count int
	c.SetTerminalObserver(func(TerminalEvent) { count++ })
	b := &attempt{coordinator: c, live: true}
	b.Release(connect("client_disconnected"))
	b.Release(connect("client_disconnected"))
	if count != 1 {
		t.Fatalf("observer count=%d", count)
	}
}

func TestUnrelatedCredentialPublicationPreservesActiveSetup(t *testing.T) {
	var instance [16]byte
	var firstID, secondID credential.RecordID
	firstID[0], secondID[0] = 1, 2
	created := time.Unix(0, 0).UTC()
	first := credential.Record{ID: firstID, Device: "laptop", CreatedAt: created, State: credential.Active}
	one, err := credential.NewValidatedSnapshot(instance, 1, []credential.Record{first})
	if err != nil {
		t.Fatal(err)
	}
	c := NewCoordinator(credential.Verifier{}, nil)
	c.InstallCredentials(one)
	handle, ok := one.AuthHandle(firstID)
	if !ok {
		t.Fatal("missing first handle")
	}
	a := &attempt{coordinator: c, live: true, handle: handle}
	second := credential.Record{ID: secondID, Device: "phone", CreatedAt: created, State: credential.Active}
	two, err := credential.NewValidatedSnapshot(instance, 2, []credential.Record{first, second})
	if err != nil {
		t.Fatal(err)
	}
	c.InstallCredentials(two)
	if _, got := c.BeginSetup(a); got.String() != "established" {
		t.Fatalf("unrelated publication invalidated setup: %s", got)
	}
}

func TestInstallSkippedRevokeAndPurgeClosesExistingTunnel(t *testing.T) {
	var instance [16]byte
	var id credential.RecordID
	id[0] = 3
	record := credential.Record{ID: id, Device: "laptop", CreatedAt: time.Unix(0, 0).UTC(), State: credential.Active}
	active, _ := credential.NewValidatedSnapshot(instance, 1, []credential.Record{record})
	c := NewCoordinator(credential.Verifier{}, nil)
	c.InstallCredentials(active)
	handle, _ := active.AuthHandle(id)
	h := newHandoff(c, &countLease{}, &attempt{handle: handle})
	h.attached = true
	c.handoffs[h] = struct{}{}
	client, peer := net.Pipe()
	defer peer.Close()
	tun := &tunnel{coordinator: c, handoff: h, origin: client}
	c.tunnels[tun] = struct{}{}
	purged, _ := credential.NewValidatedSnapshot(instance, 3, nil)
	c.InstallCredentials(purged)
	if len(c.tunnels) != 0 || len(c.handoffs) != 0 {
		t.Fatalf("purged owner survived: tunnels=%d handoffs=%d", len(c.tunnels), len(c.handoffs))
	}
}

func TestTransferRejectsCredentialRevokedAfterBeginSetup(t *testing.T) {
	var instance [16]byte
	var id credential.RecordID
	id[0] = 4
	record := credential.Record{ID: id, Device: "laptop", CreatedAt: time.Unix(0, 0).UTC(), State: credential.Active}
	active, _ := credential.NewValidatedSnapshot(instance, 1, []credential.Record{record})
	c := NewCoordinator(credential.Verifier{}, nil)
	c.InstallCredentials(active)
	handle, _ := active.AuthHandle(id)
	h := newHandoff(c, &countLease{}, &attempt{coordinator: c, live: true, handle: handle})
	h.attached = true
	c.handoffs[h] = struct{}{}
	record.State = credential.Revoked
	revoked, _ := credential.NewValidatedSnapshot(instance, 2, []credential.Record{record})
	c.InstallCredentials(revoked)
	if _, got := c.Transfer(h); got.String() != "credential_changed" {
		t.Fatalf("transfer after revoke = %s", got)
	}
	if len(c.handoffs) != 0 || len(c.pending) != 0 {
		t.Fatalf("revoked handoff retained: handoffs=%d pending=%d", len(c.handoffs), len(c.pending))
	}
}
