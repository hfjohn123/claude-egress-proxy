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
	c := NewCoordinator(credential.Verifier{}, nil)
	h := newHandoff(c, &countLease{}, &attempt{})
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
