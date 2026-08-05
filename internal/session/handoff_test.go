package session

import (
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
)

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
