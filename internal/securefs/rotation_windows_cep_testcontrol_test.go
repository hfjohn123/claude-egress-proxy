//go:build windows && cep_testcontrol

package securefs

import (
	"context"
	"testing"
	"time"
)

func TestWindowsRotationNamespaceDoesNotHoldMutableRootClose(t *testing.T) {
	root := mutableTestRoot(t)
	policy := mutableFilePolicy(Optional, 64)
	ns, err := root.AcquireRotationNamespace(context.Background(), "events", [3]string{"events", "events.1", "events.2"}, policy)
	if err != nil {
		t.Fatal(err)
	}
	file, err := ns.Create("events", rotationPolicy(policy, MustBeAbsent))
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	blockedDone := make(chan error, 1)
	go func() { blockedDone <- BlockRetainedRotationCallForTest(file, entered, release) }()
	<-entered

	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	rootDone := make(chan error, 1)
	go func() { rootDone <- root.Close() }()
	select {
	case err := <-rootDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		close(release)
		if err := <-blockedDone; err != nil {
			t.Fatalf("blocked retained call after release: %v", err)
		}
		<-rootDone
		t.Fatal("MutableRoot.Close blocked on namespace-owned retained call")
	}

	close(release)
	if err := <-blockedDone; err != nil {
		t.Fatalf("blocked retained call after root close: %v", err)
	}
	if got := ns.(*windowsRotationNamespace).op.fd; got != 0 {
		t.Fatalf("namespace root handle after admitted call = %v, want detached", got)
	}
	_ = file.Close()
}
