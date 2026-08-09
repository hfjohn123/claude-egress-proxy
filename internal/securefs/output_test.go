//go:build cep_testcontrol

package securefs

import (
	"context"
	"sync"
	"testing"
)

func TestPublishOutputLeavesCompleteTargetWithoutSibling(t *testing.T) {
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 64)
	if _, err := r.PublishOutput(context.Background(), "proxy.pac", []byte("new"), p); err != nil {
		t.Fatal(err)
	}
	b, _, err := r.ReadFile("proxy.pac", FilePolicy{Presence: Required, Kind: RegularFile, Access: p.Access, MaxBytes: p.MaxBytes})
	if err != nil || string(b) != "new" {
		t.Fatalf("output = %q, %v", b, err)
	}
}

func TestPublishOutputConcurrentWritersLeaveCompleteBody(t *testing.T) {
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 64)
	if _, err := r.PublishOutput(context.Background(), "proxy.pac", []byte("old"), p); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, body := range [][]byte{[]byte("first"), []byte("second")} {
		wg.Add(1)
		go func(body []byte) { defer wg.Done(); _, _ = r.PublishOutput(context.Background(), "proxy.pac", body, p) }(body)
	}
	wg.Wait()
	b, _, err := r.ReadFile("proxy.pac", FilePolicy{Presence: Required, Kind: RegularFile, Access: p.Access, MaxBytes: p.MaxBytes})
	if err != nil || (string(b) != "first" && string(b) != "second") {
		t.Fatalf("output=%q err=%v", b, err)
	}
}
