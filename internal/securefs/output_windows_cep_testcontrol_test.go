//go:build windows && cep_testcontrol

package securefs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishOutputRejectsWindowsTempAndTargetSwapsAtCommitBoundary(t *testing.T) {
	r := mutableTestRoot(t)
	dir, ok := mutablePathForTest.Load(r)
	if !ok {
		t.Fatal("missing test root path")
	}
	path := dir.(string)
	ctx := ContextWithWindowsOutputCommitHookForTest(context.Background(), func() error {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Type().IsRegular() && entry.Name()[0] == '.' {
				temp := filepath.Join(path, entry.Name())
				if err := os.Rename(temp, temp+".saved"); err != nil {
					return err
				}
				return os.WriteFile(temp, []byte("attacker"), 0o600)
			}
		}
		return errors.New("temp not found")
	})
	_, err := r.PublishOutput(ctx, "proxy.pac", []byte("new"), mutableFilePolicy(Optional, 64))
	if !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("PublishOutput error = %v, want ErrIdentityChanged", err)
	}
	if _, statErr := os.Stat(filepath.Join(path, "proxy.pac")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("target was published: %v", statErr)
	}
}

func TestPublishOutputRejectsWindowsTargetSwapAtCommitBoundary(t *testing.T) {
	r := mutableTestRoot(t)
	dir, ok := mutablePathForTest.Load(r)
	if !ok {
		t.Fatal("missing test root path")
	}
	path := dir.(string)
	target := filepath.Join(path, "proxy.pac")
	if _, err := r.PublishOutput(context.Background(), "proxy.pac", []byte("old"), mutableFilePolicy(Optional, 64)); err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithWindowsOutputCommitHookForTest(context.Background(), func() error {
		if err := os.Rename(target, target+".saved"); err != nil {
			return err
		}
		return os.WriteFile(target, []byte("attacker"), 0o600)
	})
	_, err := r.PublishOutput(ctx, "proxy.pac", []byte("new"), mutableFilePolicy(Optional, 64))
	if !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("PublishOutput error = %v, want ErrIdentityChanged", err)
	}
	got, readErr := os.ReadFile(target + ".saved")
	if readErr != nil || string(got) != "old" {
		t.Fatalf("validated target = %q, %v; want old unchanged", got, readErr)
	}
}

func TestPublishOutputWindowsReplacesValidatedTarget(t *testing.T) {
	r := mutableTestRoot(t)
	dir, ok := mutablePathForTest.Load(r)
	if !ok {
		t.Fatal("missing test root path")
	}
	path := dir.(string)
	p := mutableFilePolicy(Optional, 64)
	if _, err := r.PublishOutput(context.Background(), "proxy.pac", []byte("old"), p); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PublishOutput(context.Background(), "proxy.pac", []byte("new"), p); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(path, "proxy.pac"))
	if err != nil || string(got) != "new" {
		t.Fatalf("target = %q, %v; want new", got, err)
	}
}
