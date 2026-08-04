//go:build linux && cep_testcontrol

package securefs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishOutputRechecksRootPermissionsBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenMutableRoot(dir, RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = r.PublishOutput(context.Background(), "proxy.pac", []byte("new"), mutableFilePolicy(Optional, 64))
	if !errors.Is(err, ErrPermissions) {
		t.Fatalf("PublishOutput error = %v", err)
	}
	if _, statErr := os.Stat(dir + "/proxy.pac"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("output was mutated: %v", statErr)
	}
}

func TestPublishOutputRejectsTempPathSwapAtCommitBoundary(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenMutableRoot(dir, RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.WriteFile(filepath.Join(dir, "proxy.pac"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithOutputCommitHookForTest(context.Background(), func() error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Type().IsRegular() && len(entry.Name()) > len(".proxy.pac..tmp") && entry.Name()[0] == '.' && entry.Name() != "proxy.pac" {
				path := filepath.Join(dir, entry.Name())
				if err := os.Rename(path, path+".saved"); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("attacker"), 0o600)
			}
		}
		return errors.New("temp not found")
	})
	_, err = r.PublishOutput(ctx, "proxy.pac", []byte("new"), mutableFilePolicy(Optional, 64))
	if !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("PublishOutput error = %v, want ErrIdentityChanged", err)
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "proxy.pac"))
	if readErr != nil || string(got) != "old" {
		t.Fatalf("target = %q, %v; want old unchanged", got, readErr)
	}
}

func TestPublishOutputReportsPublishedButNotDurableWhenCanceledAfterRename(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenMutableRoot(dir, RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = ContextWithOutputPublishedHookForTest(ctx, func() { cancel() })
	boundary, err := r.PublishOutput(ctx, "proxy.pac", []byte("new"), mutableFilePolicy(Optional, 64))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PublishOutput error = %v, want context.Canceled", err)
	}
	if boundary != (CommitBoundary{NamespacePublished: true, TargetDurable: false}) {
		t.Fatalf("PublishOutput boundary = %+v", boundary)
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "proxy.pac"))
	if readErr != nil || string(got) != "new" {
		t.Fatalf("target = %q, %v; want published new", got, readErr)
	}
}
