//go:build linux && cep_testcontrol

package securefs

import (
	"context"
	"errors"
	"io/fs"
	"os"
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
