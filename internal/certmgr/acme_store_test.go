package certmgr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestACMEStoreAbsenceIsSafe(t *testing.T) {
	store := ACMEStore{Path: filepath.Join(t.TempDir(), "acme.json")}
	_, err := store.Load()
	if !errors.Is(err, ErrACMEStateAbsent) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestACMEStoreUsesPinnedSecureRootForReadAndPublish(t *testing.T) {
	policy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: securefs.LinuxExactPermissions(65532, 0o600), MaxBytes: maxACMEStateBytes}
	root := &fakeACMERoot{}
	store := ACMEStore{Root: root, Mutable: root, Name: "acme.json", Policy: policy}
	want := ACMEState{AccountKeyPEM: []byte("account"), CertificatePEM: []byte("certificate"), PrivateKeyPEM: []byte("key")}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || string(got.PrivateKeyPEM) != "key" {
		t.Fatalf("state=%#v err=%v", got, err)
	}
	if root.publishedName != "acme.json" || !securefs.PermissionsEqual(root.publishedPolicy.Access, policy.Access) || !root.rechecked {
		t.Fatalf("publish name=%q policy=%+v rechecked=%v", root.publishedName, root.publishedPolicy, root.rechecked)
	}
}

type fakeACMERoot struct {
	data            []byte
	rechecked       bool
	publishedName   string
	publishedPolicy securefs.FilePolicy
}

func (*fakeACMERoot) Identity() securefs.Identity { return securefs.Identity{} }
func (r *fakeACMERoot) RecheckIdentity() error    { r.rechecked = true; return nil }
func (r *fakeACMERoot) Inspect(_ string, policy securefs.FilePolicy) (securefs.FileState, error) {
	if len(r.data) == 0 {
		return securefs.FileState{}, nil
	}
	return securefs.FileState{Present: true, Kind: securefs.RegularFile, Size: int64(len(r.data)), ModTime: time.Unix(1, 0)}, nil
}
func (r *fakeACMERoot) ReadFile(_ string, _ securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	return append([]byte(nil), r.data...), securefs.FileState{Present: true, Kind: securefs.RegularFile, Size: int64(len(r.data)), ModTime: time.Unix(1, 0)}, nil
}
func (*fakeACMERoot) Close() error { return nil }
func (r *fakeACMERoot) PublishOutput(_ context.Context, name string, data []byte, policy securefs.FilePolicy) (securefs.CommitBoundary, error) {
	r.rechecked = true
	r.publishedName, r.publishedPolicy = name, policy
	r.data = append([]byte(nil), data...)
	return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
}
func (*fakeACMERoot) WithExclusiveLock(context.Context, string, securefs.FilePolicy, func(securefs.LockedFile) error) error {
	return errors.New("unused")
}
func (*fakeACMERoot) AcquireRotationNamespace(context.Context, string, [3]string, securefs.FilePolicy) (securefs.RotationNamespace, error) {
	return nil, errors.New("unused")
}

func TestACMEStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme.json")
	store := ACMEStore{Path: path}
	want := ACMEState{AccountKeyPEM: []byte("account"), CertificatePEM: []byte("certificate"), PrivateKeyPEM: []byte("key")}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if string(got.CertificatePEM) != string(want.CertificatePEM) || string(got.AccountKeyPEM) != string(want.AccountKeyPEM) {
		t.Fatalf("state = %#v", got)
	}
	if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("mode = %v, err = %v", info.Mode(), err)
	}
}
