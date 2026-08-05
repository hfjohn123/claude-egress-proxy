package certmgr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestACMEStoreAbsenceIsSafe(t *testing.T) {
	store := ACMEStore{Path: filepath.Join(t.TempDir(), "acme.json")}
	_, err := store.Load()
	if !errors.Is(err, ErrACMEStateAbsent) {
		t.Fatalf("Load error = %v", err)
	}
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
