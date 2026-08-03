package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenRootRejectsNonCanonicalAndLinkedParents catches a path preflight that
// accepts a relative, dot-cleanable, or linked root before opening it securely.
func TestOpenRootRejectsNonCanonicalAndLinkedParents(t *testing.T) {
	base := t.TempDir()
	policy := RootPolicy{Access: IdentityOnlyPermissions()}
	for _, path := range []string{"relative", base + string(filepath.Separator) + "."} {
		if _, err := OpenRoot(path, policy); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("OpenRoot(%q) error = %v, want ErrUnsafePath", path, err)
		}
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := OpenRoot(link, policy); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenRoot(link) error = %v, want ErrUnsafePath", err)
	}
}

// TestRootReadFileBoundedOnValidatedHandle catches a read that reopens by path
// or accepts a file larger than the policy's sole maximum.
func TestRootReadFileBoundedOnValidatedHandle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("four"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(dir, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	_, _, err = root.ReadFile("secret", FilePolicy{Presence: Required, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 3})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadFile oversized error = %v, want ErrTooLarge", err)
	}
	got, state, err := root.ReadFile("secret", FilePolicy{Presence: Required, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "four" || !state.Present || state.Size != 4 || state.Identity == (Identity{}) {
		t.Fatalf("ReadFile = (%q, %+v), want validated file metadata", got, state)
	}
}

// TestRootOptionalAbsenceAndMustBeAbsent catches treating unsafe/missing final
// members as interchangeable and catches a present output being accepted.
func TestRootOptionalAbsenceAndMustBeAbsent(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	state, err := root.Inspect("missing", FilePolicy{Presence: Optional, Kind: RegularFile, Access: IdentityOnlyPermissions()})
	if err != nil || state.Present || state.Identity != (Identity{}) {
		t.Fatalf("optional missing = (%+v, %v), want safely absent", state, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "present"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = root.Inspect("present", FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions()})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("MustBeAbsent error = %v, want ErrAlreadyExists", err)
	}
}

// TestRootPinnedIdentityAndClose catches a root that silently follows a
// replacement and one that uses retained handles after Close.
func TestRootPinnedIdentityAndClose(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "root")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(path, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	first := root.Identity()
	if err := os.Remove(path); err != nil {
		root.Close()
		t.Skipf("cannot replace open root on this filesystem: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.RecheckIdentity(); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("RecheckIdentity error = %v, want ErrIdentityChanged", err)
	}
	if root.Identity() != first {
		t.Fatal("pinned identity changed")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.RecheckIdentity(); !errors.Is(err, ErrClosed) {
		t.Fatalf("RecheckIdentity after Close = %v, want ErrClosed", err)
	}
}

// TestValidateOutputExcludesCheckoutAndRetainsParent catches a preflight that
// either permits an output below checkout or drops the validated parent handle.
func TestValidateOutputExcludesCheckoutAndRetainsParent(t *testing.T) {
	base := t.TempDir()
	checkout, err := OpenRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	checkoutID := checkout.Identity()
	if err := checkout.Close(); err != nil {
		t.Fatal(err)
	}

	_, _, _, err = ValidateOutput(filepath.Join(base, "out"), checkoutID,
		RootPolicy{Access: IdentityOnlyPermissions()},
		FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions()})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("ValidateOutput below checkout error = %v, want ErrUnsafePath", err)
	}

	outside := t.TempDir()
	parent, name, state, err := ValidateOutput(filepath.Join(outside, "out"), Identity{},
		RootPolicy{Access: IdentityOnlyPermissions()},
		FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if name != "out" || state.Present {
		t.Fatalf("ValidateOutput = (%q, %+v), want retained absent parent", name, state)
	}
	if err := parent.RecheckIdentity(); err != nil {
		t.Fatalf("returned parent is not usable: %v", err)
	}
}

// TestCreateRootCreatesExactlyOneRestrictedLeaf catches a creation helper that
// follows paths or creates intermediate directories instead of one leaf.
func TestCreateRootCreatesExactlyOneRestrictedLeaf(t *testing.T) {
	base := t.TempDir()
	parent, err := OpenRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	created, err := CreateRoot(parent, "state", RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	if created.Identity() == (Identity{}) {
		t.Fatal("created root has zero identity")
	}
	if _, err := CreateRoot(parent, "state", RootPolicy{Access: IdentityOnlyPermissions()}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("CreateRoot existing leaf error = %v, want ErrAlreadyExists", err)
	}
	if _, err := CreateRoot(parent, "nested/state", RootPolicy{Access: IdentityOnlyPermissions()}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("CreateRoot nested leaf error = %v, want ErrUnsafePath", err)
	}
}
