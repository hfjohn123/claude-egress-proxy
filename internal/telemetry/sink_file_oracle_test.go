package telemetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestFileSinkRotationOracle512BytesThrough61441Records(t *testing.T) {
	first := oracleRecord(t, 0)
	if len(first) != 512 || first[len(first)-1] != '\n' {
		t.Fatalf("oracle length = %d, want 512 including LF", len(first))
	}
	root := newFakeFileSinkRoot("events")
	sink, err := OpenFileSink(context.Background(), root, "events", fakeFileSinkPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20_480; i++ {
		if err := sink.WriteRecord(oracleRecord(t, i)[:511]); err != nil {
			t.Fatalf("record %d: %v", i+1, err)
		}
	}
	if root.ns.rotations != 0 || int64(len(root.ns.member("events").data)) != fileSinkMemberBytes {
		t.Fatalf("filled active rotations=%d bytes=%d", root.ns.rotations, len(root.ns.member("events").data))
	}
	if err := sink.WriteRecord(oracleRecord(t, 20_480)[:511]); err != nil {
		t.Fatal(err)
	}
	if root.ns.rotations != 1 || !bytes.Equal(root.ns.member("events").data, oracleRecord(t, 20_480)) || !bytes.Equal(root.ns.member("events.1").data[:512], oracleRecord(t, 0)) {
		t.Fatal("20,481st record did not rotate before writing")
	}
	for i := 20_481; i < 61_441; i++ {
		if err := sink.WriteRecord(oracleRecord(t, i)[:511]); err != nil {
			t.Fatalf("record %d: %v", i+1, err)
		}
	}
	if root.ns.rotations != 3 {
		t.Fatalf("rotations = %d, want 3", root.ns.rotations)
	}
	assertFakeGeneration(t, root.ns.member("events").data, oracleRecord(t, 61_440), 1)
	assertFakeGeneration(t, root.ns.member("events.1").data, oracleRecord(t, 40_960), 20_480)
	assertFakeGeneration(t, root.ns.member("events.2").data, oracleRecord(t, 20_480), 20_480)
	if bytes.Contains(root.ns.member("events.2").data, oracleRecord(t, 0)) {
		t.Fatal("oldest generation survived fourth active interval")
	}
}

func TestValidateFileSinkRejectsFourthGeneration(t *testing.T) {
	root := newFakeFileSinkRoot("events")
	root.ns.files["events.3"] = &fakeEntry{attached: true}
	err := ValidateFileSink(context.Background(), root, "events", fakeFileSinkPolicy(), CheckOnly)
	if !errors.Is(err, ErrInvalidFileSink) {
		t.Fatalf("ValidateFileSink = %v, want ErrInvalidFileSink", err)
	}
}

func TestValidateFileSinkStartupMatrixAndBounds(t *testing.T) {
	line := oracleRecord(t, 0)
	permitted := [][3]bool{{}, {true, false, false}, {true, true, false}, {true, false, true}, {true, true, true}, {false, true, false}, {false, true, true}}
	for _, present := range permitted {
		t.Run(fmt.Sprintf("permitted-%v", present), func(t *testing.T) {
			root := newFakeFileSinkRoot("events")
			setFakeGeneration(root.ns, present, line)
			if err := ValidateFileSink(context.Background(), root, "events", fakeFileSinkPolicy(), CheckOnly); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, present := range [][3]bool{{false, false, true}} {
		t.Run(fmt.Sprintf("rejected-%v", present), func(t *testing.T) {
			root := newFakeFileSinkRoot("events")
			setFakeGeneration(root.ns, present, line)
			if err := ValidateFileSink(context.Background(), root, "events", fakeFileSinkPolicy(), CheckOnly); !errors.Is(err, ErrInvalidFileSink) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for _, test := range []struct {
		name      string
		configure func(*fakeFileSinkRoot)
		want      error
	}{
		{"canonical-tail", func(r *fakeFileSinkRoot) { r.ns.files["events"] = &fakeEntry{data: line[:511], attached: true} }, ErrRepairRequired},
		{"no-lf-window-overflow", func(r *fakeFileSinkRoot) {
			r.ns.files["events"] = &fakeEntry{data: bytes.Repeat([]byte("x"), 2048), attached: true}
		}, ErrInvalidFileSink},
		{"corrupt-backup", func(r *fakeFileSinkRoot) {
			r.ns.files["events.1"] = &fakeEntry{data: []byte("not-json\n"), attached: true}
		}, ErrInvalidFileSink},
		{"oversized-member", func(r *fakeFileSinkRoot) {
			r.ns.files["events"] = &fakeEntry{data: make([]byte, fileSinkMemberBytes+1), attached: true}
		}, ErrInvalidFileSink},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := newFakeFileSinkRoot("events")
			test.configure(root)
			if err := ValidateFileSink(context.Background(), root, "events", fakeFileSinkPolicy(), CheckOnly); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	root := newFakeFileSinkRoot("events")
	full := bytes.Repeat(line, 20_480)
	setFakeGeneration(root.ns, [3]bool{true, true, true}, full)
	if err := ValidateFileSink(context.Background(), root, "events", fakeFileSinkPolicy(), CheckOnly); err != nil {
		t.Fatalf("exact 30 MiB = %v", err)
	}
}

func TestValidActiveLinesTailWindowBoundary(t *testing.T) {
	prefix := oracleRecord(t, 0)
	for _, test := range []struct {
		suffix int
		repair bool
		ok     bool
	}{{2047, true, true}, {2048, false, false}} {
		data := append(append([]byte(nil), prefix...), bytes.Repeat([]byte("x"), test.suffix)...)
		repair, ok := validActiveLines(data)
		if repair != test.repair || ok != test.ok {
			t.Fatalf("suffix %d: validActiveLines = (%v, %v), want (%v, %v)", test.suffix, repair, ok, test.repair, test.ok)
		}
	}
}

func setFakeGeneration(n *fakeRotationNamespace, present [3]bool, data []byte) {
	for i, name := range []string{n.base, n.base + ".1", n.base + ".2"} {
		if present[i] {
			n.files[name] = &fakeEntry{data: append([]byte(nil), data...), attached: true}
		}
	}
}

func TestOpenFileSinkRepairsOnlyCanonicalTailAndTombstone(t *testing.T) {
	line := oracleRecord(t, 0)
	root := newFakeFileSinkRoot("events")
	root.ns.files["events"] = &fakeEntry{data: append([]byte(nil), line[:511]...), attached: true}
	root.ns.files["events.delete"] = &fakeEntry{data: []byte("discarded"), attached: true}
	sink, err := OpenFileSink(context.Background(), root, "events", fakeFileSinkPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if got := root.ns.member("events").data; len(got) != 0 {
		t.Fatalf("active repair bytes=%d, want 0", len(got))
	}
	if got := root.ns.member("events.delete").data; len(got) != 0 {
		t.Fatalf("tombstone repair bytes=%d, want 0", len(got))
	}
}

func TestFileSinkValidationFaultsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*fakeFileSinkRoot)
		open      bool
	}{
		{"check-recheck", func(r *fakeFileSinkRoot) { r.recheck = errors.New("recheck") }, false},
		{"check-inspect", func(r *fakeFileSinkRoot) { r.inspect = errors.New("inspect") }, false},
		{"check-read", func(r *fakeFileSinkRoot) {
			r.read = errors.New("read")
			r.ns.files["events"] = &fakeEntry{data: oracleRecord(t, 0), attached: true}
		}, false},
		{"open-acquire", func(r *fakeFileSinkRoot) { r.acquire = errors.New("acquire") }, true},
		{"open-namespace-inspect", func(r *fakeFileSinkRoot) { r.ns.inspectErr = errors.New("inspect") }, true},
		{"open-namespace-read", func(r *fakeFileSinkRoot) {
			r.ns.files["events"] = &fakeEntry{data: oracleRecord(t, 0), attached: true}
			r.ns.readErr = errors.New("read")
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := newFakeFileSinkRoot("events")
			test.configure(root)
			if test.open {
				if _, err := OpenFileSink(context.Background(), root, "events", fakeFileSinkPolicy()); !errors.Is(err, ErrInvalidFileSink) {
					t.Fatalf("OpenFileSink = %v", err)
				}
				return
			}
			if err := ValidateFileSink(context.Background(), root, "events", fakeFileSinkPolicy(), CheckOnly); !errors.Is(err, ErrInvalidFileSink) {
				t.Fatalf("ValidateFileSink = %v", err)
			}
		})
	}
}

func TestFileSinkFaultsPermanentlyFailAndRollbackOwnedHandle(t *testing.T) {
	line := oracleRecord(t, 0)[:511]
	for _, test := range []struct {
		name         string
		configure    func(*fakeRotationNamespace, *fakeRetainedFile)
		wantRollback bool
	}{
		{"recheck", func(_ *fakeRotationNamespace, f *fakeRetainedFile) { f.recheck = errors.New("recheck") }, false},
		{"size", func(_ *fakeRotationNamespace, f *fakeRetainedFile) { f.sizeErr = errors.New("size") }, false},
		{"close", func(_ *fakeRotationNamespace, f *fakeRetainedFile) {
			f.entry.data = make([]byte, fileSinkMemberBytes)
			f.closeErr = errors.New("close")
		}, false},
		{"rotate", func(n *fakeRotationNamespace, f *fakeRetainedFile) {
			f.entry.data = make([]byte, fileSinkMemberBytes)
			n.rotateErr = errors.New("rotate")
		}, false},
		{"delete", func(n *fakeRotationNamespace, f *fakeRetainedFile) {
			f.entry.data = make([]byte, fileSinkMemberBytes)
			n.deleteErr = errors.New("delete")
		}, false},
		{"rename", func(n *fakeRotationNamespace, f *fakeRetainedFile) {
			f.entry.data = make([]byte, fileSinkMemberBytes)
			n.renameErr = errors.New("rename")
		}, false},
		{"partial", func(_ *fakeRotationNamespace, f *fakeRetainedFile) { f.writeN = 1 }, true},
		{"write", func(_ *fakeRotationNamespace, f *fakeRetainedFile) { f.writeErr = errors.New("write") }, true},
		{"partial-truncate", func(_ *fakeRotationNamespace, f *fakeRetainedFile) {
			f.writeN, f.writeErr, f.truncateErr = 1, errors.New("write"), errors.New("truncate")
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := newFakeFileSinkRoot("events")
			sink, err := OpenFileSink(context.Background(), root, "events", fakeFileSinkPolicy())
			if err != nil {
				t.Fatal(err)
			}
			f := root.ns.last
			test.configure(root.ns, f)
			err = sink.WriteRecord(line)
			if err == nil || sink.WriteRecord(line) != err || !root.ns.closed {
				t.Fatalf("permanent failure err=%v second=%v closed=%v", err, sink.WriteRecord(line), root.ns.closed)
			}
			if test.wantRollback && len(f.entry.data) != 0 {
				t.Fatalf("rollback bytes=%d", len(f.entry.data))
			}
		})
	}
	for _, test := range []struct {
		name      string
		configure func(*fakeRotationNamespace)
	}{
		{"create", func(n *fakeRotationNamespace) { n.createErr = errors.New("create") }},
		{"repair", func(n *fakeRotationNamespace) { n.repairErr = errors.New("repair") }},
		{"open", func(n *fakeRotationNamespace) {
			n.files["events"] = &fakeEntry{attached: true}
			n.openErr = errors.New("open")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := newFakeFileSinkRoot("events")
			test.configure(root.ns)
			if _, err := OpenFileSink(context.Background(), root, "events", fakeFileSinkPolicy()); !errors.Is(err, ErrInvalidFileSink) {
				t.Fatalf("OpenFileSink = %v", err)
			}
		})
	}
	root := newFakeFileSinkRoot("events")
	sink, err := OpenFileSink(context.Background(), root, "events", fakeFileSinkPolicy())
	if err != nil {
		t.Fatal(err)
	}
	f := root.ns.last
	f.entry.data = append(f.entry.data, line...)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	fs := sink.(*fileSink)
	fs.rollbackOwned(f, 0)
	if len(f.entry.data) != len(line) || f.truncates != 0 {
		t.Fatal("Close did not detach rollback ownership")
	}
}

func assertFakeGeneration(t *testing.T, got, first []byte, records int) {
	t.Helper()
	if len(got) != records*512 || !bytes.Equal(got[:512], first) {
		t.Fatalf("generation records=%d bytes=%d first=%q", records, len(got), got[:min(32, len(got))])
	}
}

func oracleRecord(t *testing.T, sequence int) []byte {
	t.Helper()
	key := strconv.Itoa(len(strconv.Itoa(sequence))) + "/" + strconv.Itoa(len(strconv.Itoa(sequence+1)))
	hostLen, ok := oracleHostLengths[key]
	if !ok {
		max := 0
		for n := 1; n <= 253; n++ {
			if got := oracleJSON(t, sequence, n); len(got) == 511 {
				hostLen, ok = n, true
				break
			} else if len(got) > max {
				max = len(got)
			}
		}
		if !ok {
			t.Fatalf("no 511-byte canonical oracle record (max=%d)", max)
		}
		oracleHostLengths[key] = hostLen
	}
	return append(oracleJSON(t, sequence, hostLen), '\n')
}

var oracleHostLengths = map[string]int{}

func oracleJSON(t *testing.T, sequence, hostLen int) []byte {
	t.Helper()
	s := SensitiveMetadata{DestinationHostname: oracleHost(hostLen), DeviceIdentifier: strings.Repeat("d", 64), SourcePrefix: netip.MustParsePrefix("2001:db8::/64"), DurationMillis: uint64(sequence), Bytes: contract.ByteTotals{ClientToOrigin: uint64(sequence), OriginToClient: uint64(sequence + 1)}}
	r, err := TunnelClosed(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(sequence)*time.Second), mustCloseResult(t, "clean"), &s)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(r.JSON())
}

func oracleHost(n int) string {
	if n <= 63 {
		return strings.Repeat("a", n)
	}
	first := min(63, n-2)
	return strings.Repeat("a", first) + "." + oracleHost(n-first-1)
}

func fakeFileSinkPolicy() securefs.FilePolicy {
	return securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: securefs.LinuxExactPermissions(1, 0o600), MaxBytes: fileSinkMemberBytes}
}

type fakeFileSinkRoot struct {
	ns      *fakeRotationNamespace
	recheck error
	inspect error
	read    error
	acquire error
	closed  bool
	mutated bool
}

func newFakeFileSinkRoot(base string) *fakeFileSinkRoot {
	ns := &fakeRotationNamespace{base: base, files: map[string]*fakeEntry{}}
	return &fakeFileSinkRoot{ns: ns}
}
func (r *fakeFileSinkRoot) Identity() securefs.Identity { return securefs.Identity{} }
func (r *fakeFileSinkRoot) RecheckIdentity() error      { return r.recheck }
func (r *fakeFileSinkRoot) Inspect(name string, p securefs.FilePolicy) (securefs.FileState, error) {
	if r.inspect != nil {
		return securefs.FileState{}, r.inspect
	}
	return r.ns.inspect(name, p)
}
func (r *fakeFileSinkRoot) ReadFile(name string, p securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	if r.read != nil {
		return nil, securefs.FileState{}, r.read
	}
	return r.ns.readFile(name, p)
}
func (r *fakeFileSinkRoot) Close() error { r.closed = true; return nil }
func (r *fakeFileSinkRoot) PublishOutput(context.Context, string, []byte, securefs.FilePolicy) (securefs.CommitBoundary, error) {
	return securefs.CommitBoundary{}, errors.New("unused")
}
func (r *fakeFileSinkRoot) WithExclusiveLock(context.Context, string, securefs.FilePolicy, func(securefs.LockedFile) error) error {
	return errors.New("unused")
}
func (r *fakeFileSinkRoot) AcquireRotationNamespace(context.Context, string, [3]string, securefs.FilePolicy) (securefs.RotationNamespace, error) {
	if r.acquire != nil {
		return nil, r.acquire
	}
	return r.ns, nil
}

type fakeRotationNamespace struct {
	base                                                                                         string
	mu                                                                                           sync.Mutex
	files                                                                                        map[string]*fakeEntry
	rotations                                                                                    int
	closed                                                                                       bool
	recheck, inspectErr, readErr, repairErr, openErr, createErr, rotateErr, deleteErr, renameErr error
	last                                                                                         *fakeRetainedFile
}
type fakeEntry struct {
	data     []byte
	attached bool
}

func (n *fakeRotationNamespace) member(name string) *fakeEntry { return n.files[name] }
func (n *fakeRotationNamespace) RecheckIdentity() error        { return n.recheck }
func (n *fakeRotationNamespace) RepairTombstone() error {
	if n.repairErr != nil {
		return n.repairErr
	}
	if tomb := n.files[n.base+".delete"]; tomb != nil && tomb.attached {
		tomb.data = nil
	}
	return nil
}
func (n *fakeRotationNamespace) Inspect(name string, p securefs.FilePolicy) (securefs.FileState, error) {
	if n.inspectErr != nil {
		return securefs.FileState{}, n.inspectErr
	}
	return n.inspect(name, p)
}
func (n *fakeRotationNamespace) inspect(name string, p securefs.FilePolicy) (securefs.FileState, error) {
	e := n.files[name]
	if e == nil || !e.attached {
		return securefs.FileState{Kind: p.Kind}, nil
	}
	if p.Presence == securefs.MustBeAbsent {
		return securefs.FileState{}, securefs.ErrAlreadyExists
	}
	return securefs.FileState{Present: true, Kind: securefs.RegularFile, Size: int64(len(e.data)), ModTime: time.Unix(0, 0)}, nil
}
func (n *fakeRotationNamespace) ReadFile(name string, p securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	if n.readErr != nil {
		return nil, securefs.FileState{}, n.readErr
	}
	return n.readFile(name, p)
}
func (n *fakeRotationNamespace) readFile(name string, p securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	s, err := n.inspect(name, p)
	if err != nil || !s.Present {
		return nil, s, err
	}
	e := n.files[name]
	if p.MaxBytes > 0 && int64(len(e.data)) > p.MaxBytes {
		return nil, securefs.FileState{}, securefs.ErrTooLarge
	}
	return append([]byte(nil), e.data...), s, nil
}
func (n *fakeRotationNamespace) Open(name string, p securefs.FilePolicy) (securefs.RetainedFile, error) {
	if n.openErr != nil {
		return nil, n.openErr
	}
	e := n.files[name]
	if e == nil || !e.attached {
		return nil, securefs.ErrNotFound
	}
	f := &fakeRetainedFile{entry: e}
	n.last = f
	return f, nil
}
func (n *fakeRotationNamespace) Create(name string, p securefs.FilePolicy) (securefs.RetainedFile, error) {
	if n.createErr != nil {
		return nil, n.createErr
	}
	if e := n.files[name]; e != nil && e.attached {
		return nil, securefs.ErrAlreadyExists
	}
	e := &fakeEntry{attached: true}
	n.files[name] = e
	f := &fakeRetainedFile{entry: e}
	n.last = f
	return f, nil
}
func (n *fakeRotationNamespace) Rotate(leaves [3]string, _ [3]securefs.Identity) (securefs.RetainedFile, error) {
	if n.rotateErr != nil {
		return nil, n.rotateErr
	}
	if n.deleteErr != nil {
		return nil, n.deleteErr
	}
	if n.renameErr != nil {
		return nil, n.renameErr
	}
	active, one, two := n.files[leaves[0]], n.files[leaves[1]], n.files[leaves[2]]
	if active == nil || one == nil || two == nil {
		return nil, securefs.ErrNotFound
	}
	two.attached = false
	n.files[leaves[2]] = one
	n.files[leaves[1]] = active
	next := &fakeEntry{attached: true}
	n.files[leaves[0]] = next
	n.rotations++
	f := &fakeRetainedFile{entry: next}
	n.last = f
	return f, nil
}
func (n *fakeRotationNamespace) Close() error { n.closed = true; return nil }

type fakeRetainedFile struct {
	mu                                                sync.Mutex
	entry                                             *fakeEntry
	closed                                            bool
	recheck, sizeErr, writeErr, truncateErr, closeErr error
	writeN                                            int
	truncates                                         int
}

func (*fakeRetainedFile) Identity() securefs.Identity { return securefs.Identity{} }
func (f *fakeRetainedFile) RecheckIdentity() error    { return f.recheck }
func (f *fakeRetainedFile) Size() (int64, error) {
	if f.sizeErr != nil {
		return 0, f.sizeErr
	}
	return int64(len(f.entry.data)), nil
}
func (f *fakeRetainedFile) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(f.entry.data)) {
		return 0, io.EOF
	}
	return copy(b, f.entry.data[off:]), nil
}
func (f *fakeRetainedFile) WriteAt(b []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, securefs.ErrClosed
	}
	n := len(b)
	if f.writeN > 0 && f.writeN < n {
		n = f.writeN
	}
	end := int(off) + n
	if end > len(f.entry.data) {
		f.entry.data = append(f.entry.data, make([]byte, end-len(f.entry.data))...)
	}
	copy(f.entry.data[off:], b[:n])
	return n, f.writeErr
}
func (f *fakeRetainedFile) Truncate(size int64) error {
	f.truncates++
	if f.truncateErr != nil {
		return f.truncateErr
	}
	f.entry.data = f.entry.data[:size]
	return nil
}
func (f *fakeRetainedFile) Close() error { f.closed = true; return f.closeErr }
