package telemetry

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

type recordingWriter struct {
	mu     sync.Mutex
	writes [][]byte
	n      int
	err    error
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, append([]byte(nil), p...))
	if w.n != 0 || w.err != nil {
		return w.n, w.err
	}
	return len(p), nil
}

func (w *recordingWriter) calls() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.writes)
}

func TestNewStreamSinkRejectsNilWriter(t *testing.T) {
	if got, err := NewStreamSink(nil); got != nil || !errors.Is(err, ErrInvalidSink) {
		t.Fatalf("NewStreamSink(nil) = (%v, %v), want (nil, ErrInvalidSink)", got, err)
	}
}

func TestStreamSinkWritesOneCopiedLineAtBoundaries(t *testing.T) {
	for _, json := range [][]byte{[]byte("0"), []byte(strings.Repeat("x", 2047))} {
		t.Run(string(json[:1]), func(t *testing.T) {
			w := &recordingWriter{}
			sink, err := NewStreamSink(w)
			if err != nil {
				t.Fatal(err)
			}
			original := append([]byte(nil), json...)
			if err := sink.WriteRecord(json); err != nil {
				t.Fatal(err)
			}
			if w.calls() != 1 {
				t.Fatalf("writes = %d, want 1", w.calls())
			}
			if got, want := w.writes[0], append(original, '\n'); !bytes.Equal(got, want) {
				t.Fatalf("write = %q, want %q", got, want)
			}
			json[0] = '!'
			if !bytes.Equal(w.writes[0], append(original, '\n')) {
				t.Fatal("writer retained caller input")
			}
		})
	}
}

func TestStreamSinkRejectsInvalidFramingWithoutWrite(t *testing.T) {
	for _, json := range [][]byte{nil, {}, []byte(strings.Repeat("x", 2048)), []byte("\xef\xbb\xbf{}"), []byte("{}\r"), []byte("{}\n")} {
		w := &recordingWriter{}
		sink, err := NewStreamSink(w)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.WriteRecord(json); !errors.Is(err, ErrInvalidSink) {
			t.Fatalf("WriteRecord(%q) error = %v, want ErrInvalidSink", json, err)
		}
		if w.calls() != 0 {
			t.Fatalf("invalid input wrote %d times", w.calls())
		}
	}
}

func TestStreamSinkConvertsShortAndInvalidWritesToTerminalErrors(t *testing.T) {
	writerErr := errors.New("writer failed")
	for _, tc := range []struct {
		name string
		n    int
		err  error
		want error
	}{
		{"short nil", 1, nil, io.ErrShortWrite},
		{"short error", 1, writerErr, writerErr},
		{"invalid negative", -1, nil, io.ErrShortWrite},
		{"invalid large", 99, nil, io.ErrShortWrite},
		{"full error", 3, writerErr, writerErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &recordingWriter{n: tc.n, err: tc.err}
			sink, _ := NewStreamSink(w)
			if err := sink.WriteRecord([]byte("{}")); !errors.Is(err, tc.want) {
				t.Fatalf("WriteRecord error = %v, want %v", err, tc.want)
			}
			if w.calls() != 1 {
				t.Fatalf("writes = %d, want 1", w.calls())
			}
		})
	}
}

func TestStreamSinkCloseIsConcurrentNoOp(t *testing.T) {
	w := &recordingWriter{}
	sink, err := NewStreamSink(w)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := sink.Close(); err != nil {
				t.Errorf("Close() = %v", err)
			}
		}()
	}
	group.Wait()
	if err := sink.WriteRecord([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if w.calls() != 1 {
		t.Fatalf("writes = %d, want 1", w.calls())
	}
}
