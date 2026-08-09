package telemetry

import "io"

type streamSink struct{ writer io.Writer }

// NewStreamSink creates a sink that appends one line feed to each record.
func NewStreamSink(w io.Writer) (Sink, error) {
	if w == nil {
		return nil, ErrInvalidSink
	}
	return &streamSink{writer: w}, nil
}

func (s *streamSink) WriteRecord(json []byte) error {
	if len(json) < 1 || len(json) > 2047 || containsInvalidStreamByte(json) {
		return ErrInvalidSink
	}
	line := make([]byte, len(json)+1)
	copy(line, json)
	line[len(json)] = '\n'
	n, err := s.writer.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return nil
}

func (s *streamSink) Close() error { return nil }

func containsInvalidStreamByte(json []byte) bool {
	for i, b := range json {
		if b == '\r' || b == '\n' || b == 0xef && i+2 < len(json) && json[i+1] == 0xbb && json[i+2] == 0xbf {
			return true
		}
	}
	return false
}
