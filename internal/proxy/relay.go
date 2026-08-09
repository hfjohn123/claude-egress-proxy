package proxy

import (
	"io"
	"net"
	"sync"
)

// RelayResult contains only byte totals. Relay never inspects tunneled bytes.
type RelayResult struct {
	ClientToOrigin uint64
	OriginToClient uint64
}

// Relay copies opaque bytes until either peer stops. Both connections close once
// copying finishes, releasing blocked opposite-direction reads.
func Relay(client, origin net.Conn) RelayResult {
	return RelayBuffered(client, client, origin)
}

// RelayBuffered copies an opaque tunnel while preserving bytes net/http had
// already buffered before handing the connection to the CONNECT adapter.
func RelayBuffered(client net.Conn, clientReader io.Reader, origin net.Conn) RelayResult {
	if client == nil || clientReader == nil || origin == nil {
		return RelayResult{}
	}
	var closeOnce sync.Once
	closeBoth := func() { closeOnce.Do(func() { _ = client.Close(); _ = origin.Close() }) }
	type copyResult struct {
		n      int64
		client bool
	}
	completed := make(chan copyResult, 2)
	go func() {
		n, err := io.Copy(origin, clientReader)
		if err != nil || !halfClose(origin) {
			closeBoth()
		}
		completed <- copyResult{n: n, client: true}
	}()
	go func() {
		n, err := io.Copy(client, origin)
		if err != nil || !halfClose(client) {
			closeBoth()
		}
		completed <- copyResult{n: n}
	}()
	first, second := <-completed, <-completed
	closeBoth()
	if first.client {
		return RelayResult{ClientToOrigin: uint64(first.n), OriginToClient: uint64(second.n)}
	}
	return RelayResult{ClientToOrigin: uint64(second.n), OriginToClient: uint64(first.n)}
}

func halfClose(conn net.Conn) bool {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite() == nil
	}
	return false
}
