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
	if client == nil || origin == nil {
		return RelayResult{}
	}
	var result RelayResult
	var closeOnce sync.Once
	closeBoth := func() { closeOnce.Do(func() { _ = client.Close(); _ = origin.Close() }) }
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		n, _ := io.Copy(origin, client)
		result.ClientToOrigin = uint64(n)
		closeBoth()
	}()
	go func() {
		defer wait.Done()
		n, _ := io.Copy(client, origin)
		result.OriginToClient = uint64(n)
		closeBoth()
	}()
	wait.Wait()
	return result
}
