package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

// RelayResult contains only byte totals. Relay never inspects tunneled bytes.
type RelayResult struct {
	ClientToOrigin uint64
	OriginToClient uint64
	CloseResult    contract.CloseResult
}

// Relay copies opaque bytes until either peer stops. Both connections close once
// copying finishes, releasing blocked opposite-direction reads.
func Relay(client, origin net.Conn) RelayResult {
	return RelayBuffered(client, client, origin)
}

// RelayBuffered copies an opaque tunnel while preserving bytes net/http had
// already buffered before handing the connection to the CONNECT adapter.
func RelayBuffered(client net.Conn, clientReader io.Reader, origin net.Conn) RelayResult {
	return RelayBufferedWithLimits(client, clientReader, origin, contract.V1().Idle, contract.V1().AbsoluteTunnelLifetimeDisabled)
}

// RelayBufferedWithLimits copies opaque bytes and owns both idle and absolute
// tunnel termination. Idle is refreshed only after bytes are successfully
// written to the opposite peer.
func RelayBufferedWithLimits(client net.Conn, clientReader io.Reader, origin net.Conn, idle, absolute time.Duration) RelayResult {
	if client == nil || clientReader == nil || origin == nil {
		return RelayResult{CloseResult: relayClose("io_error")}
	}
	const (
		causeClean uint32 = iota
		causeIO
		causeIdle
		causeAbsolute
	)
	var cause atomic.Uint32
	var closeOnce sync.Once
	clock := timebase.Real{}
	closeBoth := func() { closeOnce.Do(func() { _ = client.Close(); _ = origin.Close() }) }
	refreshIdle := func() {
		if idle <= 0 {
			return
		}
		deadline := clock.Now().Add(idle)
		_ = client.SetDeadline(deadline)
		_ = origin.SetDeadline(deadline)
	}
	refreshIdle()
	var absoluteTimer timebase.Timer
	absoluteDone := make(chan struct{})
	if absolute > 0 {
		absoluteTimer = clock.NewTimer(absolute)
		go func() {
			select {
			case <-absoluteTimer.C():
				cause.CompareAndSwap(causeClean, causeAbsolute)
				closeBoth()
			case <-absoluteDone:
			}
		}()
		defer func() {
			absoluteTimer.Stop()
			close(absoluteDone)
		}()
	}
	type copyResult struct {
		n      int64
		client bool
		err    error
	}
	completed := make(chan copyResult, 2)
	go func() {
		n, err := io.CopyBuffer(activityWriter{Writer: origin, activity: refreshIdle}, clientReader, make([]byte, 32<<10))
		if err != nil || !halfClose(origin) {
			closeBoth()
		}
		completed <- copyResult{n: n, client: true, err: err}
	}()
	go func() {
		n, err := io.CopyBuffer(activityWriter{Writer: client, activity: refreshIdle}, origin, make([]byte, 32<<10))
		if err != nil || !halfClose(client) {
			closeBoth()
		}
		completed <- copyResult{n: n, err: err}
	}()
	first, second := <-completed, <-completed
	closeBoth()
	for _, err := range []error{first.err, second.err} {
		if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
			continue
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			cause.CompareAndSwap(causeClean, causeIdle)
			continue
		}
		cause.CompareAndSwap(causeClean, causeIO)
	}
	result := RelayResult{CloseResult: relayCause(cause.Load())}
	if first.client {
		result.ClientToOrigin, result.OriginToClient = uint64(first.n), uint64(second.n)
		return result
	}
	result.ClientToOrigin, result.OriginToClient = uint64(second.n), uint64(first.n)
	return result
}

type activityWriter struct {
	io.Writer
	activity func()
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 && w.activity != nil {
		w.activity()
	}
	return n, err
}

func relayCause(cause uint32) contract.CloseResult {
	switch cause {
	case 1:
		return relayClose("io_error")
	case 2:
		return relayClose("idle_timeout")
	case 3:
		return relayClose("absolute_lifetime")
	default:
		return relayClose("clean")
	}
}

func relayClose(value string) contract.CloseResult {
	result, ok := contract.ParseCloseResult(value)
	if !ok {
		panic("proxy: invalid relay close result")
	}
	return result
}

func halfClose(conn net.Conn) bool {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite() == nil
	}
	return false
}
