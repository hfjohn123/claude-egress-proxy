// Package check owns standalone, non-mutating operator probes.
package check

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

var (
	ErrInvalidHealthAddress = errors.New("invalid health address")
	ErrHealthProbe          = errors.New("health probe failed")
)

const healthRequest = "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
const healthResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"

// Health performs the config-independent loopback liveness probe.
func Health(ctx context.Context, address string) error {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || endpoint.Port() == 0 || endpoint.String() != address || endpoint.Addr().Zone() != "" ||
		(endpoint.Addr() != netip.MustParseAddr("127.0.0.1") && endpoint.Addr() != netip.MustParseAddr("::1")) {
		return ErrInvalidHealthAddress
	}
	if ctx == nil {
		return ErrHealthProbe
	}
	probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	network := "tcp4"
	if endpoint.Addr().Is6() {
		network = "tcp6"
	}
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(probeContext, network, address)
	if err != nil {
		return ErrHealthProbe
	}
	defer connection.Close()
	if err := connection.SetDeadline(timebase.Real{}.Now().Add(2 * time.Second)); err != nil {
		return ErrHealthProbe
	}
	if _, err := io.WriteString(connection, healthRequest); err != nil {
		return ErrHealthProbe
	}
	response, err := io.ReadAll(io.LimitReader(connection, (4<<10)+17))
	if err != nil || !bytes.Equal(response, []byte(healthResponse)) {
		return ErrHealthProbe
	}
	return nil
}
