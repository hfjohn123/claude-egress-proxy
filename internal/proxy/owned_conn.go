package proxy

import (
	"net"
	"sync"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
)

// ownedConn binds an accepted connection to its admin admission lease. Either
// the HTTP framework or an application handoff may release it, never both.
type ownedConn struct {
	net.Conn
	lease    admission.AdminLease
	once     sync.Once
	released bool
}

func newOwnedConn(conn net.Conn, lease admission.AdminLease) *ownedConn {
	return &ownedConn{Conn: conn, lease: lease}
}
func (c *ownedConn) Release() bool {
	if c == nil {
		return false
	}
	did := false
	c.once.Do(func() { c.lease.Release(); c.released = true; did = true })
	return did
}
func (c *ownedConn) Close() error {
	if c == nil {
		return nil
	}
	err := c.Conn.Close()
	c.Release()
	return err
}
