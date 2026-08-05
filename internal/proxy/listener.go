package proxy

import (
	"net"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
)

type adminListener struct {
	net.Listener
	admission *admission.Admin
}

// NewAdminListener admits at accept time, before net/http reads any bytes.
func NewAdminListener(listener net.Listener, admissionControl *admission.Admin) net.Listener {
	return &adminListener{Listener: listener, admission: admissionControl}
}
func (l *adminListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.admission == nil {
			_ = conn.Close()
			continue
		}
		lease, decision := l.admission.Acquire()
		if !decision.Allowed() {
			_ = conn.Close()
			continue
		}
		return newOwnedConn(conn, lease), nil
	}
}
