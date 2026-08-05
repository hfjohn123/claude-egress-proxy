package proxy

import (
	"errors"
	"net/http"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

var errHijackOwnership = errors.New("proxy: hijack ownership mismatch")

// WriteFixedResponse transfers an admitted request to a one-response handoff.
// The framework's owner remains the sole close/release authority on failure.
func WriteFixedResponse(w http.ResponseWriter, r *http.Request, c *session.Coordinator, frame wire.Frame, body []byte) (err error) {
	owner, ok := wire.ConnectionOwner(r)
	if !ok || c == nil {
		return errHijackOwnership
	}
	h, ok := c.BeginFixed(owner)
	if !ok {
		return errHijackOwnership
	}
	defer func() {
		if recover() != nil {
			_ = owner.Close()
			err = errHijackOwnership
		}
	}()
	hj, ok := w.(http.Hijacker)
	if !ok {
		h.Release()
		return errors.New("proxy: hijack unsupported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		h.Release()
		return err
	}
	if conn != owner {
		_ = conn.Close()
		h.Release()
		return errHijackOwnership
	}
	if err := h.Attach(conn, rw); err != nil {
		_ = conn.Close()
		h.Release()
		return err
	}
	if err := conn.SetWriteDeadline(timebase.Real{}.Now().Add(10 * time.Second)); err != nil {
		h.Release()
		return err
	}
	if err := wire.WriteFrame(rw, []byte(r.Method), frame, body); err != nil {
		h.Release()
		return err
	}
	if err := rw.Flush(); err != nil {
		h.Release()
		return err
	}
	_ = conn.Close()
	h.Release()
	return nil
}
