package wire

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// OwnedConn is an admission-owned connection. Release is idempotent and tells
// the owner whether this caller performed the release.
type OwnedConn interface {
	net.Conn
	Release() bool
}

type ownerContextKey struct{}

// NewServer builds the standard library HTTP/1 boundary used after admission.
func NewServer(handler http.Handler) *http.Server {
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := ConnectionOwner(r); ok {
				handler.ServeHTTP(w, r)
			}
		}),
		ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		MaxHeaderBytes: 16 << 10, DisableGeneralOptionsHandler: true,
		Protocols: protocols, ErrorLog: log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			owner, ok := conn.(OwnedConn)
			if !ok {
				return ctx
			}
			return context.WithValue(ctx, ownerContextKey{}, owner)
		},
	}
	server.SetKeepAlivesEnabled(false)
	return server
}

// ConnectionOwner returns only the exact OwnedConn admitted by the listener.
func ConnectionOwner(r *http.Request) (OwnedConn, bool) {
	owner, ok := r.Context().Value(ownerContextKey{}).(OwnedConn)
	return owner, ok
}
