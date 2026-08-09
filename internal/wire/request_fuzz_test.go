package wire

import (
	"net/http"
	"testing"
)

func FuzzFramingValues(f *testing.F) {
	f.Add("/", "", "")
	f.Fuzz(func(t *testing.T, uri, contentLength, transfer string) {
		h := make(http.Header)
		if contentLength != "" {
			h.Set("Content-Length", contentLength)
		}
		r := &http.Request{Method: "GET", RequestURI: uri, ProtoMajor: 1, ProtoMinor: 1, Header: h, Body: http.NoBody}
		if transfer != "" {
			r.TransferEncoding = []string{transfer}
		}
		_, _ = AdaptRequest(r)
	})
}
