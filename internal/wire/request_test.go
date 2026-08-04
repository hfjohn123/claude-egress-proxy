package wire

import (
	"io"
	"net/http"
	"testing"
)

func TestAdaptRequestClassifiesImmutableTargetAndStructuralPrecedence(t *testing.T) {
	tests := []struct {
		name                   string
		protoMajor, protoMinor int
		uri                    string
		header                 http.Header
		body                   io.ReadCloser
		transfer               []string
		wantTarget             TargetForm
		want                   Decision
	}{
		{"origin", 1, 1, "/proxy.pac?x", nil, http.NoBody, nil, TargetOrigin, DecisionAllow},
		{"authority", 1, 1, "example.com:443", nil, http.NoBody, nil, TargetAuthority, DecisionAllow},
		{"absolute", 1, 1, "http://example.com/a", nil, http.NoBody, nil, TargetAbsolute, DecisionAllow},
		{"asterisk", 1, 1, "*", nil, http.NoBody, nil, TargetAsterisk, DecisionAllow},
		{"wrong version wins", 1, 0, "/", http.Header{"Content-Length": {"0"}}, http.NoBody, nil, TargetOrigin, DecisionHTTPVersionNotSupported},
		{"content length zero", 1, 1, "/", http.Header{"Content-Length": {"0"}}, http.NoBody, nil, TargetOrigin, DecisionBadRequest},
		{"transfer encoding", 1, 1, "/", nil, http.NoBody, []string{"chunked"}, TargetOrigin, DecisionBadRequest},
		{"expect", 1, 1, "/", http.Header{"Expect": {"100-continue"}}, http.NoBody, nil, TargetOrigin, DecisionBadRequest},
		{"upgrade", 1, 1, "/", http.Header{"Connection": {"upgrade"}}, http.NoBody, nil, TargetOrigin, DecisionBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.header
			if h == nil {
				h = make(http.Header)
			}
			r := &http.Request{Method: "CONNECT", RequestURI: tt.uri, ProtoMajor: tt.protoMajor, ProtoMinor: tt.protoMinor, Header: h, Body: tt.body, TransferEncoding: tt.transfer}
			got, decision := AdaptRequest(r)
			if decision != tt.want || got.Target != tt.wantTarget || got.RequestURI != tt.uri || got.Method != "CONNECT" {
				t.Fatalf("got %#v, %v", got, decision)
			}
		})
	}
}

func TestTakeAuthorizationCopiesAndDeletesAllValues(t *testing.T) {
	h := http.Header{"Proxy-Authorization": {"Basic abc"}}
	got, count := TakeAuthorization(h, "Proxy-Authorization")
	if count != 1 || string(got) != "Basic abc" || len(h.Values("Proxy-Authorization")) != 0 {
		t.Fatalf("got %q, %d, %#v", got, count, h)
	}
	got[0] = 'X'
	if h.Get("Proxy-Authorization") != "" {
		t.Fatal("header retained credential")
	}
	if got, count = TakeAuthorization(http.Header{"Authorization": {"a", "b"}}, "Authorization"); count != 2 || got != nil {
		t.Fatalf("got %q, %d", got, count)
	}
}
