package certmgr

import (
	"errors"
	"net/http"
	"testing"
)

func TestACMEClientUsesDirectTransportAndRejectsRedirects(t *testing.T) {
	transport, err := NewDirectTransport(DirectTransportConfig{DirectoryURL: "https://ca.example/directory"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewACMEClient(ACMEConfig{DirectoryURL: "https://ca.example/directory", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if client.Client.HTTPClient == nil || client.Client.HTTPClient.Transport != transport {
		t.Fatal("client does not retain direct transport")
	}
	if err := client.Client.HTTPClient.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect error = %v", err)
	}
}
