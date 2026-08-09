package certmgr

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
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
	if client.Client.HTTPClient == nil || client.Client.HTTPClient.Transport == nil {
		t.Fatal("client does not retain direct transport")
	}
	if client.Client.HTTPClient.Timeout != 30*time.Second {
		t.Fatalf("transaction timeout = %v", client.Client.HTTPClient.Timeout)
	}
	if err := client.Client.HTTPClient.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestACMEClientRejectsForeignEndpointBeforeTransport(t *testing.T) {
	called := false
	client, err := NewACMEClient(ACMEConfig{DirectoryURL: "https://ca.example/directory", Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://other.example/directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Client.HTTPClient.Do(req); err == nil {
		t.Fatal("foreign endpoint accepted")
	}
	if called {
		t.Fatal("transport called for foreign endpoint")
	}
}

func TestACMEClientRejectsResponseOverOneMiB(t *testing.T) {
	client, err := NewACMEClient(ACMEConfig{DirectoryURL: "https://ca.example/directory", Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(make([]byte, acmeBodyLimit+1))), Header: make(http.Header)}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Client.HTTPClient.Get("https://ca.example/resource")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); !errors.Is(err, errACMEBodyLimit) {
		t.Fatalf("read error = %v, want body limit", err)
	}
}
