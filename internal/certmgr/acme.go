package certmgr

import (
	"errors"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
)

// ACMEConfig contains the bounded CA directory and its dedicated transport.
type ACMEConfig struct {
	DirectoryURL string
	Transport    http.RoundTripper
}

// Client is the low-level ACME client boundary. It intentionally does not use
// autocert, which would own transport and challenge lifetime policy.
type Client struct{ Client *acme.Client }

func NewACMEClient(config ACMEConfig) (*Client, error) {
	if err := validateACMEURL(config.DirectoryURL); err != nil {
		return nil, err
	}
	if config.Transport == nil {
		return nil, errors.New("missing acme transport")
	}
	return &Client{Client: &acme.Client{DirectoryURL: config.DirectoryURL, HTTPClient: &http.Client{
		Transport:     boundedACMETransport{next: config.Transport},
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}}, nil
}

// boundedACMETransport makes the low-level client safe even when it follows
// endpoint URLs returned by a CA directory. The directory host is the sole
// authority permitted to reach the dedicated direct transport.
type boundedACMETransport struct {
	next http.RoundTripper
}

func (t boundedACMETransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || validateACMEURL(request.URL.String()) != nil {
		return nil, errUnsafeACMEEndpoint
	}
	response, err := t.next.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	response.Body = &boundedBody{ReadCloser: response.Body, remaining: acmeBodyLimit}
	return response, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		var extra [1]byte
		n, err := b.ReadCloser.Read(extra[:])
		if n > 0 {
			return 0, errACMEBodyLimit
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}
