package certmgr

import (
	"errors"
	"net/http"

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
		Transport:     config.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}}, nil
}
