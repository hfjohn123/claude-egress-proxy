package certmgr

import (
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

const maxSuppliedFileBytes = 1 << 20

// SuppliedConfig identifies one certificate/key pair. Paths are deliberately
// never included in returned errors.
type SuppliedConfig struct {
	Hostname, CertificateFile, PrivateKeyFile string
	Now                                       func() time.Time
	Clock                                     timebase.Clock
}

// Supplied validates and polls a supplied PEM pair without replacing good state on failure.
type Supplied struct {
	*Manager
	certificateFile, privateKeyFile string
	clock                           timebase.Clock
	mu                              sync.Mutex
	failed                          bool
}

func NewSupplied(config SuppliedConfig) (*Supplied, error) {
	if config.Hostname == "" || config.CertificateFile == "" || config.PrivateKeyFile == "" {
		return nil, errNoCertificate
	}
	clock := config.Clock
	if clock == nil {
		clock = timebase.Real{}
	}
	m := &Supplied{Manager: New(config.Hostname, config.Now), certificateFile: config.CertificateFile, privateKeyFile: config.PrivateKeyFile, clock: clock}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Supplied) load() error {
	certPEM, err := readSuppliedFile(m.certificateFile)
	if err != nil {
		return errNoCertificate
	}
	keyPEM, err := readSuppliedFile(m.privateKeyFile)
	if err != nil {
		return errNoCertificate
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errNoCertificate
	}
	return m.InstallServing(certificate)
}

func readSuppliedFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Size() > maxSuppliedFileBytes || (runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0) {
		return nil, errors.New("unsafe certificate file")
	}
	return os.ReadFile(path)
}

func (m *Supplied) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	go func() {
		ticker := m.clock.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C():
				m.ReloadOnce(ctx)
			}
		}
	}()
	return nil
}

func (m *Supplied) ReloadOnce(ctx context.Context) contract.ReloadResult {
	failure, _ := contract.ParseReloadResult("failure")
	success, _ := contract.ParseReloadResult("success")
	recovered, _ := contract.ParseReloadResult("recovered")
	if ctx == nil || ctx.Err() != nil {
		return failure
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.load(); err != nil {
		m.failed = true
		return failure
	}
	if m.failed {
		m.failed = false
		return recovered
	}
	return success
}
