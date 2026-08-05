package certmgr

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

const maxSuppliedFileBytes = 1 << 20

// SuppliedConfig identifies one certificate/key pair. Paths are deliberately
// never included in returned errors.
type SuppliedConfig struct {
	Hostname, CertificateFile, PrivateKeyFile string
	Now                                       func() time.Time
	Clock                                     timebase.Clock
	RootPolicy                                securefs.RootPolicy
	FilePolicy                                securefs.FilePolicy
}

// Supplied validates and polls a supplied PEM pair without replacing good state on failure.
type Supplied struct {
	*Manager
	certificateFile, privateKeyFile string
	clock                           timebase.Clock
	rootPolicy                      securefs.RootPolicy
	filePolicy                      securefs.FilePolicy
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
	rootPolicy := config.RootPolicy
	if securefs.PermissionsEqual(rootPolicy.Access, securefs.PermissionPolicy{}) {
		rootPolicy.Access = securefs.IdentityOnlyPermissions()
	}
	filePolicy := config.FilePolicy
	if securefs.PermissionsEqual(filePolicy.Access, securefs.PermissionPolicy{}) {
		filePolicy.Access = securefs.IdentityOnlyPermissions()
	}
	if filePolicy.Presence != securefs.Required {
		filePolicy.Presence = securefs.Required
	}
	if filePolicy.Kind != securefs.RegularFile {
		filePolicy.Kind = securefs.RegularFile
	}
	if filePolicy.MaxBytes == 0 {
		filePolicy.MaxBytes = maxSuppliedFileBytes
	}
	m := &Supplied{Manager: New(config.Hostname, config.Now), certificateFile: config.CertificateFile, privateKeyFile: config.PrivateKeyFile, clock: clock, rootPolicy: rootPolicy, filePolicy: filePolicy}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Supplied) load() error {
	certPEM, keyPEM, err := readSuppliedPair(m.certificateFile, m.privateKeyFile, m.rootPolicy, m.filePolicy)
	if err != nil {
		return errNoCertificate
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errNoCertificate
	}
	return m.InstallServing(certificate)
}

func readSuppliedPair(certPath, keyPath string, rootPolicy securefs.RootPolicy, filePolicy securefs.FilePolicy) ([]byte, []byte, error) {
	if filepath.Dir(certPath) != filepath.Dir(keyPath) {
		return nil, nil, errors.New("certificate pair split")
	}
	root, err := securefs.OpenRoot(filepath.Dir(certPath), rootPolicy)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	certPEM, _, err := root.ReadFile(filepath.Base(certPath), filePolicy)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, _, err := root.ReadFile(filepath.Base(keyPath), filePolicy)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
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
