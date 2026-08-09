package certmgr

import (
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type ManagedACMEConfig struct {
	Hostname string
	Store    ACMEStore
	Clock    timebase.Clock
	Now      func() time.Time
	Jitter   func(time.Duration) time.Duration
	Observe  func(contract.ReloadResult)
}

type issuedACME struct {
	Certificate tls.Certificate
	State       ACMEState
}

type issueACME func(context.Context, *Manager, crypto.Signer) (issuedACME, error)

// ManagedACME owns cached serving material plus one serialized issuance loop.
type ManagedACME struct {
	*Manager
	store   ACMEStore
	clock   timebase.Clock
	issue   issueACME
	account crypto.Signer
	jitter  func(time.Duration) time.Duration
	observe func(contract.ReloadResult)

	mu      sync.Mutex
	failed  bool
	started atomic.Bool
	done    chan struct{}
	closed  sync.Once
}

func newManagedACME(config ManagedACMEConfig, issue issueACME) (*ManagedACME, error) {
	if config.Hostname == "" || !config.Store.Valid() || issue == nil {
		return nil, ErrACMEStateInvalid
	}
	clock := config.Clock
	if clock == nil {
		clock = timebase.Real{}
	}
	jitter := config.Jitter
	if jitter == nil {
		jitter = defaultACMEJitter
	}
	manager := &ManagedACME{Manager: New(config.Hostname, config.Now), store: config.Store, clock: clock, issue: issue, jitter: jitter, observe: config.Observe, done: make(chan struct{})}
	state, err := config.Store.Load()
	if errors.Is(err, ErrACMEStateAbsent) {
		return manager, nil
	}
	if err != nil {
		return nil, ErrACMEStateInvalid
	}
	account, err := parsePrivateKey(state.AccountKeyPEM)
	if err != nil {
		return nil, ErrACMEStateInvalid
	}
	certificate, err := tls.X509KeyPair(state.CertificatePEM, state.PrivateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, ErrACMEStateInvalid
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || !exactDNSName(leaf, config.Hostname) || !certificateMatchesKey(leaf, certificate.PrivateKey) {
		return nil, ErrACMEStateInvalid
	}
	manager.account = account
	if manager.now().Before(leaf.NotAfter) {
		if err := manager.InstallServing(certificate); err != nil {
			return nil, ErrACMEStateInvalid
		}
	}
	return manager, nil
}

func parsePrivateKey(bytes []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(bytes)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, ErrACMEStateInvalid
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrACMEStateInvalid
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrACMEStateInvalid
	}
	return signer, nil
}

func (m *ManagedACME) Start(ctx context.Context) error {
	if ctx == nil || m == nil || m.issue == nil || m.clock == nil {
		return ErrACMEStateInvalid
	}
	if !m.started.CompareAndSwap(false, true) {
		return nil
	}
	go func() {
		defer close(m.done)
		m.run(ctx)
	}()
	return nil
}

func (m *ManagedACME) Close() error {
	if m == nil {
		return nil
	}
	if m.started.Load() {
		<-m.done
	}
	var err error
	m.closed.Do(func() { err = m.store.Close() })
	return err
}

func (m *ManagedACME) run(ctx context.Context) {
	backoff := time.Minute
	for {
		delay := m.renewalDelay()
		if delay > 0 {
			timer := m.clock.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C():
			}
		}
		result := m.ReloadOnce(ctx)
		if result.String() == "failure" {
			timer := m.clock.NewTimer(m.retryDelay(backoff))
			if backoff < 12*time.Hour {
				backoff *= 2
				if backoff > 12*time.Hour {
					backoff = 12 * time.Hour
				}
			}
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C():
			}
			continue
		}
		backoff = time.Minute
	}
}

func (m *ManagedACME) retryDelay(base time.Duration) time.Duration {
	delay := base
	if m != nil && m.jitter != nil {
		if jittered := m.jitter(base); jittered > 0 {
			delay = jittered
		}
	}
	if delay < time.Minute {
		return time.Minute
	}
	if delay > 12*time.Hour {
		return 12 * time.Hour
	}
	return delay
}

func defaultACMEJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	var sample [1]byte
	if _, err := cryptorand.Read(sample[:]); err != nil {
		return base
	}
	span := base / 10
	offset := time.Duration((int64(sample[0])*int64(2*span))/255) - span
	return base + offset
}

func (m *ManagedACME) renewalDelay() time.Duration {
	expiry := m.Expiry(m.now())
	if expiry <= 30*24*time.Hour {
		return 0
	}
	return expiry - 30*24*time.Hour
}

func (m *ManagedACME) ReloadOnce(ctx context.Context) contract.ReloadResult {
	failure, _ := contract.ParseReloadResult("failure")
	success, _ := contract.ParseReloadResult("success")
	recovered, _ := contract.ParseReloadResult("recovered")
	if ctx == nil || ctx.Err() != nil || m == nil || m.issue == nil {
		return m.observeResult(failure)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	attemptContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	issued, err := m.issue(attemptContext, m.Manager, m.account)
	if err != nil {
		m.failed = true
		return m.observeResult(failure)
	}
	if _, err := validateMaterial(issued.Certificate, m.hostname, m.now()); err != nil {
		m.failed = true
		return m.observeResult(failure)
	}
	account, err := parsePrivateKey(issued.State.AccountKeyPEM)
	if err != nil || m.store.Save(attemptContext, issued.State) != nil {
		m.failed = true
		return m.observeResult(failure)
	}
	if err := m.InstallServing(issued.Certificate); err != nil {
		m.failed = true
		return m.observeResult(failure)
	}
	m.account = account
	if m.failed {
		m.failed = false
		return m.observeResult(recovered)
	}
	return m.observeResult(success)
}

func (m *ManagedACME) observeResult(result contract.ReloadResult) contract.ReloadResult {
	if m != nil && m.observe != nil {
		m.observe(result)
	}
	return result
}
