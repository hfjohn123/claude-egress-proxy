//go:build linux

package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestProductionBinaryE2E(t *testing.T) {
	binary, workRoot := e2eEnvironment(t)
	identity := lookupServiceIdentity(t, "claude-egress-proxy")
	runtime := prepareRuntime(t, workRoot, identity)
	runProduct(t, identity, binary, "--config", runtime.configPath, "check", "config")
	credential := addCredential(t, identity, binary, runtime.configPath, "e2e-client")
	fixtures := startRuntimeFixtures(t, runtime)
	server := startProduct(t, identity, binary, diagnosticForbidden(runtime.forbidden, "e2e-client", credential.secret), "--config", runtime.configPath, "serve")
	waitForHealth(t, identity, binary, "127.0.0.1:9090")
	if err := fixtures.client.reject(""); err != nil {
		t.Fatalf("missing-auth CONNECT: %v; product=%s", err, server.output())
	}
	if got := fixtures.origin.Connections(); got != 0 {
		t.Fatalf("missing-auth reached origin %d times", got)
	}
	if err := fixtures.client.reject(basicHeader("e2e-client", wrongSecret())); err != nil {
		t.Fatalf("wrong-auth CONNECT: %v; product=%s", err, server.output())
	}
	if got := fixtures.origin.Connections(); got != 0 {
		t.Fatalf("wrong-auth reached origin %d times", got)
	}
	if err := fixtures.client.roundTrip(basicHeader("e2e-client", credential.secret), runtime.sentinel); err != nil {
		t.Fatalf("authenticated CONNECT: %v; product=%s", err, server.output())
	}
	if got := fixtures.origin.Accepted(); got != 1 {
		t.Fatalf("origin accepted %d requests, want 1", got)
	}
	if got := fixtures.origin.Connections(); got != 1 {
		t.Fatalf("origin received %d connections, want 1", got)
	}
	stopGracefully(t, server, 12*time.Second)
}

type serviceIdentity struct {
	uid uint32
	gid uint32
}

type runtimeState struct {
	configPath string
	statePath  string
	pki        pkiBundle
	roots      *x509.CertPool
	originCert tls.Certificate
	sentinel   []byte
	forbidden  []string
}

type credentialResult struct{ secret string }

type runtimeFixtures struct {
	dns    *dnsFixture
	origin *originFixture
	client proxyClient
}

func e2eEnvironment(t *testing.T) (string, string) {
	t.Helper()
	binary := os.Getenv("CEP_E2E_BINARY")
	workRoot := os.Getenv("CEP_E2E_WORK_ROOT")
	if binary == "" && workRoot == "" {
		t.Skip("native E2E environment is not configured")
	}
	if binary == "" || workRoot == "" {
		t.Fatal("CEP_E2E_BINARY and CEP_E2E_WORK_ROOT must be set together")
	}
	for name, path := range map[string]string{"CEP_E2E_BINARY": binary, "CEP_E2E_WORK_ROOT": workRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
			t.Fatalf("%s must be a clean absolute path", name)
		}
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("CEP_E2E_BINARY is not a regular file: %v", err)
	}
	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		t.Fatalf("create E2E work root: %v", err)
	}
	if err := os.Chmod(workRoot, 0o755); err != nil {
		t.Fatalf("secure E2E work root: %v", err)
	}
	return binary, workRoot
}

func lookupServiceIdentity(t *testing.T, name string) serviceIdentity {
	t.Helper()
	account, err := user.Lookup(name)
	if err != nil {
		t.Fatalf("lookup service identity: %v", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatalf("invalid service UID: %q", account.Uid)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		t.Fatalf("invalid service GID: %q", account.Gid)
	}
	return serviceIdentity{uid: uint32(uid), gid: uint32(gid)}
}

func prepareRuntime(t *testing.T, workRoot string, identity serviceIdentity) runtimeState {
	t.Helper()
	root, err := os.MkdirTemp(workRoot, "runtime-")
	if err != nil {
		t.Fatalf("create runtime root: %v", err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("secure runtime root: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove runtime root: %v", err)
		}
	})
	configDir := filepath.Join(root, "config")
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	if err := os.Chown(stateDir, int(identity.uid), int(identity.gid)); err != nil {
		t.Fatalf("own state directory: %v", err)
	}

	pki, err := generatePKI(time.Now().UTC())
	if err != nil {
		t.Fatalf("generate E2E PKI: %v", err)
	}
	proxyCertPath := filepath.Join(stateDir, "proxy-cert.pem")
	proxyKeyPath := filepath.Join(stateDir, "proxy-key.pem")
	writeServiceFile(t, proxyCertPath, pki.proxyCertPEM, identity)
	writeServiceFile(t, proxyKeyPath, pki.proxyKeyPEM, identity)

	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		t.Fatalf("generate instance ID: %v", err)
	}
	var sentinelBytes [24]byte
	if _, err := rand.Read(sentinelBytes[:]); err != nil {
		t.Fatalf("generate sentinel: %v", err)
	}
	sentinel := []byte(hex.EncodeToString(sentinelBytes[:]))
	configPath := filepath.Join(configDir, "config.yaml")
	configBytes := []byte(fmt.Sprintf("format_version: 1\ninstance_id: %s\nstate_root: %s\npublic_listener:\n  addresses: [192.0.0.9:8443]\n  pac_enabled: false\nadmin_listener:\n  enabled: true\n  address: 127.0.0.1:9090\ntls:\n  mode: supplied\n  hostname: proxy.e2e.invalid\n  certificate_file: %s\n  private_key_file: %s\nresolver:\n  mode: explicit\n  address: 127.0.0.1:5353\npublic_self_ipv4s: [192.0.0.9]\nper_device_capacity: 2\nabsolute_tunnel_lifetime: disabled\ngraceful_shutdown_drain: 5s\ndestination:\n  profile: code\n  exact_hosts: [origin.e2e.invalid]\n  suffixes: []\n  dangerous_custom_suffixes: false\nlogging:\n  sink: default\n  sensitive_metadata: false\nmetrics:\n  enabled: false\n", hex.EncodeToString(instance[:]), strconv.Quote(stateDir), strconv.Quote(proxyCertPath), strconv.Quote(proxyKeyPath)))
	if err := os.WriteFile(configPath, configBytes, 0o644); err != nil {
		t.Fatalf("write E2E config: %v", err)
	}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatalf("secure E2E config: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pki.caPEM) {
		t.Fatal("append E2E root certificate")
	}
	originCert, err := tls.X509KeyPair(pki.originCertPEM, pki.originKeyPEM)
	if err != nil {
		t.Fatalf("load origin certificate: %v", err)
	}
	return runtimeState{
		configPath: configPath,
		statePath:  stateDir,
		pki:        pki,
		roots:      roots,
		originCert: originCert,
		sentinel:   sentinel,
		forbidden:  []string{string(pki.proxyKeyPEM), string(pki.originKeyPEM), string(sentinel)},
	}
}

func writeServiceFile(t *testing.T, path string, data []byte, identity serviceIdentity) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write service file: %v", err)
	}
	if err := os.Chown(path, int(identity.uid), int(identity.gid)); err != nil {
		t.Fatalf("own service file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("secure service file: %v", err)
	}
}

func runProduct(t *testing.T, identity serviceIdentity, binary string, arguments ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stdout, stderr, err := runProductCommand(ctx, identity, binary, arguments...)
	if err != nil {
		t.Fatalf("product command failed: %v; stdout=%q stderr=%q", err, redact(stdout), redact(stderr))
	}
}

func addCredential(t *testing.T, identity serviceIdentity, binary, configPath, device string) credentialResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stdout, stderr, err := runProductCommand(ctx, identity, binary, "--config", configPath, "credential", "add", "--device", device)
	if err != nil {
		t.Fatalf("credential add failed: %v; stderr=%q", err, redact(stderr))
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		key, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok || key == "" || fields[key] != "" {
			t.Fatal("credential output is not canonical")
		}
		fields[key] = value
	}
	if fields["device_identifier"] != device || len(fields) != 3 {
		t.Fatal("credential output fields are invalid")
	}
	secret := fields["secret"]
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != secret {
		t.Fatal("credential secret is not canonical")
	}
	return credentialResult{secret: secret}
}

func runProductCommand(ctx context.Context, identity serviceIdentity, binary string, arguments ...string) (string, string, error) {
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: identity.uid, Gid: identity.gid, Groups: []uint32{identity.gid}}}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func startRuntimeFixtures(t *testing.T, runtime runtimeState) runtimeFixtures {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dns, err := startDNSFixtureForAnswers(ctx, "127.0.0.1:5353", map[string]netip.Addr{
		"proxy.e2e.invalid":  netip.MustParseAddr("192.0.0.9"),
		"origin.e2e.invalid": netip.MustParseAddr("192.0.0.10"),
	})
	if err != nil {
		t.Fatalf("start DNS fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := dns.Close(); err != nil {
			t.Errorf("close DNS fixture: %v", err)
		}
	})
	origin, err := startOrigin(ctx, "192.0.0.10:443", runtime.originCert, runtime.sentinel)
	if err != nil {
		t.Fatalf("start origin fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := origin.Close(); err != nil {
			t.Errorf("close origin fixture: %v", err)
		}
	})
	return runtimeFixtures{dns: dns, origin: origin, client: proxyClient{proxyAddress: "192.0.0.9:8443", proxyName: "proxy.e2e.invalid", originAuthority: "origin.e2e.invalid:443", originName: "origin.e2e.invalid", roots: runtime.roots}}
}

type productProcess struct {
	command   *exec.Cmd
	stdout    *bytes.Buffer
	stderr    *bytes.Buffer
	forbidden []string
	done      chan struct{}
	mu        sync.Mutex
	waitErr   error
}

func startProduct(t *testing.T, identity serviceIdentity, binary string, forbidden []string, arguments ...string) *productProcess {
	t.Helper()
	command := exec.Command(binary, arguments...)
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: identity.uid, Gid: identity.gid, Groups: []uint32{identity.gid}}}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start product: %v", err)
	}
	process := &productProcess{command: command, stdout: stdout, stderr: stderr, forbidden: append([]string(nil), forbidden...), done: make(chan struct{})}
	go func() {
		err := command.Wait()
		process.mu.Lock()
		process.waitErr = err
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		select {
		case <-process.done:
		default:
			_ = command.Process.Kill()
			<-process.done
		}
	})
	return process
}

func waitForHealth(t *testing.T, identity serviceIdentity, binary, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastError error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _, err := runProductCommand(ctx, identity, binary, "check", "health", "--address", address)
		cancel()
		if err == nil {
			return
		}
		lastError = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("health did not become ready: %v", lastError)
}

func stopGracefully(t *testing.T, process *productProcess, timeout time.Duration) {
	t.Helper()
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal product: %v", err)
	}
	select {
	case <-process.done:
		process.mu.Lock()
		err := process.waitErr
		process.mu.Unlock()
		if err != nil {
			t.Fatalf("product did not stop cleanly: %v; output=%s", err, process.output())
		}
	case <-time.After(timeout):
		_ = process.command.Process.Kill()
		<-process.done
		t.Fatalf("product shutdown timed out; output=%s", process.output())
	}
}

func (p *productProcess) output() string {
	values := append([]string(nil), p.forbidden...)
	return redact("stdout="+strconv.Quote(p.stdout.String())+" stderr="+strconv.Quote(p.stderr.String()), values...)
}

func basicHeader(device, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(device+":"+secret))
}

func wrongSecret() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
}

func diagnosticForbidden(base []string, device, secret string) []string {
	values := append([]string(nil), base...)
	return append(values, secret, basicHeader(device, secret), basicHeader(device, wrongSecret()))
}
