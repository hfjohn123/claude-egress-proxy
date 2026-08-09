# Native Black-Box E2E Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Add a hermetic WSL/Linux black-box E2E harness for the unmodified production binary and make its E2E GitHub Actions status a required main-branch gate.

**Architecture:** A root-owned Bash wrapper builds the production executable and a Linux E2E test binary, creates a network namespace, and executes the test without an external route. The Go test generates ephemeral PKI and state, starts fake DNS and HTTPS origin services, invokes production CLI commands under the real service identity, verifies both TLS layers and CONNECT relay bytes, and proves graceful SIGTERM shutdown.

**Tech Stack:** Go 1.26.5, golang.org/x/net/dns/dnsmessage, Bash, Linux ip netns, WSL2 Ubuntu, GitHub Actions.

## Global Constraints

- Exercise the unmodified production executable; add no production test mode, build tag, dependency-injection bypass, or policy exception.
- Use no Docker daemon, public Internet endpoint, Anthropic credential, ACME account, or repository secret.
- Keep logging.sensitive_metadata false; never print the generated proxy secret, Basic header, private keys, or sentinel.
- Give every socket, process, handshake, and cleanup operation a finite deadline.
- Use only loopback, 192.0.0.9/32, and 192.0.0.10/32 inside a namespace with no external interface or default route.
- Name the GitHub job exactly E2E, run it on pull requests and main, and set timeout-minutes to 5.
- Preserve the two existing untracked root binaries; stage only files named by each task.

---

### Task 1: Ephemeral PKI, DNS, origin, and client fixtures

**Files:**
- Create: integration/e2e/fixtures_linux_test.go
- Create: integration/e2e/fixtures_unit_linux_test.go
- Create: integration/e2e/client_linux_test.go
- Create: integration/e2e/client_unit_linux_test.go

**Interfaces:**
- Produces: generatePKI(now time.Time) (pkiBundle, error).
- Produces: startDNSFixture(ctx, address, allowedHost string, answer netip.Addr) (*dnsFixture, error).
- Produces: startOrigin(ctx, address string, cert tls.Certificate, sentinel []byte) (*originFixture, error).
- Produces: proxyClient.reject(authHeader string) error and proxyClient.roundTrip(authHeader string, sentinel []byte) error.
- Produces: redact(text string, forbidden ...string) string.

- [ ] **Step 1: Write failing PKI and redaction tests**

~~~go
//go:build linux

package e2e_test

func TestGeneratedPKISeparatesNames(t *testing.T) {
	bundle, err := generatePKI(time.Unix(1_786_252_800, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle.caPEM) {
		t.Fatal("CA PEM rejected")
	}
	proxy := parseLeaf(t, bundle.proxyCertPEM)
	origin := parseLeaf(t, bundle.originCertPEM)
	if _, err := proxy.Verify(x509.VerifyOptions{Roots: roots, DNSName: "proxy.e2e.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := origin.Verify(x509.VerifyOptions{Roots: roots, DNSName: "origin.e2e.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.Verify(x509.VerifyOptions{Roots: roots, DNSName: "origin.e2e.invalid"}); err == nil {
		t.Fatal("proxy certificate accepted origin name")
	}
}

func TestRedactRemovesEveryOccurrence(t *testing.T) {
	if got := redact("secret before secret after", "secret"); got != "[REDACTED] before [REDACTED] after" {
		t.Fatalf("redacted = %q", got)
	}
}
~~~

- [ ] **Step 2: Run and verify RED**

~~~bash
go test ./integration/e2e -run 'TestGeneratedPKI|TestRedact' -count=1 -v
~~~

Expected: build failure because generatePKI, pkiBundle, parseLeaf, and redact do not exist.

- [ ] **Step 3: Implement minimal PKI and redaction**

Generate one ECDSA P-256 CA and independent proxy/origin leaves. Use serials 1, 2, and 3; CA key usage CertSign; leaf usage ServerAuth; validity from now minus one hour through now plus 48 hours. Give each leaf exactly one DNS SAN. Encode private keys as PKCS#8 PEM.

~~~go
type pkiBundle struct {
	caPEM, proxyCertPEM, proxyKeyPEM, originCertPEM, originKeyPEM []byte
}

func generatePKI(now time.Time) (pkiBundle, error)
func parseCertificatePEM(raw []byte) (*x509.Certificate, error)
func redact(text string, forbidden ...string) string
~~~

redact replaces every nonempty forbidden string with [REDACTED]. All eventual failure paths pass the proxy secret, Basic header, both private keys, and sentinel.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 command. Expected: PASS.

- [ ] **Step 5: Write the failing DNS behavior test**

~~~go
func TestDNSFixtureAnswersOnlyAllowedOrigin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture, err := startDNSFixture(ctx, "127.0.0.1:0", "origin.e2e.invalid", netip.MustParseAddr("192.0.0.10"))
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	resolver := fixtureResolver(fixture.Address())
	got, err := resolver.LookupNetIP(ctx, "ip4", "origin.e2e.invalid")
	if err != nil || len(got) != 1 || got[0].String() != "192.0.0.10" {
		t.Fatalf("answer = %v, %v", got, err)
	}
	if _, err := resolver.LookupNetIP(ctx, "ip4", "unknown.e2e.invalid"); err == nil {
		t.Fatal("unknown name resolved")
	}
}
~~~

- [ ] **Step 6: Run and verify RED**

~~~bash
go test ./integration/e2e -run TestDNSFixtureAnswersOnlyAllowedOrigin -count=1 -v
~~~

Expected: build failure because startDNSFixture and fixtureResolver do not exist.

- [ ] **Step 7: Implement bounded UDP/TCP DNS**

Use dnsmessage.Parser. Require one A/IN question. The focused fixture test returns one zero-TTL A record for its configured origin and NXDOMAIN otherwise. The production E2E configures exact answers for proxy.e2e.invalid at 192.0.0.9 and origin.e2e.invalid at 192.0.0.10 because supplied TLS resolves its hostname for public-self state. Reject malformed, multi-question, non-A, and non-IN input. Cap UDP packets at 512 bytes and TCP length-prefixed messages at 4096 bytes. Close UDP and TCP listeners exactly once.

~~~go
type dnsFixture struct {
	address string
	udp net.PacketConn
	tcp net.Listener
	queries atomic.Uint64
	cancel context.CancelFunc
	done chan struct{}
}

func startDNSFixture(ctx context.Context, address, allowedHost string, answer netip.Addr) (*dnsFixture, error)
func (f *dnsFixture) Address() string
func (f *dnsFixture) Queries() uint64
func (f *dnsFixture) Close() error
func fixtureResolver(address string) *net.Resolver
~~~

- [ ] **Step 8: Write failing origin and CONNECT-client tests**

Write a literal in-process TLS test that requires CA/SNI validation and exact sentinel return. Also test strict CONNECT response parsing with literal 200 and 407 responses, plus rejection of HTTP/1.0 and oversized headers.

~~~go
func TestOriginExchangeRequiresExactSentinel(t *testing.T)
func TestReadConnectStatusAcceptsOnlyClosedHTTP11Responses(t *testing.T)
~~~

Name the mutation each test catches: wrong SNI, mutated sentinel, wrong protocol, unexpected status, or oversized response.

- [ ] **Step 9: Implement origin and client helpers**

originFixture requires TLS 1.2+, ALPN http/1.1, GET /e2e, host origin.e2e.invalid, and exact X-E2E-Sentinel. It returns the sentinel as a fixed-length body and counts valid requests.

proxyClient verifies outer TLS with SNI proxy.e2e.invalid. reject sends CONNECT and requires 407. roundTrip requires 200, negotiates verified inner TLS with SNI origin.e2e.invalid, sends the sentinel request, and requires an exact response.

~~~go
type originFixture struct {
	listener net.Listener
	accepted atomic.Uint64
	done chan struct{}
}

type proxyClient struct {
	proxyAddress, proxyName, originAuthority, originName string
	roots *x509.CertPool
}

func startOrigin(ctx context.Context, address string, cert tls.Certificate, sentinel []byte) (*originFixture, error)
func (o *originFixture) Accepted() uint64
func (o *originFixture) Close() error
func (c proxyClient) reject(authHeader string) error
func (c proxyClient) roundTrip(authHeader string, sentinel []byte) error
~~~

- [ ] **Step 10: Verify and commit**

~~~bash
gofmt -w integration/e2e/fixtures_linux_test.go integration/e2e/fixtures_unit_linux_test.go integration/e2e/client_linux_test.go integration/e2e/client_unit_linux_test.go
go test ./integration/e2e -count=1 -v
git add integration/e2e/fixtures_linux_test.go integration/e2e/fixtures_unit_linux_test.go integration/e2e/client_linux_test.go integration/e2e/client_unit_linux_test.go
git commit -m "test(e2e): add isolated fixtures"
~~~

---

### Task 2: Production-binary test and native namespace runner

**Files:**
- Create: integration/e2e/e2e_linux_test.go
- Create: integration/e2e/runner_linux_test.go
- Create: scripts/verify-e2e.sh
- Modify: .gitattributes

**Interfaces:**
- Consumes: CEP_E2E_BINARY and CEP_E2E_WORK_ROOT absolute paths.
- Produces: TestProductionBinaryE2E.
- Produces: scripts/verify-e2e.sh with --preflight-only.

- [ ] **Step 1: Write the failing top-level E2E test**

~~~go
func TestProductionBinaryE2E(t *testing.T) {
	binary := requireAbsoluteEnv(t, "CEP_E2E_BINARY")
	workRoot := requireAbsoluteEnv(t, "CEP_E2E_WORK_ROOT")
	identity := lookupServiceIdentity(t, "claude-egress-proxy")
	paths, secrets := prepareRuntime(t, workRoot, identity)
	runProduct(t, identity, binary, "--config", paths.config, "check", "config")
	credential := addCredential(t, identity, binary, paths.config, "e2e-client")
	fixtures := startFixtures(t, paths, secrets)
	server := startProduct(t, identity, binary, "--config", paths.config, "serve")
	waitForHealth(t, identity, binary, "127.0.0.1:9090")
	requireNoError(t, fixtures.client.reject(""))
	requireNoError(t, fixtures.client.reject(basicHeader("e2e-client", wrongSecret())))
	requireNoError(t, fixtures.client.roundTrip(basicHeader("e2e-client", credential.secret), secrets.sentinel))
	if fixtures.origin.Accepted() != 1 {
		t.Fatalf("origin accepted %d requests, want 1", fixtures.origin.Accepted())
	}
	stopGracefully(t, server, 12*time.Second)
}
~~~

Skip only when both environment variables are absent; fail if exactly one is set.

- [ ] **Step 2: Run and verify RED**

~~~bash
go test ./integration/e2e -run TestProductionBinaryE2E -count=1 -v
~~~

Expected: build failure because runtime/process helpers do not exist.

- [ ] **Step 3: Implement secure runtime preparation**

Create a random child below CEP_E2E_WORK_ROOT and verify its evaluated path remains beneath that root. Create:
- root-owned config directory mode 0755;
- root-owned config file mode 0644;
- service-owned state directory mode 0700;
- service-owned proxy certificate and key mode 0600.

Generate an instance ID and use exact addresses and names from the design: public listener 192.0.0.9:8443, admin 127.0.0.1:9090, supplied TLS proxy.e2e.invalid, explicit resolver 127.0.0.1:5353, public self 192.0.0.9, capacity 2, drain 5s, exact destination origin.e2e.invalid, default nonsensitive logging, and metrics disabled. Quote every absolute path with strconv.Quote.

- [ ] **Step 4: Implement dropped-identity commands and lifecycle**

Use os/user.Lookup and SysProcAttr.Credential for every product process. Capture stdout/stderr privately. Parse credential output for exactly device_identifier=e2e-client and one canonical 43-character base64url secret. Register cleanup immediately after Start.

Start DNS at 127.0.0.1:5353 and origin at 192.0.0.10:443. Poll production check health every 50 milliseconds for at most five seconds. Send SIGTERM and require exit zero within 12 seconds; on timeout, kill and wait for only that child, then fail with redacted evidence.

- [ ] **Step 5: Write the failing non-root runner test**

~~~go
func TestRunnerRejectsNonRootBeforeMutation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged caller")
	}
	cmd := exec.Command("bash", filepath.Join("..", "..", "scripts", "verify-e2e.sh"), "--preflight-only")
	output, err := cmd.CombinedOutput()
	if err == nil || string(output) != "e2e: root is required\n" {
		t.Fatalf("runner output = %q, %v", output, err)
	}
}
~~~

Run it and require failure because the script is absent.

- [ ] **Step 6: Implement strict runner ownership and cleanup**

The script uses set -Eeuo pipefail, requires UID zero, validates go, ip, getent, useradd, and userdel, and creates only mktemp -d /var/tmp/claude-egress-proxy-e2e.XXXXXXXX. It creates the service user only when absent and records ownership.

The trap terminates only PIDs returned by ip netns pids for its namespace, deletes only that random namespace, removes only the validated mktemp directory, and deletes only a user created by this run. Cleanup failure is fatal. --preflight-only performs no mutation.

- [ ] **Step 7: Build and run inside the namespace**

~~~bash
go mod download
CGO_ENABLED=0 go build -trimpath -o "$work/claude-egress-proxy" ./cmd/claude-egress-proxy
go test -c -o "$work/e2e.test" ./integration/e2e
ip netns add "$namespace"
ip -n "$namespace" link set lo up
ip -n "$namespace" address add 192.0.0.9/32 dev lo
ip -n "$namespace" address add 192.0.0.10/32 dev lo
ip netns exec "$namespace" env CEP_E2E_BINARY="$work/claude-egress-proxy" CEP_E2E_WORK_ROOT="$work/runtime" "$work/e2e.test" -test.v -test.run '^TestProductionBinaryE2E$'
~~~

Add scripts/verify-e2e.sh text eol=lf to .gitattributes.

- [ ] **Step 8: Verify locally through WSL**

~~~powershell
$wslRepo = wsl.exe -d Ubuntu -- wslpath -a -u (Get-Location).Path
wsl.exe -d Ubuntu -- bash "$wslRepo/scripts/verify-e2e.sh" --preflight-only
wsl.exe -d Ubuntu -u root -- bash "$wslRepo/scripts/verify-e2e.sh"
~~~

Expected: non-root preflight prints e2e: root is required. Root run exits zero and leaves no namespace, temporary directory, process, credential, or script-created service user.

- [ ] **Step 9: Verify and commit**

~~~bash
gofmt -w integration/e2e/e2e_linux_test.go integration/e2e/runner_linux_test.go
go test ./integration/e2e -count=1 -v
git add .gitattributes scripts/verify-e2e.sh integration/e2e/e2e_linux_test.go integration/e2e/runner_linux_test.go
git commit -m "test(e2e): run production binary"
~~~

---

### Task 3: GitHub Actions job and release documentation

**Files:**
- Create: integration/release/ci_e2e_policy_test.go
- Modify: .github/workflows/ci.yml
- Modify: docs/release-checklist.md

**Interfaces:**
- Produces: E2E GitHub check on pull requests and main.
- Produces: exact local WSL command in the release checklist.

- [ ] **Step 1: Write the failing semantic workflow test**

Decode ci.yml with yaml.v3 and assert the job contract.

~~~go
func TestCIE2EJobContract(t *testing.T) {
	workflow := loadCIWorkflow(t)
	job, ok := workflow.Jobs["e2e"]
	if !ok {
		t.Fatal("CI has no e2e job")
	}
	if job.Name != "E2E" || job.RunsOn != "ubuntu-latest" || job.TimeoutMinutes != 5 {
		t.Fatalf("E2E job = %+v", job)
	}
	if !job.Runs("sudo --preserve-env=PATH bash scripts/verify-e2e.sh") {
		t.Fatal("E2E job does not run the native harness")
	}
}
~~~

- [ ] **Step 2: Run and verify RED**

~~~bash
go test ./integration/release -run TestCIE2EJobContract -count=1 -v
~~~

Expected: FAIL with CI has no e2e job.

- [ ] **Step 3: Add the bounded job**

Reuse the repository's pinned action SHAs.

~~~yaml
  e2e:
    name: E2E
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
        with:
          go-version: '1.26.5'
          check-latest: true
      - name: Run native black-box E2E
        shell: bash
        run: sudo --preserve-env=PATH bash scripts/verify-e2e.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        if: failure()
        with:
          name: e2e-failure
          path: out/e2e
          if-no-files-found: ignore
          retention-days: 7
~~~

- [ ] **Step 4: Document and verify**

Add the exact WSL command from Task 2 to the release checklist. Require zero exit and green GitHub E2E status. State that the harness uses no Docker, public endpoint, or persistent credential.

~~~bash
go test ./integration/release -count=1 -v
go test ./integration/docs -count=1 -v
git diff --check
git add .github/workflows/ci.yml docs/release-checklist.md integration/release/ci_e2e_policy_test.go
git commit -m "ci: add native E2E job"
~~~

---

### Task 4: Full verification, pull request, and required status

**Files:**
- No planned source-file modification.
- Modify only an exposed defect's owner plus its focused regression test.

- [ ] **Step 1: Run complete Windows verification**

~~~powershell
$unformatted = @(gofmt -l (git ls-files -co --exclude-standard -- '*.go'))
if ($unformatted.Count -ne 0) { $unformatted; exit 1 }
go vet ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go test ./... -count=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git diff --check
~~~

- [ ] **Step 2: Run complete Linux and E2E verification**

~~~powershell
$wslRepo = wsl.exe -d Ubuntu -- wslpath -a -u (Get-Location).Path
wsl.exe -d Ubuntu -- bash -lc "cd '$wslRepo' && go test ./... -count=1"
wsl.exe -d Ubuntu -u root -- bash "$wslRepo/scripts/verify-e2e.sh"
~~~

- [ ] **Step 3: Perform mutation checks**

Apply and restore each mutation separately:
1. alter one expected sentinel byte; require inner-response failure;
2. alter the Basic secret; require 407 and zero origin requests;
3. suppress SIGTERM; require bounded shutdown failure.

Use apply_patch for each edit and restoration. Re-run the unmodified E2E after every restoration.

- [ ] **Step 4: Push and open the PR**

~~~bash
git push -u origin Qi/add-native-e2e-gate
gh pr create --repo hfjohn123/claude-egress-proxy --base main --head Qi/add-native-e2e-gate --title "ci: add native black-box E2E gate" --body "Adds a hermetic production-binary E2E gate using a Linux network namespace. Verifies supplied proxy TLS, disposable Basic authentication, CONNECT, inner origin TLS, exact relay bytes, health, and SIGTERM cleanup without Docker, public endpoints, or secrets."
~~~

- [ ] **Step 5: Require green checks and merge through review policy**

Require every existing check plus E2E to pass. Diagnose actual failures; do not retry unchanged failures. Obtain the configured approving review. Do not use administrator bypass without fresh explicit authorization for this PR.

- [ ] **Step 6: Add E2E without overwriting protection settings**

After merge and a green main run, re-read branch protection and update only required status checks:

~~~powershell
$repo = 'hfjohn123/claude-egress-proxy'
gh api --method PATCH "repos/$repo/branches/main/protection/required_status_checks" -F strict=false -f 'contexts[]=E2E'
~~~

If the subresource does not exist, update protection using every setting from the fresh read. Never replace protection from a stale snapshot.

- [ ] **Step 7: Verify the live gate**

Read protection again and require E2E plus unchanged review, administrator, force-push, deletion, conversation-resolution, and history settings. Record the merged commit, green Actions URL, local E2E result, and protection response.
