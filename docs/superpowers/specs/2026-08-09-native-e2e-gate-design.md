# Native Black-Box E2E Gate Design

## Goal

Add a lightweight, hermetic end-to-end gate that runs the unmodified Linux
production binary through its real configuration, credential, TLS, policy,
DNS, CONNECT, relay, health, and shutdown paths. The same harness must run in
WSL2 locally and in GitHub Actions without Docker, public Internet access,
Anthropic credentials, ACME, or repository secrets.

The GitHub Actions check is named `E2E`, runs for every pull request and every
push to `main`, and becomes a required status check on the protected `main`
branch after the workflow lands.

## Non-goals

- Do not contact Anthropic, Claude, a public DNS resolver, or any public origin.
- Do not exercise ACME, systemd installation, Windows SCM, or Windows binaries.
- Do not add a production test mode, build tag, dependency-injection bypass, or
  SSRF-policy exception.
- Do not inspect or log tunneled payloads in the proxy. Test fixtures may create
  and verify their own one-time sentinel bytes at the two ends of the tunnel.
- Do not retain credentials, private keys, network namespaces, users, processes,
  or temporary state after the run.

## Architecture

`scripts/verify-e2e.sh` is the privileged orchestration boundary. It downloads
modules before isolation, builds the production executable, compiles the E2E
test binary, creates one Linux network namespace, runs the compiled test inside
that namespace, and removes every resource through an unconditional shell
trap. It refuses to run unless it is root and required tools are available.

`integration/e2e/e2e_linux_test.go` is an external black-box test. It never
imports application internals and communicates with the product only through
the executable's CLI, files, signals, and TCP sockets. Standard-library code
generates an ephemeral CA and leaf certificates, while
`golang.org/x/net/dns/dnsmessage` implements the bounded fake DNS responder.

The harness creates the `claude-egress-proxy` system identity only when it is
absent, records whether it owns that mutation, and deletes only an identity it
created. Product commands run with that identity's UID and GID. Fixture DNS,
origin, and client code remain in the privileged test process inside the
isolated namespace.

## Isolated Network

The namespace owns only loopback and two addresses that the existing policy
already classifies as global IPv4:

- `192.0.0.9:8443`: supplied-TLS proxy listener
- `192.0.0.10:443`: fake HTTPS origin
- `127.0.0.1:9090`: proxy administrative listener
- `127.0.0.1:5353`: fake DNS over UDP and TCP

The configuration uses `proxy.e2e.invalid` as the supplied-certificate name,
`origin.e2e.invalid` as its single custom exact destination, an explicit
resolver at `127.0.0.1:5353`, and `public_self_ipv4s: [192.0.0.9]`. The DNS
fixture returns only `192.0.0.10` for the exact origin name and rejects every
other question. No veth pair, default route, or external namespace interface is
created, so the test cannot reach the host or Internet network.

## Filesystem and Identity Contract

Each run creates a random directory below `/var/tmp` and keeps it outside the
source checkout. The configuration directory and file are root-owned with
modes `0755` and `0644`. The state root is owned by the
`claude-egress-proxy` UID and GID with mode `0700`; certificate, key, and
credential-store files are owned by that identity with mode `0600`.

The test generates one ephemeral instance ID, CA, proxy certificate, origin
certificate, and disposable proxy credential. It invokes the production
`credential add --device e2e-client` command and parses only the documented
`device_identifier` and `secret` fields. The secret is retained in memory,
never placed on a command line, and never included in diagnostic output.

## E2E Sequence and Pass Criteria

1. Run the production `check config` command against the generated file and
   require exit code zero with no fatal diagnostic.
2. Start fake UDP/TCP DNS and the TLS origin, then start the production
   `serve` command as the service identity.
3. Poll the production `check health --address 127.0.0.1:9090` command until it
   succeeds or a bounded startup deadline expires.
4. Establish outer TLS to `192.0.0.9:8443` with SNI
   `proxy.e2e.invalid`, certificate-chain verification against the ephemeral
   CA, and HTTP/1.1 ALPN.
5. Send CONNECT once without `Proxy-Authorization` and once with an incorrect
   disposable credential. Both requests must receive `407 Proxy Authentication
   Required` and close without reaching the origin.
6. Open a fresh verified outer-TLS connection, send strict Basic authentication
   using `e2e-client` and the generated secret, and require an exact
   `200 Connection Established` response.
7. Negotiate a second verified TLS session through that tunnel using SNI
   `origin.e2e.invalid`. Send an HTTP/1.1 request containing a random one-time
   sentinel. The fake origin returns that sentinel, and the client requires an
   exact byte match. The origin also requires exactly one authenticated request,
   proving rejected authentication attempts never reached it.
8. Close the tunnel, send `SIGTERM` to the serving process, and require a clean
   exit code within the configured five-second drain plus a bounded allowance.
   A timeout, forced kill, nonzero exit, leaked child, or missing cleanup fails
   the gate.

The proxy configuration keeps `logging.sensitive_metadata: false`. Failure
output may include process exit codes, closed diagnostics, listener names, and
sanitized proxy logs, but never the generated secret, private keys, Basic
header, or sentinel payload.

## Failure Handling and Cleanup

Every socket operation, startup poll, process wait, TLS handshake, and HTTP
exchange has an explicit deadline. The Go test registers cleanup immediately
after each process or filesystem mutation. The shell wrapper's trap is the
last-resort owner: it terminates the namespace process group, deletes the
namespace, removes the temporary directory, and removes the service identity
only when this run created it.

Cleanup failures are reported and fail the run. Existing users, namespaces,
paths, or processes are never adopted or deleted: randomly named resources and
identity-before-mutation checks make ownership explicit.

## GitHub Actions Gate

`.github/workflows/ci.yml` gains an Ubuntu job with display name `E2E`,
`contents: read`, and `timeout-minutes: 5`. After checkout and Go `1.26.5`
setup, it executes:

```bash
sudo --preserve-env=PATH bash scripts/verify-e2e.sh
```

The job has no secrets and no network dependency after the normal checkout,
toolchain, and module-download phase. The script builds the test binary before
entering the namespace. CI uploads only sanitized failure evidence when the
gate fails; successful runs retain no artifact.

Once the workflow is merged and the `E2E` check exists, repository branch
protection is updated to require the exact `E2E` context. Existing review,
force-push, deletion, and administrator settings remain unchanged.

## Local Execution

Windows runs the same Linux harness through the installed WSL2 Ubuntu distro:

```powershell
$wslRepo = wsl.exe -d Ubuntu -- wslpath -a -u (Get-Location).Path
wsl.exe -d Ubuntu -u root -- bash "$wslRepo/scripts/verify-e2e.sh"
```

The script prints one concise pass/fail summary and the sanitized phase that
failed. It does not require Docker Desktop, Windows elevation, or a persistent
Linux service installation.

## Test Strategy

Implementation follows red-green cycles at observable boundaries:

- certificate generation must fail verification for the wrong SNI before leaf
  generation is implemented;
- DNS must reject unknown names and return the one literal address for the
  allowed origin;
- the client must fail against a fixture that omits the required CONNECT
  status or mutates the sentinel;
- the orchestration test must fail when the production proxy is absent, when
  authentication is rejected, and when graceful shutdown does not complete;
- the complete namespace harness must then pass using the unmodified production
  binary.

The normal `go test ./...`, race tests, formatting, vet, generated-file checks,
security scans, and release workflow remain independent gates.
