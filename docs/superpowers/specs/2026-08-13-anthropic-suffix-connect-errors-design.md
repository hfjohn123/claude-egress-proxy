# Anthropic Domain Suffixes and CONNECT Error Delivery Design

## Goal

Keep the `all` deployment functional as Anthropic introduces new web endpoints, while preserving the narrower Claude Code profile and ensuring a hijacked CONNECT client receives its terminal HTTP error before connection cleanup.

## Evidence

- A test client needed `anthropic.com`, `www.anthropic.com`, `www.claude.com`, and `support.claude.com` in addition to previously observed CDN hosts.
- `anthropic.com` and `claude.com` are registrable Anthropic-controlled domains, not public suffixes. The policy package already recognizes both as trusted custom suffix roots.
- On 2026-08-13, the system resolver, Cloudflare DNS, and Google DNS all returned NXDOMAIN for `statsig.anthropic.com`. Anthropic's published Claude Code corporate-proxy documentation still lists that exact hostname, so current DNS absence is not sufficient evidence to remove compatibility coverage.
- In post-hijack setup failures, `reservation.Release` calls `handoff.releaseLocked`, which closes the attached client connection. The handler currently calls `Release` before `writeFrame`, so intended 502/503 responses are written to an already closed socket.

## Destination Policy

The built-in `web-desktop` profile will use suffix rules for `anthropic.com` and `claude.com`. Exact hosts covered by either suffix will be removed from that profile. The existing `claude.ai` and `claudeusercontent.com` suffixes remain unchanged.

The built-in `code` profile remains least-privilege: its existing exact `anthropic.com` and `claude.com` hosts remain exact, while its existing `claude.ai` suffix remains. The `all` profile continues to be the union of `code` and `web-desktop`, so it inherits the two new web suffixes without weakening the standalone `code` profile.

The generated PAC for the deployed `all` profile will route the roots and dotted subdomains of `anthropic.com` and `claude.com`. It will not contain credentials. Adjacent lookalikes such as `evilanthropic.com` and `evilclaude.com` must remain direct and must remain denied by server policy.

`statsig.anthropic.com` requires no special exact rule after the suffix change. Documentation will record that it is currently NXDOMAIN but remains covered if Anthropic restores it.

## CONNECT Failure Ordering

For failures after the client connection has been hijacked and attached, the handler owns an ordered terminal sequence:

1. Select the canonical connect result and public HTTP frame.
2. Record the setup result.
3. Write and flush the public frame while the client connection is still owned and open.
4. Release the handoff or reservation exactly once, allowing coordinator cleanup to close the connection and release capacity.

This ordering applies to transfer rejection, unavailable public-self state, missing or failed DNS resolution, and dial failure. Pre-hijack paths continue using normal `net/http` response handling. Established tunnels retain their existing tunnel-release lifecycle.

The change does not promise that a frame can always be delivered: a client disconnect or concurrent credential invalidation can still make the write fail. It guarantees that the normal handler path does not itself close the socket before attempting the response.

## Timeout Semantics

This change fixes response delivery order without redefining outcome classification. Existing DNS and dial failures continue to use their current canonical frames. Any separate change mapping an exhausted overall setup deadline to `setup_timeout`/504 requires its own evidence and test because it changes the public contract beyond the reported cleanup defect.

## Verification

Automated tests will prove:

- `web-desktop` and `all` match each suffix root and arbitrary dotted subdomains;
- `code` retains its current exact-host boundary for `anthropic.com` and `claude.com` endpoints;
- adjacent and noncanonical domains remain denied;
- profile generation is reproducible from the manifest;
- representative DNS and dial failures flush the intended frame before release closes the client connection;
- release/accounting remains exactly once when the frame write itself fails;
- the complete Go test, vet, module verification, package-list, and profile-generator checks pass.

Deployment verification will rebuild the pinned binary, atomically replace the installed service binary while stopped, validate the managed configuration, restart the service, and check local health, trusted public TLS, authenticated proxy behavior, suffix coverage, adjacent-domain denial, PAC coverage, and continued closure of public port 9090. Existing browser and Claude Code credentials are not rotated or exposed.

## Scope

Included: built-in profile manifest/generated documentation, PAC generation or deployment artifacts needed for the new `all` behavior, CONNECT failure ordering, regression tests, rebuilt binary, and verified local deployment.

Excluded: router changes, credential rotation, metrics-token changes, removal of documented-but-currently-NXDOMAIN endpoints, and unrelated diagnostic tools already present as untracked worktree files.
