# Anthropic Suffix and CONNECT Error Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add future-compatible Anthropic web-domain suffix coverage and ensure post-hijack CONNECT failures attempt their HTTP response before coordinator cleanup closes the client socket.

**Architecture:** `policy/profiles.yaml` remains the source for generated built-in profiles. Only `web-desktop` gains `anthropic.com` and `claude.com` suffix roots, so `all` inherits them while `code` remains narrow. A focused proxy helper flushes the terminal frame before invoking a release closure; session rejection paths defer handler-owned cleanup long enough to use that ordering.

**Tech Stack:** Go 1.26.5, `net/http`, the existing session coordinator, generated profiles, PowerShell 5.1, and Windows SCM.

## Global Constraints

- Add only the suffix roots `anthropic.com` and `claude.com`.
- Keep the standalone `code` profile's exact-host boundary.
- Deny adjacent and noncanonical hostnames.
- Keep `statsig.anthropic.com` covered without claiming it currently resolves.
- Release exactly once even when the response write fails.
- Do not rotate or emit browser, Claude Code, or metrics credentials.
- Keep the admin listener loopback-only and public TCP 9090 closed.
- Do not modify or commit the existing untracked diagnostic tool directories.

---

### Task 1: Built-in destination suffixes

**Files:**
- Modify: `policy/profiles.yaml`
- Modify: `internal/policy/policy_test.go`
- Regenerate: `internal/policy/generated_profiles.go`
- Regenerate: `docs/reference/profiles.md`

**Interfaces:**
- Consumes: `Load(profile string, custom CustomRules) (Policy, error)` and `Policy.MatchHost(string) bool`.
- Produces: suffix coverage in `web-desktop` and `all`, with unchanged narrow `code` behavior.

- [ ] Add `TestBuiltInAnthropicWebSuffixBoundaries`, requiring `web-desktop` and `all` to accept `anthropic.com`, `www.anthropic.com`, `future.cdn.anthropic.com`, `claude.com`, `support.claude.com`, and `future.web.claude.com`; require rejection of `evilanthropic.com`, `evilclaude.com`, and uppercase noncanonical forms; require `code` to reject `www.anthropic.com` and `support.claude.com`.
- [ ] Run `go test ./internal/policy -run TestBuiltInAnthropicWebSuffixBoundaries -count=1`; expect RED on the new web hosts.
- [ ] Remove suffix-covered exact hosts from `web-desktop` in the manifest; add sorted suffixes `anthropic.com` and `claude.com`; do not change `code`.
- [ ] Run `go run ./internal/tools/profilegen`.
- [ ] Run `go test ./internal/policy ./internal/tools/profilegen` and `go run ./internal/tools/profilegen -check`; expect GREEN.
- [ ] Commit with `git commit -m "feat: allow Anthropic web domain suffixes"`.

---

### Task 2: CONNECT failure response ordering

**Files:**
- Modify: `internal/proxy/connect.go`
- Modify: `internal/proxy/connect_test.go`
- Modify: `internal/session/coordinator.go`
- Modify: `internal/session/handoff_test.go`

**Interfaces:**
- Consumes: `writeFrame`, `Handoff.Release`, and `Reservation.Release`.
- Produces: `writeFrameThenRelease(rw *bufio.ReadWriter, frame wire.Frame, release func())`.

- [ ] Add a writer-backed test that records events and requires `write,release` ordering for `FrameBadGateway`.
- [ ] Add a forced-write-failure test requiring the supplied release closure to run exactly once.
- [ ] Add session tests proving transfer and commit rejection preserve caller ownership until explicit release, after which the connection closes and coordinator state clears.
- [ ] Run focused proxy and session tests; expect RED because the helper is absent and rejection currently releases internally.
- [ ] Implement `writeFrameThenRelease` as an attempted `writeFrame` followed unconditionally by one `release()` call.
- [ ] Replace handler-controlled release-before-write branches for transfer rejection, public-self failure, missing/failed DNS, dial failure, and commit rejection with record, write/flush, then release.
- [ ] Change `Coordinator.Transfer` and `Coordinator.Commit` rejection paths to return ownership for handler cleanup instead of pre-closing it; preserve idempotence under concurrent invalidation.
- [ ] Run `go test ./internal/proxy ./internal/session ./internal/network ./internal/wire ./internal/contract -count=1`; expect GREEN.
- [ ] Commit with `git commit -m "fix: deliver CONNECT errors before cleanup"`.

---

### Task 3: Full verification and release binary

**Files:**
- Create outside Git: `work/build/claude-egress-proxy-<commit>.exe`

**Interfaces:**
- Consumes: the committed worktree and Go 1.26.5.
- Produces: a verified Windows binary and SHA-256 digest.

- [ ] Run `gofmt` on every modified Go file, `go run ./internal/tools/profilegen -check`, and `git diff --check`.
- [ ] Run `go mod download`, `go mod verify`, `go test ./...`, `go vet ./...`, and `go list ./...`; require every command to exit 0.
- [ ] Build with `go build -trimpath -o .\build\claude-egress-proxy-<commit>.exe ./cmd/claude-egress-proxy`.
- [ ] Compute and record the binary SHA-256 digest.

---

### Task 4: Deploy, regenerate PAC, and verify end to end

**Files:**
- Modify: `work/deployment/Apply-ProxyAnthropicHosts.ps1`
- Modify: `work/deployment/Apply-ProxyAnthropicHosts.Tests.ps1`
- Modify: `outputs/claude-egress-proxy-all.pac`
- Modify: `outputs/claude-egress-proxy-handoff.md`

**Interfaces:**
- Consumes: the verified release binary, existing installed config, service, and credentials.
- Produces: the updated running service and a credential-free PAC matching both roots and dotted subdomains.

- [ ] Update deployment tests to require suffix PAC coverage, adjacent-domain `DIRECT`, no embedded credentials, and preservation of token/credential artifacts.
- [ ] Run the deployment test and observe RED against the exact-host implementation.
- [ ] Update the bounded script to validate old/new binary hashes, stop the service, atomically replace only the executable, keep custom suffixes empty, validate config, generate a credential-free suffix PAC, restart, and poll health.
- [ ] Run deployment tests GREEN, then execute the script locally with administrator rights available to the current session or one bounded elevated PowerShell process.
- [ ] Verify public trusted TLS, service auto/running, DDNS current, admin loopback-only, and public 9090 closed.
- [ ] Use a disposable in-memory credential to prove CONNECT 200 plus inner TLS for the reported Anthropic/Claude hosts, 403 for adjacent domains, and a complete error response rather than EOF for a controlled unreachable allowed destination.
- [ ] Revoke and purge the disposable credential in `finally`; verify it is absent and emit no secret.
- [ ] Update the handoff with suffix coverage, the current NXDOMAIN observation, CONNECT ordering fix, commit/hash, and closed verification results.
- [ ] Commit only repository-owned changes and confirm the only remaining worktree status entries are the two pre-existing untracked diagnostic directories.
