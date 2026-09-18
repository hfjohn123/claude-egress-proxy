# Prefix TTL Renewal and Capacity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Renew retained active source-prefix entries at TTL expiry and raise mapped-prefix pre-authentication capacity from 16 to 32.

**Architecture:** Keep `prefixMap` generation and cleanup semantics intact. Handle the retained-expired case only in `Public.Acquire`, renewing its deadline without resetting the bucket, then continue through existing capacity and token checks. Change the single contract constant for mapped-prefix active capacity while preserving every other limit.

**Tech Stack:** Go 1.26.5, fake-clock admission tests, existing contract constants, PowerShell 5.1 Windows-service deployment.

## Global Constraints

- Preserve the limiter entry pointer, generation, bucket, and token state across renewal.
- Keep global pre-auth capacity 128, global tunnel capacity 256, device capacity 64, mapped start rate 5/s, and mapped burst 10.
- Do not change authentication or PAC limiter behavior.
- Do not read, rotate, persist, or emit existing credentials or metrics tokens.
- Keep public TCP 9090 closed and the admin listener loopback-only.
- Do not modify or commit the two existing untracked diagnostic tool directories.

---

### Task 1: Renew an expired active public prefix

**Files:**
- Modify: `internal/admission/public_test.go`
- Modify: `internal/admission/public.go`

**Interfaces:**
- Consumes: `Public.Acquire(Prefix) (PublicLease, Decision)` and `LimiterEntryTTL`.
- Produces: retained active entries resume ordinary admission after their eviction deadline without resetting limiter state.

- [ ] Add `TestPublicExpiredActivePrefixRenewsWithoutReset` using `testClock`. Acquire one lease, capture the mapped entry pointer, generation, bucket, and original expiry, advance by exactly `LimiterEntryTTL`, acquire again, and require `DecisionAllowed`, the same entry/generation/bucket state, a later expiry, and active count 2.
- [ ] Run `go test ./internal/admission -run TestPublicExpiredActivePrefixRenewsWithoutReset -count=1`; expect RED with `DecisionThrottled`.
- [ ] In `Public.Acquire`, replace the `entryExpired` rejection with `entry.expires = now.Add(p.limits.LimiterEntryTTL)` and continue as `entryExisting`.
- [ ] Release both leases and require active count 0; run `go test ./internal/admission -count=1`; expect GREEN.
- [ ] Commit with `git commit -m "fix: renew active prefix admission TTL"`.

---

### Task 2: Raise mapped-prefix active capacity to 32

**Files:**
- Modify: `internal/contract/constants_test.go`
- Modify: `internal/admission/public_test.go`
- Modify: `internal/contract/constants.go`

**Interfaces:**
- Consumes: `contract.V1().MappedPrefixActive`.
- Produces: exactly 32 concurrent pre-authentication leases per mapped source prefix.

- [ ] Change the contract assertion to require mapped-prefix active capacity 32.
- [ ] Add `TestPublicMappedPrefixAllowsThirtyTwoActive` with a fake clock whose token bucket is advanced between acquisitions as needed; retain 32 leases, require each acquisition allowed, require the 33rd to return `DecisionThrottled`, then release all leases and require active count 0.
- [ ] Run the two focused tests and observe RED because the current contract remains 16.
- [ ] Change only `MappedPrefixActive` in `contract.V1()` from 16 to 32.
- [ ] Run `go test ./internal/contract ./internal/admission -count=1`; expect GREEN.
- [ ] Commit with `git commit -m "feat: raise mapped prefix handshake capacity"`.

---

### Task 3: Full verification and binary build

**Files:**
- Create outside Git: `work/build/claude-egress-proxy-<commit>.exe`

**Interfaces:**
- Consumes: committed branch source.
- Produces: a verified `-trimpath` Windows binary and SHA-256 digest.

- [ ] Run `gofmt` on modified Go files, `go run ./internal/tools/profilegen -check`, and `git diff --check`.
- [ ] Run `go mod download`, `go mod verify`, `go test ./... -count=1`, `go vet ./...`, and `go list ./...`; require exit 0 throughout.
- [ ] Build with `go build -trimpath -o .\build\claude-egress-proxy-<commit>.exe ./cmd/claude-egress-proxy` and record SHA-256.

---

### Task 4: Atomic live deployment and smoke verification

**Files:**
- Create or modify: `work/deployment/Upgrade-ProxyPrefixAdmission.ps1`
- Create or modify: `work/deployment/Upgrade-ProxyPrefixAdmission.Tests.ps1`
- Modify: `outputs/claude-egress-proxy-handoff.md`

**Interfaces:**
- Consumes: old/new approved binary hashes and the running Windows service.
- Produces: updated automatic/running service with unchanged configuration and credential store.

- [ ] Write a deployment safety test requiring elevation, exact old/new hashes, stopped-service atomic `MoveFileExW` replacement, config and credential metadata preservation, bounded restart/health, and no credential/admin-token operations.
- [ ] Run the deployment test RED before the script exists or satisfies the new hash.
- [ ] Implement the bounded idempotent upgrade script; stop only for replacement, verify copied hash, atomically replace the executable, restart, and report closed fields.
- [ ] Run deployment tests GREEN, then execute the script in the current elevated session.
- [ ] Run the existing suffix-specific disposable verification and full disposable smoke: trusted TLS, allowed/denied CONNECT, complete NXDOMAIN 502, disposable revoke/purge/absence, service auto/running, public 443, public 9090 closed, DDNS current, and no secret emission/persistence.
- [ ] Verify installed hash, loopback-only 9090 listener, both persistent operator device records present, disposable records absent, PAC suffixes unchanged, and output secret scan clean.
- [ ] Update the handoff with commit, hash, TTL renewal, capacity 32, and verification results. Keep the branch/worktree for the later PR.
