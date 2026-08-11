# README Quick Start Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a concise, accurate native-operation quick start to the repository README.

**Architecture:** Insert one cross-platform `Quick start` section before the existing operational-boundary section. Keep detailed platform setup in the linked deployment documents and use only CLI forms defined by `internal/cli/usage.go`.

**Tech Stack:** Markdown, Go CLI contract tests

## Global Constraints

- Modify `README.md` only for the user-facing implementation.
- Do not document the E2E harness or make Docker the primary path.
- Do not place real endpoints, credentials, or personal paths in examples.
- Keep the admin listener loopback-only and distinguish foreground from service operation.
- Do not place a credential in a proxy URL example.

---

### Task 1: Add and verify the native quick start

**Files:**
- Modify: `README.md`
- Reference: `internal/cli/usage.go`
- Reference: `docs/configuration.md`
- Reference: `docs/deploy-home.md`
- Reference: `docs/deploy-vps.md`
- Reference: `docs/client-configuration.md`

**Interfaces:**
- Consumes: the public command grammar exported by `internal/cli/usage.go` and the deployment/security boundaries in the existing documentation.
- Produces: a `README.md` quick start that an operator can follow from release download through health verification.

- [ ] **Step 1: Insert the quick-start section**

Add the following section immediately before `## Boundaries and operation`:

````markdown
## Quick start

Download the native artifact for your operating system and architecture from
[GitHub Releases](https://github.com/hfjohn123/claude-egress-proxy/releases),
verify it against `SHA256SUMS`, and place the executable on the server's `PATH`.
Use absolute paths chosen for the target platform; the deployment guides cover
the required ownership and service permissions.

1. Generate the configuration and state directory:

   ```text
   claude-egress-proxy --config <absolute-config-file> init --state-root <absolute-state-directory>
   ```

2. Edit the generated configuration for the public hostname, listener, TLS
   mode, resolver, public server addresses, and allowed destinations. Follow
   the [home](docs/deploy-home.md) or [VPS](docs/deploy-vps.md) guide for DNS,
   TCP 443, NAT/firewall, and ACME requirements.

3. Validate the configuration and host network:

   ```text
   claude-egress-proxy --config <absolute-config-file> check config
   claude-egress-proxy --config <absolute-config-file> check network
   ```

4. Create a separate credential for each client device:

   ```text
   claude-egress-proxy --config <absolute-config-file> credential add --device <device-identifier>
   ```

   The credential secret is emitted once. Store it securely, never commit or
   log it, and revoke it if that device is lost or compromised.

5. Start the proxy in the foreground:

   ```text
   claude-egress-proxy --config <absolute-config-file> serve
   ```

   For persistent operation, install and start the native service instead:

   ```text
   claude-egress-proxy --config <absolute-config-file> service install
   claude-egress-proxy --config <absolute-config-file> service start
   ```

6. Configure a supported client separately with the server's HTTPS proxy
   hostname, TCP port 443, and the per-device Basic credential. See
   [client approaches](docs/client-configuration.md); the proxy does not install
   or enforce client settings.

7. If the generated loopback admin listener is enabled at its default address,
   verify local readiness:

   ```text
   claude-egress-proxy check health --address 127.0.0.1:9090
   ```

Keep the admin listener on loopback only. Read the
[security guide](docs/security.md) before exposing the public listener.
````

- [ ] **Step 2: Verify the documented command grammar**

Compare every command in `README.md` with `internal/cli/usage.go`. Confirm that
`check health` intentionally omits `--config`, all other configuration-bound
commands place `--config` before the command, and every placeholder appears
inside a fenced code block.

- [ ] **Step 3: Run documentation and repository checks**

Run:

```powershell
git diff --check
go test ./integration/docs ./integration/release
go test ./...
```

Expected: all commands exit 0 with no failed tests.

- [ ] **Step 4: Review the final diff and commit**

Run:

```powershell
git diff -- README.md
git status --short
```

Confirm only `README.md` is staged for the implementation commit and the two
pre-existing untracked release binaries remain unstaged. Commit with:

```powershell
git add -- README.md
git commit -m "docs: add native proxy quick start"
```
