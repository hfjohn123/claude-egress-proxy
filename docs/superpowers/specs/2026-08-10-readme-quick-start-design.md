# README Quick Start Design

## Goal

Add a concise, cross-platform quick start to the repository README so an
operator can move from a downloaded native binary to a running authenticated
proxy without treating the README as a replacement for the deployment and
security guides.

## Scope

The change modifies `README.md` only. It documents native operation of the
proxy; it does not document the E2E harness, add container-first instructions,
change runtime behavior, or claim that the project configures or enforces
client proxy settings.

## Content

Insert a `Quick start` section before `Boundaries and operation`. The section
will:

1. Direct operators to download the native release artifact and use absolute
   paths for configuration and state.
2. Show the exact `init` command grammar with cross-platform path placeholders.
3. Direct operators to edit the generated configuration for their hostname,
   listener, TLS, and allowed destination, with links to the home and VPS
   deployment guides.
4. Show `check config` and `check network` before startup.
5. Show creation of a unique per-device credential and state that its secret
   must be stored securely because it is emitted only once.
6. Show foreground startup with `serve` and native service installation/start
   as the persistent alternative.
7. Explain that a supported client must be configured separately with the
   HTTPS proxy address and per-device Basic credential, linking to the client
   approaches document without placing a secret in a URL example.
8. Show the loopback health check and retain the existing warning that the
   project is pre-release software.

## Safety and Compatibility

- Commands must match `internal/cli/usage.go` exactly.
- Examples must not contain real endpoints, credentials, or personal paths.
- The public proxy listener is TCP 443; the admin listener remains loopback
  only and must never be exposed publicly.
- The README must distinguish foreground execution from native service
  operation and remain valid on both Linux and Windows.
- Detailed platform ownership, firewall, NAT, DNS, and ACME steps remain in the
  linked deployment guides.

## Verification

Review each command against the CLI usage table, run the repository's Markdown
or documentation checks if present, and run `go test ./...` to catch policy
tests that validate documentation or command contracts.
