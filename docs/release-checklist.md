# Release checklist

- Generate and validate configuration; check the generated profile separately.
- Confirm public TCP 443 and TLS-ALPN-01 reachability from an external network.
- Keep admin and insecure loopback listeners private.
- Run `go test ./...` and inspect closed telemetry/log schemas.
- Run the native black-box E2E from an elevated WSL2 Ubuntu environment:

  ```powershell
  wsl.exe -d Ubuntu --cd (Get-Location).Path -u root -- bash scripts/verify-e2e.sh
  ```

  Require a zero exit code and a green GitHub `E2E` status. The harness uses
  no Docker daemon, public endpoint, repository secret, or persistent
  credential.
- Run the opt-in `scripts/verify-claude-code-interop.ps1` only in a provisioned
  release environment; retain its sanitized version/result evidence.
- Update [compatibility](compatibility.md) with actual date, version, result,
  and evidence. Do not turn an unknown or failed result into a claim.
- Rotate disposable credentials after compatibility work and rotate all secrets
  after checkpoint restore.
