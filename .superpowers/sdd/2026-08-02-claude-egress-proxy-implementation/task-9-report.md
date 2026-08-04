# Task 9 report

## Securefs Windows rotation namespace

### RED

`GOOS=windows GOARCH=amd64 go test -c ./internal/securefs` failed as expected
on 2026-08-04: `(*mutableRoot).AcquireRotationNamespace` was undefined in
`rotation_windows_test.go`.

### GREEN / verification

- `go test ./internal/securefs -run TestAcquireRotationNamespaceRejectsUnsafeLeaves -v`: PASS.
- `GOOS=windows GOARCH=amd64 go test -c ./internal/securefs`: PASS.
- `GOOS=windows GOARCH=amd64 go vet ./internal/securefs`: PASS.
- `go test ./internal/securefs`: PASS.
- Windows race compilation was attempted with `CGO_ENABLED=1`; it is blocked
  on this host because `gcc` is absent from `PATH`.

## Securefs Linux rotation namespace

### RED

`GOOS=linux GOARCH=amd64 go test -c ./internal/securefs` failed as expected on
2026-08-04: `*mutableRoot` did not implement `MutableRoot` because
`AcquireRotationNamespace` was absent. The Linux contract test also had no
shared rotation-policy helper.

### GREEN / verification

- Added `rotation_linux.go` with dirfd/no-follow retained files, the lifetime
  `base.lock` flock, restricted `base.delete`, allowed-generation gate, and
  identity-checked `renameat2(RENAME_EXCHANGE)` rotation with handle truncation.
- Added `rotation_linux_test.go`, including generation ordering, retained active
  truncation, and coordination-name rejection.
- Moved the shared namespace-policy helpers from the Windows-only source into
  `lock.go`; this is the only Windows-related compile fix.
- `GOOS=linux GOARCH=amd64 go test -c ./internal/securefs`: PASS (the Linux
  binary cannot run on this Windows host).
- `GOOS=windows GOARCH=amd64 go test -c -o $env:TEMP\\securefs-windows-task9.test.exe ./internal/securefs`: PASS.
- `go test ./internal/securefs`: PASS.
- `go vet ./internal/securefs`: PASS.
