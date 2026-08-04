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

## Telemetry file sink

### RED

`go test ./internal/telemetry -run TestValidateFileSinkRejectsUnsafeBase -count=1`
failed as expected on 2026-08-04 because `ValidateFileSink`, `CheckOnly`, and
`ErrInvalidFileSink` did not exist.

### GREEN / verification

- Added `sink_file.go` with strict canonical-record validation, check-only
  identity/metadata/digest snapshots, repairable active-tail and tombstone
  handling, retained-namespace ownership, bounded rotation, and permanent
  write-failure handling.
- Added ordinary CheckOnly fixtures and a Windows restricted-ACL integration
  fixture covering creation of active, backups, lock, tombstone, and a record
  append.
- `go test ./internal/telemetry -count=1`: PASS.
- `go vet ./internal/telemetry`: PASS.
- `go test -tags=cep_testcontrol ./internal/telemetry -run 'Test(File|Rotation|Recovery|EventLog)' -count=1 -v`: PASS.
- `GOOS=linux GOARCH=amd64 go test -c ./internal/telemetry`: PASS.
- `GOOS=windows GOARCH=amd64 go test -c ./internal/telemetry`: PASS.

## Securefs Windows retained tombstone repair

### RED

`go test ./internal/securefs -run TestWindowsRotationNamespaceExposesTombstoneRepair -v`
failed as expected on 2026-08-04: `(*windowsRotationNamespace).RepairTombstone`
was undefined.

### GREEN / verification

- Added retained-handle identity/attachment check, truncate, and flush; it
  serializes with rotation and performs no pathname mutation.
- `go test ./internal/securefs -run 'Test(WindowsRotationNamespaceExposesTombstoneRepair|AcquireRotationNamespaceRejectsUnsafeLeaves)' -v`: PASS.
- `GOOS=linux GOARCH=amd64 go test -c ./internal/securefs`: PASS.

## Securefs Linux retained tombstone repair

### RED

`GOOS=linux GOARCH=amd64 go test -c -o $env:TEMP\\securefs-linux-task9-red.test ./internal/securefs`
failed as expected on 2026-08-04: `RotationNamespace.RepairTombstone` was
undefined in the focused retained-tombstone test.

### GREEN / verification

- Added `RepairTombstone` to the shared namespace contract and Linux
  implementation. It serializes with rotation, rechecks the retained
  `.delete` attachment/identity, then truncates and fsyncs the same descriptor.
- `GOOS=linux GOARCH=amd64 go test -c -o $env:TEMP\\securefs-linux-task9-green.test ./internal/securefs`: PASS.
- `GOOS=windows GOARCH=amd64 go test -c -o $env:TEMP\\securefs-windows-task9-api.test.exe ./internal/securefs`: PASS.

## Telemetry file-sink deterministic oracle and fault matrix

### RED

- The first deterministic oracle fixture failed because it could not form a
  valid 511-byte canonical record; the corrected host-label generator supplied
  a 512-byte (including LF), distinguishable record.
- `TestValidateFileSinkRejectsFourthGeneration` then failed as expected:
  CheckOnly accepted `events.3`, demonstrating the missing forbidden-member
  check.

### GREEN / verification

- Added a test-only `MutableRoot`/`RotationNamespace`/`RetainedFile` harness
  with stable zero identities and injected validation, close, rotate/delete/
  rename, create, truncate, partial-write, and write failures.
- The oracle proves no rotation at 20,480 records, pre-write rotation at
  20,481, and active/`.1`/`.2` ordering plus deletion through record 61,441.
- Added startup presence, active-tail/no-LF, corrupt backup, member/30 MiB
  boundary, tombstone repair, CheckOnly, and Close-detach coverage.
- Added production rejection of an observable `base.3` member before CheckOnly,
  repair, or Open proceeds.
- `go test ./internal/telemetry -run 'Test(FileSinkRotationOracle512BytesThrough61441Records|ValidateFileSink|OpenFileSinkRepairsOnlyCanonicalTailAndTombstone|FileSinkFaults)' -count=1 -v`: PASS.
- `go vet ./internal/telemetry`: PASS.

## Task 9 review fix wave (partial)

- Added pre-mutation reopened-handle identity checks to Windows rotation.
- Added exported restricted-file policy validation; file sinks reject identity-only policy.
- Added `.3` to CheckOnly snapshots, changed interrupted active-tail repair to
  discard unframed suffix bytes within the permitted window, and added prompt
  Event Log Close while report is blocked.
- Regenerated Windows Event Log resources with `%1%0`.
- `go test ./...`, `go vet ./...`, tagged Event Log tests, resource `-Verify`,
  and Linux/Windows amd64+arm64 telemetry compilation: PASS.
- Race attempt is unavailable on this host: `go: -race requires cgo; enable
  cgo by setting CGO_ENABLED=1` (the host does not provide gcc).

## Windows Event Log sink

### RED

`go test -tags=cep_testcontrol ./internal/telemetry -run TestEventLog -v`
failed as expected on 2026-08-04: Event Log sink and tagged opener seam were
undefined.

### GREEN / verification

- Added Windows-only Application Event Log sink, non-Windows unsupported stub,
  and `windows && cep_testcontrol`-only opener injection.
- Canonical records map to x/sys `Info`/`Warning`/`Error`, event ID 1; x/sys
  fixes category 0, one insertion string, and no binary data.
- Tagged framing test asserts exact compact no-LF JSON and level mapping; report
  errors permanently fail the sink; Close is idempotent.
- `go test -tags=cep_testcontrol ./internal/telemetry -run TestEventLog -v`: PASS.
- `GOOS=linux GOARCH=amd64 go test -c ./internal/telemetry`: PASS.
- `go test ./...`, `go vet ./...`, `go mod verify`: PASS.
