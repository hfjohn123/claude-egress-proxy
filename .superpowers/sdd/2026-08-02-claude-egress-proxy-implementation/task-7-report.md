# Task 7 report

## Implementation

Added a private Prometheus pedantic registry, closed typed metric methods, atomic state snapshots, record constructors and validation, a minimal generator/checker, initial schema and reference documentation. Removed framework-owned oversized-request contract values and added `ServiceStateReason`.

Files changed: `internal/contract/{http,outcomes}.go`, their tests, `internal/telemetry/{generate,generated,metrics,record}.go`, telemetry tests, `internal/tools/telemetrygen/main.go`, `schema/telemetry.yaml`, `docs/reference/telemetry.md`, and module sums.

## TDD evidence

RED command: `go generate ./internal/telemetry; go test ./internal/telemetry -run 'Test(Schema|Descriptors|PrivateRegistry|Record)' -v`.

Expected failure observed: `undefined: TunnelClosed` and `undefined: SensitiveMetadata` in `record_test.go`; the test intentionally described the required record API before its implementation existed.

GREEN command: `go test ./internal/telemetry -run 'Test(Record|PrivateRegistry)' -v`.

Passing output: both `TestRecord` and `TestPrivateRegistry` passed.

## Verification

`go fmt ./...`, `go generate ./internal/telemetry`, `go run ./internal/tools/telemetrygen -check`, `go mod download`, `go mod verify`, `go test ./...`, `go vet ./...`, and `go list -m all` passed. `go test -race ./internal/telemetry -v` could not run because this Windows environment reports `-race requires cgo; enable cgo by setting CGO_ENABLED=1`.

## Self-review and concerns

The closed values, HELP strings, private registry, state snapshot, output bounds, sensitive-extension validation, and no-default-registry rule are implemented. Concern: the manifest/generator and schema/matrix coverage are skeletal rather than the brief's complete independently golden-tested closed schema; Task 7 therefore remains incomplete despite passing local tests. Platform limitation: race verification requires a CGO-capable toolchain.

## Second TDD pass

RED command: `go test ./internal/telemetry -run 'Test(SchemaHasClosedSurface|EmissionMatrixHasOneClosedOwnerPerCase)' -v`.

Expected failure observed: undefined `MatrixCases`, `SilenceCases`, `ReloadCases`, and `LifecycleCases`; the tests defined the required generated table surface before it existed.

GREEN command: `go generate ./internal/telemetry; go test ./internal/telemetry -run 'Test(SchemaHasClosedSurface|EmissionMatrixHasOneClosedOwnerPerCase)' -v; go run ./internal/tools/telemetrygen -check`.

Passing output: both case-surface tests passed and generator check exited zero.

## Updated self-review and concern

The manifest now enumerates all metric families, label/value sets, limiter pairs, record bounds, and all specified case IDs; generated case tables expose all 33/12/7/9 IDs. The generator strict-parses YAML and refuses missing generated output. It still does **not** render all tables/docs directly from the YAML or byte-compare generated Go against a separately rendered in-memory result, and the independently literal descriptor golden remains incomplete. This is a confirmed acceptance gap; do not mark Task 7 complete.

## Generator/drift slice TDD evidence

RED command: `go test ./internal/telemetry -run TestGeneratorCheckRejectsMissingAndDriftedOwnedOutput -v`.

Expected failure observed: `check accepted drift in internal/telemetry/generated.go`; the prior checker only rendered/docs-compared one owned file and merely statted `generated.go`.

GREEN command: `go generate ./internal/telemetry; go test ./internal/telemetry -run TestGeneratorCheckRejectsMissingAndDriftedOwnedOutput -v; go run ./internal/tools/telemetrygen -check`.

Passing output: drift and missing-file mutations of both generated outputs are rejected, then the regenerated files byte-compare cleanly. The generator now parses the manifest with known fields, rejects duplicate top-level fields, validates the ordered closed metric and limiter-pair rows, and renders both generated Go definitions and reference documentation in memory.

## Case semantics completion slice

RED command: `go test ./internal/telemetry -run TestEmissionMatrixHasOneClosedOwnerPerCase -v`.

Expected RED observed: the test did not compile because `EmissionCase` had no `Required` or `Forbidden` fields.

GREEN command: `go fmt ./...; go generate ./internal/telemetry; go test ./internal/telemetry -run TestEmissionMatrixHasOneClosedOwnerPerCase -v; go run ./internal/tools/telemetrygen -check`.

Result: passed. The hand-authored manifest now has structured required/forbidden rows for all matrix, deliberate-silence, reload, and lifecycle cases; generated Go and reference tables render those fields. The focused test has literal matrix IDs, owners, required emissions, and core forbidden constraints.

Self-review: validation now rejects blank required fields and duplicate/blank case IDs, but it still validates ID prefixes/counts rather than a fully literal per-row ID/owner contract inside the generator. This remains an acceptance concern for the broader Task 7 scope.

## Adversarial finish-tunnel slice

RED command: `go test ./internal/telemetry -run 'Test(FinishTunnelRecordsCloseAndRejectsInexactBytes|CertificateExpiryRunsOncePerGatherAndFloors)' -v`.

Expected RED observed: `claude_proxy_tunnel_closes_total{result="clean"}` was missing after `FinishTunnel`.

GREEN: `FinishTunnel` now registers/initializes/increments every closed tunnel-close child and rejects either byte total above `2^53-1` before any mutation, avoiding lossy conversion to Prometheus's `float64` counter. The independent descriptor golden now contains all 17 literal families with HELP/type/labels/values/tuples/buckets. Focused telemetry tests pass.

Remaining concern: this slice does not yet add a parser-driven exhaustive comparison of every golden descriptor row to a gathered metric family, nor exhaust every record grammar and enum mutation required by the original Task 7 brief. Task 7 remains incomplete.

## Exact case validation slice

RED command: `go test ./internal/tools/telemetrygen -run TestValidateRejectsCaseMutations -v`.

Expected RED observed: all ID, owner, required, forbidden, and reorder mutations across matrix, silence, reload, and lifecycle were accepted by `validate`.

GREEN command: `go fmt ./...; go test ./internal/tools/telemetrygen -run TestValidateRejectsCaseMutations -v; go generate ./internal/telemetry; go run ./internal/tools/telemetrygen -check; go test ./internal/telemetry -run TestEmissionMatrixHasOneClosedOwnerPerCase -v`.

Result: passed. Validation now locks every ordered case row through independent canonical contract digests, and the focused mutation test exercises every field and order for all four groups.

Self-review: the digest check is exact for all case fields, but the telemetry package's literal assertions are not yet exhaustive for every silence/lifecycle row.

## Independent case-oracle completion

RED command: `go test ./internal/telemetry -run TestEmissionMatrixHasOneClosedOwnerPerCase -v` with one deliberately mismatched silence literal.

Expected RED observed: the exact comparison rejected the mismatched deliberate-silence contract.

GREEN command: `go fmt ./...; go test ./internal/telemetry -run TestEmissionMatrixHasOneClosedOwnerPerCase -v; go mod download; go mod verify; go test ./...; go vet ./...; go list -m all`.

Result: passed. `emission_matrix_test.go` now has independent ordered literal expectations for every field of all 33 matrix, 12 silence, 7 reload, and 9 lifecycle rows. Together with generator mutation coverage and the generator's canonical digests, every case field and row order is closed.

## Descriptor registry verification slice

RED: first focused run exposed parser defects (tuple delimiter and nil/empty label handling); corrected test-only oracle, then reran against live private registry.

GREEN: added `descriptor_registry_test.go`. It parses hand-authored `testdata/descriptors.golden`, requires exactly 17 families, and compares fresh private gather output for exact family membership, type, HELP, zero-valued closed tuples, valid histogram finite buckets and zero `+Inf` count mechanics. It independently locks generated ordered labels/allowed values against golden, checks every valid limiter pair exists and invalid cross-product pair is absent, snapshots default gatherer names before/after private Metrics construction/gather, rejects extra/raw-string exported Metrics methods, and proves certificate callback/clock each run once per gather with floor, expiry clamp, absent callback snapshot, and mutable-clock decay. Generator test proves `descriptors.golden` remains hand-authored.

Verification: `go fmt ./...`; `go generate ./internal/telemetry`; `go run ./internal/tools/telemetrygen -check`; `go mod download`; `go mod verify`; `go test ./...`; `go vet ./...`; `go list -m all`; `git diff --check` all pass.
