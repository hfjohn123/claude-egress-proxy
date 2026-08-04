# Task 8 telemetry logger

RED: `TestLoggerAPIExists` failed with `undefined: Logger`.

GREEN: added fixed 256-slot asynchronous logger, permanent nil/failure paths,
FIFO copied records, one-call supervisor, injected-clock deadlines, shutdown gate,
and tagged `WaitQuiescent`. Focused tagged logger and stream tests pass.

RED: deterministic call-deadline and sink-error expectations exposed an inert
test timer, active-call nil timer selection, and use of shutdown's frozen result
for accepted records failed during drain.

GREEN: manual clock records/fires exact deadlines without sleeps. Completion at
249ms writes; exact 250ms fails active plus queue; sink errors are permanent;
shutdown keeps later submissions frozen to its deadline result while accepted
records still receive sink-failed; exact one-second shutdown wins ties.

GREEN: tagged quiescence now uses one constructor-owned condition variable;
terminal delivery no longer allocates/replaces a notification channel.

GREEN: replaced producer mutex admission with atomic gate/ticket publication,
fixed 256-token semaphore, and fixed notification channels. Shutdown/failure
wait for in-flight producers before snapshotting the accepted tail; tagged tests
cover concurrent capacity admission, static producer lock/goroutine absence,
and a reserved-ticket shutdown publication barrier.

RED: final oracle inspection showed the shutdown test submitted `stopped` after
the producer gate closed, so its 252-drop total did not prove that `stopped` was
accepted as FIFO record 256. The suite also lacked direct abandoned-writer byte
immutability, concurrent repeated-shutdown, and ordinary-build symbol checks.

GREEN: `stopped` is now accepted and verified at ticket 255 before shutdown;
four writes complete at cumulative 249/498/747/996 milliseconds and the active
fifth plus 251 queued records terminalize at exactly one second. Added a sink
that retains the live slot slice through timeout and concurrent close, proving
quiescence without slot reuse or a second call/result. Concurrent shutdown
callers share one deadline, timer, close, and terminal result. Source/build-tag
tests freeze the exact test-control boundary.

Final verification: `go test -tags=cep_testcontrol ./internal/telemetry -run
'Test(Logger|BlockedSink|Shutdown|Stream)' -count=20`, `go test ./...`, `go vet
./...`, and `git diff --check` pass. The Windows host cannot run the race suite:
`go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`.
