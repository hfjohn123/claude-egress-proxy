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

## Review fix round 1

RED: review exposed that shutdown published its atomic gate before installing
the deadline/timer, ordinary test-pause state lived in `Logger`, a single
in-flight count allowed post-gate rejections to postpone draining, and tagged
quiescence independently sampled a moving counter and tail.

GREEN: shutdown and accepting-to-failed publication now coordinate with the
supervisor under `stateMu`; shutdown initializes all deadline state before the
lock-free gate store. The drain barrier now counts only capacity-owning
producers through their final gate recheck and ticket publication. Tagged
quiescence uses a CAS-managed two-side admission sequence: it flips a side,
waits only submissions already admitted to the old side (including synchronous
results), snapshots `tail` once, then waits for that fixed terminal target.
The deterministic one-shot ticket pause moved to `cep_testcontrol` files, with
an inlineable no-op ordinary counterpart; ordinary `Logger` has no hook field
or hook type/branch. Source checks now reject the former hook names from
ordinary logger code.

## Review fix round 2

RED: the first epoch implementation still used a global tail after draining
its old admission side, so a later submission could extend a prior
`WaitQuiescent` target. It also used unbounded producer CAS loops, and the
ordinary build retained a named pause seam.

GREEN: each admission epoch now owns only an active count. `Submit` joins with
fixed atomic increments and no retry loop; tagged quiescence swaps epochs,
drains the fixed join window and old active count, then scans the fixed 256
slot-owner table for the old epoch's exact terminal target. A deterministic
regression proves a later-epoch blocked write cannot extend the earlier
snapshot. Shutdown stores its rejecting gate
while holding the state lock, then installs its budget before releasing that
lock, so the supervisor cannot observe partial state. Publication is routed
through build-specific methods: ordinary code only invokes the core publisher;
the tagged variant supplies logger-scoped deterministic pausing. The ordinary
source audit now enumerates all files selected by an ordinary `go/build` and
rejects test-control, pause, and hook seams.

## Review fix round 3

RED: review found a producer could increment the join counter before a
quiescence snapshot, then load the new epoch after the snapshot flip. The wait
drained the short join window but excluded that already-entered submission.

GREEN: a single packed atomic RMW now both enters the handoff and classifies the
producer into one of two lanes. Tagged quiescence flips only the lane bit, waits
for classified joiners to register, drains the old lane, and scans fixed slot
ownership for its terminal target. Producer admission has no mutex, retry loop,
or contention drop. A tagged pause between classification and lane registration
proves the snapshot cannot return before that record's delivery result.
