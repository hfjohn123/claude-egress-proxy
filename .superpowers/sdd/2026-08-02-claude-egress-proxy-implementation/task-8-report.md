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
