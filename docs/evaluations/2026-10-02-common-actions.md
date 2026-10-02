# Common member actions, 0.7.0

The member MCP surface stays at 40 tools. Common intents use existing named tools directly;
VM pause/resume are additional actions on `machine_power`. Infrastructure mutations wait for
completion by default and successful responses offer summary/full presentation.

## Pre-deployment validation

Sandbox VM104 ran Go race tests, vet, both static Linux builds, 176 Python tests, Ruff check/format
and script compilation. The frozen 79-case Python comparison still covers the legacy behavior;
explicit new tests cover additive pause capabilities and live power/readiness presentation.

New tests exercise graceful/forced shutdown, VM pause/resume, repeated target-state operations,
fresh boot requirements, preserved resume boot identity, readiness checkpoint recovery, unchanged
quota reservations, unsupported CT pause, failed/unconfirmed transitions, shutdown timeout without
forced-stop fallback, paused rollback rejection, summary/full accounting, preview requirements and
idempotency independent of presentation. Failures and cleanup evidence remain unabridged.

Live verification is pending deployment. The existing member machine is `sandbox` (VM10300);
acceptance uses separate disposable machines and preserves it.
