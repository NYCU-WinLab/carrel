# Common member actions, 0.7.0

The 40-tool member surface now handles everyday intents directly. Existing tools wait for
completion by default, VM pause/resume are actions on `machine_power`, and successful results
provide concise outcomes with `detail=full` available for diagnostics. Implementation PRs:
[#12](https://github.com/NYCU-WinLab/carrel/pull/12) and
[#13](https://github.com/NYCU-WinLab/carrel/pull/13).

## Validation

Sandbox VM104 ran Go race tests, vet, both static Linux builds, 177 Python tests, Ruff check/format
and script compilation. PR and main CI passed for implementation commit
`4f922c6e51f9026d5e21348ad0b996445fcbe774`. The frozen 79-case Python comparison retains legacy
coverage, with explicit tests for the new pause capability and live power/readiness presentation.

Regression coverage includes graceful and forced shutdown, pause/resume, repeated target-state
operations, fresh boot/report requirements, persisted readiness checkpoint recovery, unchanged
quota reservations, unsupported CT pause, failed/unconfirmed transitions, shutdown timeout without
force-stop fallback, paused rollback rejection, summary/full accounting, preview requirements and
idempotency independent of presentation. Failures and cleanup evidence remain unabridged.

## Live acceptance

All successful mutations below completed in one MCP call. These are individual samples, not an
SLA or a controlled comparison of provisioning speed. The VM started at 2 vCPU/2 GiB/20 GiB and
was later resized while stopped to 1 vCPU/1 GiB. The CT used 1 vCPU/512 MiB/10 GiB.

| Request | MCP wall time | Evidence |
|---|---:|---|
| Create default VM with saved keys | 29.03 s | Name plus idempotency key; owner SSH succeeds |
| Create disk snapshot | 4.49 s | Snapshot ready in the same call |
| Pause / resume VM | 4.85 / 4.92 s | Same boot ID and original sleep process preserved |
| Graceful shutdown / repeated shutdown | 7.78 / 2.15 s | Repeated request reports `changed=false` |
| Reduce stopped VM CPU/RAM | 4.92 s | Guest later observes 1 CPU and about 1 GiB |
| Start VM | 19.97 s | SSH plus initialization complete |
| Retry reboot after fix | 22.43 s | Fresh boot ID, owner SSH and cloud-init done |
| Reboot directly from paused | 23.92 s | Internal resume, new boot/report, ready |
| Graceful shutdown directly from paused | 8.58 s | Internal resume; stopped without force fallback |
| Create CT | 20.61 s | Server job 14.81 s; root SSH succeeds |
| CT shutdown / start / explicit force-stop | 6.49 / 6.74 / 6.23 s | Correct final state, retained reservations |
| Publish TCP / HTTPS | 2.04 / 14.84 s | External requests return exact `before` body |
| Delete CT / VM with snapshot and publications | 5.83 / 7.04 s | Exact named resources removed |

A paused VM's disk rollback was rejected without changing resources. After resume, retry restored
a marker from `after` to `before` and returned verified readiness and SSH access. CT pause returned
an explicit unsupported-operation error without calling its experimental checkpoint machinery.

Acceptance found two defects and verified their fixes. PVE finishes `qm reboot` before a separate
`qmstart` worker completes, leaving a short stopped gap. The adapter now waits up to 30 seconds
for the target power state; readiness also requires a report after that confirmed transition.
A retry's outer response still carried quota tables; successful retries now use the same concise
presentation. The full failure and successful retry remain in the evidence. The operation's
`duration_seconds` measures time since its original submission, including delay between retries;
the table reports the wall time of each tool invocation.

For the same completed creation, `operation_get` returned 2,680 bytes with full detail and 939
bytes in summary, a 65% reduction. Full data remains stored and retrievable. Publication summaries
provide a direct endpoint/URL and `verification=routing_configured`; the separate external probes
establish actual application reachability. Existing MCP OAuth credentials survived both upgrades.

Cleanup removed both disposable guests, their snapshot, HTTPS route and extra TCP grant. The node
returned to 15 PVE volumes, with no 10301/10302 test volumes. Quota returned to one machine, 2 vCPU,
2 GiB RAM, 20 GiB disk, one IP and one SSH grant, with zero snapshots/domains. The original
`sandbox` (VM10300, allocation `2d6a0f537e167d74bddd1e3064126c82`) retained its identity and resources;
owner SSH returned hostname `sandbox`. Its disks and workload were never modified.

The chosen default public key was intentionally saved in the personal tenant, so future creations
can omit `ssh_keys`. No private key was sent to Carrel, and no existing SSH alias was overwritten.
Raw operation IDs, outcomes, timing and cleanup checks are in
[the evidence JSON](2026-10-02-common-actions.json).

Installed SHA-256:

- Control: `2f0423be0c93899287abe96d4ed94f47dbc55701aae8ccdb7d3a2c6e1f903c82`.
- Node adapter: `b39350c6e081166ee6f0079d66220e4ec696f21f7b6a9811620a1ab3d4117a25`.
- Reader, unchanged: `7a5bbe9f5ea68d1bb3eee9779b31937b01175c453c05f0cda7a14917ccda82da`.

Private rollback files remain at `/opt/carrel/rollback/go-20261002-054530.tar.gz` in CT100 and
`/var/lib/carrel/go-upgrade-20261002-054530/` on the node. Restore service/binaries separately
from the database; that saved database predates test-resource cleanup.
