# Carrel scope audit from member intent (2026-10-02)

Carrel's next improvements should make completion and recovery consistent across existing
workflows. The review found seven reproducible behavior problems and one existing-machine
networking limitation. The largest gaps are readiness, offline configuration and recovery
guidance. They do not require another language rewrite or a new orchestration service.

Reviewed runtime: **v0.7.2**, commit `7d979ec6f14272343c8170cef9e4af6493047491`.
This document preserves the v0.7.2 baseline. The subsequent [0.8 corrections](2026-10-02-scope-fixes.md)
address A1 through A8 and record their acceptance separately.

## Method and coverage

The previous iterations exposed four useful questions: can the agent act on a known name;
does the result include everything needed to use it; does success describe the user's outcome;
and does failure identify a viable next step? Apply these questions to state transitions and
repeated requests as well as first-time success.

All 40 member tools were mapped to their current contract and Go implementation. The review
also inspected the bounded node adapter, guest reporter, admission, OAuth, administrator quota
decisions and maintenance. This is not a new production acceptance run for every tool.

| Scope | Tools reviewed | Outcome |
|---|---|---|
| Identity, catalog, capacity, quota | `whoami`, `catalog_get`, `capacity_get`, `quota_get` | Discovery and observation/admission separation are useful. No new authentication failure reproduced. |
| Machine lifecycle | create, list, get, delete, power, resize, metrics, retry | A1, A2 and A6; guest-visible resize completion needs follow-up. |
| Composed deployments | `deployment_plan`, `deployment_apply` | A3 and A4 affect completion; A8 limits existing-machine changes. |
| Private networks | network create/list/delete, NIC attach/detach | A1, A3 and A7. |
| Sharing | peer allow/list/revoke | Current lists/selectors expose grant IDs and addresses; apply A1's presentation policy here too. |
| Publications | domain add/list/remove, port open/list/close | A1 and A7; configured routing remains distinct from application health. |
| Snapshots | create/list/delete/rollback | A7; retain disk-only and power-state safeguards. |
| SSH keys | add/list/remove | Saved-key reuse is useful. Existing-guest key rotation/recovery remains a separate limitation. |
| Operations | get/retry | A6; durable identity and restart checkpoints remain necessary. |
| Requests and audit | quota request, request list, audit log | A5; request notification described in the roadmap is not implemented by these handlers. |

Evidence combines source inspection, read-only calls to the live v0.7.2 MCP and isolated
diagnostic probes on sandbox VM104. The complete Go race suite passed, including the existing
79 parity cases. The diagnostic probes produced 14 records across seven findings. They use
temporary SQLite databases and a fake PVE backend. They do not demonstrate a real guest boot
or establish performance timings. No production resources were created, modified or deleted;
read-only calls can still add normal audit entries.

## Confirmed findings

### A3. Offline NIC configuration waits for a guest that cannot report (P1)

**Trigger:** attach a managed private NIC to a stopped or paused VM, directly or through a
deployment containing an attachment to an existing VM.

`NetworkAction` and `DeploymentApply` unconditionally set such a VM to `initializing`.
The operation then waits for SSH and a reported interface. The direct call times out and retains
the NIC; the composed call rolls the NIC back. Both can leave the recorded VM state at
`needs_owner_fix`, although the requested offline configuration was accepted by the adapter.
The probes reproduced all four combinations. They shortened the readiness timeout to one second;
the production code default is 900 seconds. No power-status query occurred in these paths.

**Smallest correction:** observe the affected VM's power state. Preserve stopped/paused state,
finish the configuration operation, and report that guest verification awaits an authorized
start/resume. Verify active guests normally. Do not start a stopped guest as a hidden side effect.
Apply the same rule to direct and composed attachment paths and retry recovery.

Sources: `internal/carrel/network.go:115`, `internal/carrel/intent.go:334`,
`internal/carrel/operations.go:277`, `internal/carrel/lifecycle.go:166`.

### A4. One failed application sample can remove a warming deployment (P1)

**Trigger:** cloud-init completes after starting an application, but the first HTTP/TCP/service
check arrives while that application is still warming up.

`WaitReady` treats `application_status=failed` like failed initialization immediately.
The probe supplied one failed application report with initialization complete and SSH available.
The default deployment policy then rolled back its newly created machine without waiting for
another report. Existing resources remain protected by the existing cleanup ownership rules.

**Smallest correction:** distinguish failed bootstrap commands from application warm-up. Use a
bounded readiness window for application checks, persist its deadline across restarts, and
retain failed check indices at the deadline. Avoid sleeping while holding the infrastructure
writer. A slow-start-then-healthy test and a never-healthy test must exercise the complete job.

Sources: `scripts/guest-report.py:29`, `internal/carrel/lifecycle.go:213`,
`internal/carrel/operations.go:328`.

### A2. Live power observations can carry stale readiness (P1)

**Trigger:** a previously ready VM remains powered on while reporting stops, or an application
later fails its checks.

`machine_get` observes current power state but combines it with persisted `ssh_ready` and guest
reports without an explicit freshness classification. The probes returned `state=ready` and
`ssh_ready=true` with a 30-minute-old healthy report. A current failed application report also
coexisted with `state=ready`. `reported_at` is present, so the timestamp is not concealed, but
the agent must infer the meaning of these conflicting or historical signals.

**Smallest correction:** expose observation freshness and distinguish last verified SSH,
current power, initialization and application health. A stale report should be `unknown/stale`,
not a current readiness claim. Keep status requests inexpensive; do not turn every list into an
SSH fan-out. Add a current connection probe only where connection readiness is required.

Sources: `internal/carrel/platform.go:363`, `internal/carrel/power.go:12`.

### A1. Summaries remove data needed to complete networking work (P2)

**Trigger:** configure an app to reach its database, inspect an attached private interface, or
identify the machine behind an existing public route.

`machineSummary` drops the primary private IP, access rules and private NICs, even though the
full response already contains them. Deployment success uses the same summary. Meanwhile,
`port_list` and `domain_list` return internal VMIDs without machine names or ready-to-use
endpoint fields. Live calls confirmed those list shapes; isolated probes confirmed the
summary/full difference. This pushes the agent into extra calls and manual joins.

**Smallest correction:** retain tenant-visible connection addresses, named network attachments
and relevant ingress rules in the normal response. Resolve list entries to machine names and
endpoints server-side. Keep IDs where a removal tool needs them, while making ordinary intent
readable without learning VMIDs, bridges or gateway topology. These are presentation changes
to existing tools.

Sources: `internal/carrel/presentation.go:96`, `internal/carrel/network.go:10`,
`internal/carrel/domains.go:153`, `internal/carrel/intent.go:356`.

### A5. Quota requests can duplicate or enter an unusable approval flow (P2)

Three probes exposed a shared validation gap:

1. Requesting 11 public ports succeeds, although the fixed address plan allows at most 10 and
   approval subsequently rejects it.
2. Sending the identical quota request twice with the same advertised `idempotency_key`
   creates two pending requests. The synchronous handler does not use the operation deduplicator.
3. A pending request whose expiry passed while awaiting review can still be approved. The next
   maintenance expiry pass will undo that grant.

**Smallest correction:** share quota/address-plan validation between request and approval;
deduplicate synchronous request submission by tenant and key; recheck expiry at approval.
Return the actual blocker when it is a physical address limit rather than a grant an admin can
approve. This requires no larger approval-workflow framework.

Sources: `internal/carrel/execute.go:239`, `internal/carrel/admin.go:33`,
`internal/carrel/operations.go:74`, `internal/carrel/contract.json` (`quota_request`).

### A6. Recovery guidance can send agents into deterministic retry loops (P2)

**Trigger:** create a machine using a name that already exists.

The operation fails with `conflict` and `next_action=operation_retry`. Retrying uses the same
name and fails again with the same recommendation. The probe completed two attempts and
created no extra machine. Current special handling recognizes only unreserved `invalid`
failures. Other failures such as quota/capacity blockers and guest failures also need more
specific guidance than retry alone.

**Smallest correction:** use structured recovery categories for revise-input, resolve-capacity,
repair-guest, wait, retry-infrastructure and finish-cleanup. Derive these from typed errors and
checkpoint state, not string matching. Preserve the original operation ID and allocation
binding. A repair response should include the relevant machine/access information when retained.

Sources: `internal/carrel/operations.go:14`, `internal/carrel/platform.go:284`,
`internal/carrel/backend.go:36`.

### A7. Successful deletion can return a resource that still looks present (P2)

**Trigger:** delete a snapshot, close a public port, or delete an empty private network.

All three probes confirmed successful removal from storage. The successful snapshot result
still said `state=ready`; port and network results said `state=deleting`. This is a result
presentation problem, not evidence of leaked resources. It encourages another list or poll to
establish whether deletion completed. Domain removal uses the same deleting-record pattern.

**Smallest correction:** return the removed resource's user-facing identity and explicit
`state=deleted` or `removed=true` once cleanup is confirmed. Preserve partial cleanup details
on failure. Extend the existing machine deletion convention to the other removal tools.

Sources: `internal/carrel/snapshots.go:71`, `internal/carrel/network.go:54`,
`internal/carrel/network.go:159`, `internal/carrel/presentation.go:72`.

## Existing-machine scope gap

### A8. Isolation intent only works for destinations created with the right mode (P2)

Read-only live planning accepted a connection to an existing `restricted` destination. The
reverse plan targeting an existing default `tenant` machine failed with:
`Use network_access=restricted on the destination to enforce declared connections`.
The current tools have no operation for changing that mode on an existing machine.

Refusing to pretend an allow rule provides isolation is correct. The missing workflow is
"restrict this existing database to this application". The agent should not discover that
creation-time choice only after the machine holds data, and must not rebuild it as a workaround.
A later extension should explicitly preview the lost connectivity, reject experiment NICs that
bypass isolation, then change ingress policy with the requested connections. Until supported,
return this limitation directly. This is an API decision, not a default-mode change in this audit.

Source: `internal/carrel/intent.go:24`; no `network_access` update field exists on current
machine mutation tools. Both live plans were previews and applied no rules.

## Follow-up checks, not established production incidents

| Area | Evidence and next check |
|---|---|
| Resize completion | The VM adapter changes virtual disk capacity with `qm resize`; it does not verify guest filesystem growth. The response mentions possible CPU/RAM restart but gives no filesystem follow-up. Verify prepared Debian and Ubuntu images after online growth and restart, then report allocation, effective guest capacity and any required owner action separately. |
| Publication queue latency | Certificate issuance and DNS work run under the shared writer, including a configured 30-second ACME propagation wait. Guest boot already releases that writer. Measure first-domain issuance against an unrelated queued power action before deciding whether certificate preparation needs its own checkpoint. |
| Access recovery | Saved-key removal correctly leaves existing guests unchanged. Lost-key or broken-SSH recovery remains deferred. Document that boundary before adding any credential rotation or console mechanism. |
| Operator diagnostics | The SSH adapter reduces backend failures to a generic error and logs successful calls, while the operation log keeps the error type. Add bounded error codes and correlation before attempting automatic recovery; do not expose arbitrary guest output or secrets. |
| Backup and release claims | Current backups cover control state, not tenant disks. Full infrastructure/tenant disaster restore and install-from-scratch CI remain unaccepted. Keep these explicit release gates rather than implying the larger roadmap is deployed. |

## Recommended implementation order and acceptance

1. **Truthful completion:** A2, A3 and A4. Exercise running, stopped and paused machines,
   stale/missing/current reports, slow application startup, persistent failure and service restart.
2. **Usable outcomes and recovery:** A1, A6 and A7. A successful call supplies connection details
   or a definitive removal receipt. Failed requests return a viable next step without blind retries.
3. **Quota requests:** A5. Invalid limits fail before submission; duplicate submissions remain
   one request; approval rechecks time and current limits.
4. **Existing-resource intent:** A8 and resize completion. Add only the changes required to finish
   these concrete tasks. Preserve explicit authorization for downtime or connectivity changes.

For each slice, keep direct calls and `deployment_apply` consistent. Reuse existing tools and
durable operations. Record client tool-call count, elapsed time, final usable state and cleanup,
including failures, rather than treating an accepted backend action as the whole outcome.
Custom images, special domains/ports, multi-node scheduling and the larger skill catalog remain
deferred. This audit provides no reason to add a warm pool, another control-plane language,
generic guest execution or a separate intent service.

## Reproduction artifacts

[JSON evidence](2026-10-02-scope-audit.json) contains the 14 isolated observations and package
test outcomes. [Live preview evidence](2026-10-02-scope-audit-live.json) records the running
version and the two existing-machine connection previews. The [diagnostic source](fixtures/scope-audit-v072_test.go.txt) is deliberately
outside the test suite: it asserts the defective v0.7.2 behavior so that a pass means reproduced,
not fixed. On an isolated sandbox copy of the reviewed commit:

```sh
cp /path/to/scope-audit-v072_test.go.txt internal/carrel/scope_audit_test.go
go test -race ./internal/carrel -run TestScopeAudit -count=1 -v
rm internal/carrel/scope_audit_test.go
```

Future fixes should turn the relevant probes into regression tests for the corrected outcomes.
