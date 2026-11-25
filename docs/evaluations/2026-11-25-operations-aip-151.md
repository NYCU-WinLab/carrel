# Operations compared with AIP-151

Issue #557. Date: 2026-11-25.

carrel's operations already follow the shape of Google's long-running operations (AIP-151) closely.
Two additions are worth making: a `done` field and a cancel tool for operations that have not
started changing anything. Everything else stays, because it gives agents more than AIP-151 does.

## Sources

- AIP-151: https://google.aip.dev/151, read 2026-11-25.
- `google.longrunning.Operation` and the Operations service:
  https://github.com/googleapis/googleapis/blob/master/google/longrunning/operations.proto, read
  2026-11-25.
- carrel: `internal/carrel/operations.go`, `recovery.go`, `store.go` (retention), and the
  `operation_get` and `operation_retry` entries of `contract.json`, at `main` on 2026-11-25.
- Not read: AIP-155 (request identification). AIP-151 does not link to it.

## Fields

| AIP-151 | carrel today | Verdict |
|---|---|---|
| `name`, "only unique within the same service" | `id`, a random hex string | keep `id`; nothing in carrel addresses operations as resources |
| `done`: false while running, true when finished | none; a client compares `state` with the 4 terminal states `succeeded`, `failed`, `rolled_back`, `cleanup_failed` | **add `done`**: a boolean costs nothing, and generic clients look for it |
| `error`, a `google.rpc.Status`, set only when done | `error` with a string `code`, `message` and `recovery` | keep: `recovery` tells an agent what to do next, which `Status` does not |
| `response`, set only when done and successful | `result` | keep the name; check that `result` is empty on a failed operation, as AIP-151 requires one of `error` or `response`, never both |
| `metadata`, progress and times | `phase`, `attempts`, `reserved`, `resource_changes`, `cleanup`, `ready_at`, `created_at`, `updated_at` | keep |

## Methods

| AIP-151 | carrel today | Verdict |
|---|---|---|
| GetOperation | `operation_get` with `id` | match |
| WaitOperation, best effort, "may return the latest state before the specified timeout" | `operation_get` with `wait_seconds` (up to 55) | match; carrel folds Get and Wait into one tool |
| ListOperations | `operation_get` without `id`: the latest 50 of the tenant | match |
| CancelOperation: best effort; a cancelled operation stays, with error code CANCELLED | none; "disconnects do not cancel jobs" | **add `operation_cancel`** for `queued` and `waiting` operations only |
| DeleteOperation: drops interest, does not cancel | none; finished operations are pruned after 30 days (`operationRetention`) | keep; AIP-151's rule of thumb for expiry is also 30 days |

## Rules

- **Start errors versus run errors.** AIP-151: an error that stops an operation from starting is a
  plain error response; a failure while running goes into `Operation.error`. carrel does the same:
  validation and quota refusals come back from the tool call, and failures during the job land in
  the operation's `error`.
- **Parallel work.** AIP-151: a resource that refuses parallel operations returns `ABORTED`. carrel
  queues instead (`waiting` with `waiting_for`, for example one migration at a time). Keep:
  an agent does not have to retry.
- **Polling.** AIP-151 says only "at intervals as recommended by the API service". carrel says it
  in every response: `poll_after_seconds` and `next_action`. Keep.
- **Recovery.** `operation_retry`, `cleanup_failed` and `recovery` (`revise_request`,
  `retry_infrastructure`, `resolve_prerequisite`, …) have no AIP-151 counterpart. Keep.
- **Idempotency.** `idempotency_key` on every mutation. AIP-151 says nothing about it; compare
  with AIP-155 before the plugin contract fixes the name.

## Cancel, in detail

A cancel is safe only before an operation changes anything. The cancel tool accepts an operation
in `queued`, or in `waiting` with `resource_changes: false`; it moves it to `failed` with error
code `cancelled` and recovery `retry`, and releases its reservation. Any other state answers
`conflict` with the current state, so an agent sees why. This matches AIP-151's "best effort".

## For the plugin contract (#564)

The plugin contract uses the same shape, so a plugin operation looks like a core operation to an
agent: `StartOperation` takes an idempotency key and returns an `id`; `GetOperation` returns `id`,
`done`, `state`, metadata (`phase`, progress), and exactly one of `result` or `error` once done;
`Cancel` follows the rule above.

## Follow-up issues

- #583: add `done` to operation responses.
- #584: add `operation_cancel` for operations that have not changed anything.
