# Plugin mechanism: go-plugin or a service on a unix socket

Issue #563. Date: 2026-11-26.

**Choice: each plugin runs as its own service on a unix socket, under systemd, and speaks the gRPC
contract.** go-plugin works, but it ties the plugin's life to the agent's. Then an agent restart
leaves a plugin process behind, a plugin crash needs an agent restart, and the same idempotency key
can start a task twice. A service has none of these problems, and a plugin in another language
needs only a gRPC server.

A second finding matters more than the choice. A Proxmox task outlives its caller only when the
plugin starts it through the HTTP API (pvedaemon). Started through the CLI (`pvesh`, and so `qm` and
`pct`), the task dies with the caller. carrel calls `qm snapshot` today.

## Sources

- hashicorp/go-plugin v1.8.0, read in the module cache on the sandbox: `client.go`, `server.go`,
  `constants.go`, and `examples/grpc/plugin-python/plugin.py`.
- The prototypes and scenarios: [`plugin-mechanism/`](plugin-mechanism/README.md).
- Raw results, one object per run: [`2026-11-26-plugin-mechanism.json`](2026-11-26-plugin-mechanism.json).
- Proxmox VE on spawner (a non-production node), one throwaway container, created and destroyed for
  this test.

## Setup

- One contract for both mechanisms: Describe, Probe, StartOperation (with an idempotency key),
  GetOperation and Cancel, the 5 calls of #564. Contract 2 adds `Operation.message` to contract 1.
- One plugin: a 4 s snapshot run as a task, a worker in its own session that writes progress to
  files, the way pvedaemon keeps a task. The plugin keeps one record per key on disk, so any
  process of it answers for any operation.
- 3 plugin builds: Go (contract 2), Go (contract 1), Python 3.13 with grpcio 1.76.0 (contract 2).
- Host: a stand-in for the agent that starts an operation and reads it every 200 ms.
- Every kill is SIGKILL, as a crash or an OOM kill would be.
- Runs: 3 per scenario, except the same-key check, which ran once per pair.
- Machine: the sandbox, AMD Ryzen 7 9700X, 8 threads, Linux, Go 1.26.5.

## Results

| Scenario | go-plugin | go-plugin with Reattach | Service |
|---|---|---|---|
| Agent killed 1 s in; a new agent asks by key | 6/6 succeeded, same task; **the old plugin process is left running, 6/6** | 6/6 succeeded, same task and same plugin process | 6/6 succeeded, same task |
| Plugin killed 1 s in | 6/6 succeeded, **only after the agent was restarted**: the agent's reads failed for 3 s (15 of 15) and it neither recovered nor exited | not run | 6/6 succeeded **with the same agent**: the supervisor restarted the plugin, and reads failed for 5 (Go) or 24 to 28 (Python, slower start) polls |
| Plugin in Python (the rows above and below) | 7/7 finished | 3/3 finished | 7/7 finished |
| Contract 1 plugin, agent serves 1 and 2 | 3/3 succeeded, version 1 negotiated, new field empty | not run | 3/3 succeeded, contract 1 read from Describe |
| Contract 1 plugin, agent serves 2 only | 3/3 refused: `incompatible API version with plugin. Plugin version: 1, Client versions: [2]` | not run | 3/3 refused: `plugin snapshot 0.1.0 speaks contract 1; this host serves contracts 2 to 2: install a plugin release built for one of them` |
| Same key from 2 agents at once | Go: 1 task. **Python: 2 tasks** | not run | 1 task each |

"6/6" counts the Go and the Python plugin together, 3 runs each. Time to a finished operation was
2.6 to 3.2 s in every case. That is the rest of the 4 s task, so it does not compare mechanisms.

### Why the same key started 2 tasks

Under go-plugin each agent launches its own plugin process. Two agents meant two processes on one
state directory, and the plugin's lock is in memory. The Go plugin came out right by timing; the
Python one did not. A service is one process per plugin on a node, so its in-memory lock is enough.
Under go-plugin, every plugin author would need a lock across processes.

## go-plugin claims from the survey

| Claim | Verdict | Evidence in v1.8.0 |
|---|---|---|
| Same host only | true | `server.go:569`: TCP listens on `127.0.0.1`; `server.go:594`: or a unix socket. `RunnerFunc` can run the plugin elsewhere, but the address is still local |
| No sandbox | true | No `SysProcAttr`, credentials, seccomp or chroot anywhere in the client; the plugin runs as the agent's user |
| Protocol version is one integer | true | `VersionedPlugins map[int]PluginSet` (`client.go:153`, `server.go:76`) |
| Reattach excludes SecureConfig and AutoMTLS | true | `client.go:606`: SecureConfig with Reattach is an error; `client.go:615` returns to reattach before AutoMTLS is set up at `client.go:671`; `client.go:249` says so |

The prototype found 3 more traps:

1. **A launcher that forks breaks Kill.** `uv run` keeps Python as a child process. Kill ended `uv`,
   the child kept the pipes open, and the agent hung for good. The plugin must be the direct child
   (`exec`).
2. **`ReattachConfig()` returns version 0.** The negotiated version must be saved separately.
3. **Reattach skips version negotiation.** The agent must choose the plugin set for the saved version
   itself, or Dispense fails with `unknown plugin type`.

A Python plugin under go-plugin also needs the health service and the handshake line. It has no
GRPCController, so Kill cannot ask it to stop and kills it instead.

## Proxmox re-attach by task id

The issue assumed a restarted plugin could find its Proxmox task again by its task id. Tested on
spawner with `vzdump` of a throwaway container, 1 run per path:

| How the task was started | Caller killed with SIGKILL 1.5 s in | Read by UPID from a new process |
|---|---|---|
| `pvesh create /nodes/pve/vzdump` (the CLI) | the worker died with it | `stopped`, `unexpected status` |
| `POST /api2/json/nodes/pve/vzdump` (HTTP API) | the request had already returned the UPID; the worker's parent is `pvedaemon worker` | `running` on the first read, `stopped OK` 5 reads later |

So re-attach holds only for tasks started through the API. The snapshot plugin must call the API and
store the UPID under the idempotency key. Then the rest is what the prototype shows: an agent or a
plugin restarted at any point gets the same operation back.

## What the service choice means for #564

- A plugin ships as a binary or a package with a systemd unit. The site lists the units it runs.
  systemd restarts a crashed plugin, and the agent's gRPC connection reconnects on its own.
- The agent checks `Describe.contract` against the range it serves, current and previous, as #561
  does for agents.
- The socket is the boundary. It is mode 0600 and owned by the agent's user. A plugin can run as its
  own user and under its own systemd sandboxing, which go-plugin cannot offer.
- Long work runs as a Proxmox task started through the API, keyed by idempotency key. CSI's
  "ask again until ready" rule is exactly the GetOperation loop.

## Not tested

- Real snapshot plugin against Proxmox: the prototype's task is a stand-in. Only the re-attach
  question was asked of Proxmox itself.
- Reattach after a plugin crash: go-plugin cannot reattach to a dead process, so it was not run.
- Load: one operation at a time.
