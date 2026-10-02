# Direct creation and prepared development VM acceptance

Carrel 0.5.0 was exercised on B09 through the authenticated Carrel MCP connector on
2026-10-02. Builds, tests and image preparation ran on sandbox VM 104. Guest checks
used the disposable guests' owner SSH key. The existing member VM `dev-01` was preserved.
Machine-readable observations are in [the accompanying report](2026-10-02-fast-create.json).

## Latency and tool calls

| Observation | Server operation | Tool wall time | Creation/status calls |
| --- | ---: | ---: | --- |
| Original member Debian creation | 97.71 s | Not measured separately | Preview, apply and repeated status calls |
| Prepared Debian, first accepted clone | 41.98 s | 42.03 s | One `machine_create` |
| Prepared Debian, independent sibling | 42.21 s | 42.38 s | One `machine_create` |
| Prepared Ubuntu, final response policy | 46.17 s | 46.21 s | One `machine_create` |

The user's original agent workflow took 146 seconds, including reasoning, tool round trips
and an additional SSH probe. This is not directly comparable to server operation time.
The measured Debian server operation improved by about 57%. These are a few individual
observations on one node, not a percentile, concurrency benchmark or latency guarantee.

The original VM's `cloud-init analyze` attributed 39.205 seconds to base package update and
installation. Prepared images move that work to image construction. Linked LVM-thin clones
avoid copying the template disk. Reconciliation reads the VNet inventory once and reads existing
tenant subnets concurrently, while mutations remain serialized. The guest reporter starts
after cloud-init completion without an additional 20-second timer floor.

Adapter timing logs for the 41.98-second Debian operation show:

| Stage | Elapsed |
| --- | ---: |
| PVE inventory and admission | 4.530 s |
| Node network reconciliation | 6.726 s |
| Edge reconciliation | 0.889 s |
| Storage accounting | 0.777 s |
| Clone, configure and start | 7.902 s |
| Remaining time, predominantly boot and readiness | 21.16 s |

These adapter durations include external SSH/PVE work. The remainder is not a CPU profile.
There is no evidence here that Python execution dominates creation. A Go or Rust rewrite
would retain the hypervisor, guest boot and package latency. Further work should measure and
reduce repeated PVE calls, boot dependencies and readiness delays. The single infrastructure
writer also queues concurrent mutations. A target of a few seconds would probably require
prestarted capacity and careful tenant/key assignment, with additional memory and maintenance
costs. No warm pool or new provisioning service was introduced in this release.

## Environment and correctness

Both distributions passed owner SSH checks as non-root `user`, successful C and C++20
compilation/execution, Python venv/pip creation, Node execution, Git initialization, and
`docker run --rm hello-world` without sudo. Cloud-init reported `status: done` without schema
warnings. Docker Compose and the unattended OS update timer are available. QEMU guest execution
and file RPCs remain blocked.

| Tool | Debian 13 | Ubuntu 24.04 |
| --- | --- | --- |
| GCC/G++ | 14.2.0 | 13.3.0 |
| Python | 3.13.5 | 3.12.3 |
| Node.js / npm | 24.21.0 / 11.19.0 | 24.21.0 / 11.19.0 |
| Docker | 26.1.5 | 29.1.3 |
| Compose | 2.26.1 | 2.40.3 |
| Git | 2.47.3 | 2.43.0 |

Sibling Debian clones had distinct machine IDs and SSH host keys. Writing a marker in one
guest did not create it in the other. A live linked-clone snapshot, subsequent marker change,
rollback and deletion succeeded. Rollback restored the marker and running state; owner SSH
and cloud-init were healthy afterward.

The initial Ubuntu image candidate exposed a `virt-resize` problem: renumbering its separate
`/boot` partition left BIOS GRUB in rescue mode. That candidate is excluded from latency and
acceptance results. Preparation now converts and grows the image while preserving partition
numbers, GUIDs and boot-loader offsets. Two fresh guests from the corrected image booted
unattended in 47.51 and 46.17 seconds. The first observation exceeded the original 45-second
response window, so the final default and maximum wait are 55 seconds. Client cancellation or
the bounded wait does not cancel durable provisioning. Extra packages and queueing can still
require `operation_get`.

150 tests, Ruff lint/format checks, script compilation and sdist/wheel builds passed. Coverage
includes cancelled/bounded waits, idempotency, concurrent reads, preview behavior, actual
OpenSSH alias parsing, prepared and unprepared cloud-init, user-requested packages, immutable
template validation, generation receipts and topology snapshot reuse. Source archives exclude
runtime keys, qcow2 images and task artifacts. Installed control and node source hashes match
the reviewed worktree. Authenticated native MCP calls continued across service restarts without
a fresh login.

All disposable guests and snapshots were deleted after acceptance, and the task's private SSH
key was removed. The tenant returned to one member VM, 2 vCPU, 2 GiB RAM, 20 GiB disk and one
public SSH port. The rejected Ubuntu template was removed; original templates remain available
for rollback alongside the accepted prepared generations.

## Access and scope

Creation returns tenant-scoped `ssh_short` and `ssh_config`. Installing the returned stanza on
the connecting client enables the short command. On the user's Mac, `ssh dev01` was configured
for the existing machine and verified by successful SSH login. This is local SSH configuration;
it does not create a globally routed DNS endpoint. No bare `ssh railway.new` style provisioning
gateway is implemented. SSH alone has no destination-hostname field for selecting different
guests behind one IPv4 address and port.

The development environment applies to new prepared VMs. CTs remain minimal and existing
member disks are unchanged. OS security updates remain enabled; Node point releases are pinned
to the verified archive at template build time. New template generations must be rebuilt and
activated deliberately. Clients that cached the old MCP tool descriptions should open a new
session to receive the direct-creation instructions; this does not require reauthentication.
