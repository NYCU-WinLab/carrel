# Go control plane, 0.6

The control plane is rewritten in Go with the existing MCP contract, SQLite state,
OAuth bindings and root mutation adapters. Guest readiness no longer holds the
infrastructure writer. Independent jobs can provision while an earlier guest boots;
resource admission and shared network writes remain serialized.

## PVE read experiment

Twelve randomized, interleaved trials on B09 compare the installed 0.5.1 Perl reader
with the native Go HTTPS reader. Each observation starts a fresh process and includes
Go's inventory permission check. Stable normalized data signatures match before
measurement and in every trial, including all 15 storage volumes. Raw evidence:
[read measurements](2026-10-02-go-reads.json).

| Read | Existing median | Go HTTPS median | Reduction |
| --- | ---: | ---: | ---: |
| Capacity inventory | 1.3191 s | 0.2402 s | 81.8% |
| SDN topology | 0.9882 s | 0.0162 s | 98.4% |

These timings exclude outer SSH, LVM pressure sampling, mutations and guest boot.
The main gain is querying PVE's running HTTPS service instead of repeatedly loading
PVE modules. This is not evidence that Go alone makes VM creation five times faster.
The preceding Python/Rust experiment separates language and transport effects.

The token is root-only and privilege-separated. PVEAuditor alone silently filters
volumes; the inventory path also requires Datastore.Audit and Datastore.Allocate on
local-lvm and checks both on every observation. TLS verifies the PVE CA and hostname.
Only two fixed read modes are exposed; failed reads cannot admit from stale data.

## Validation

The native suite covers 79 frozen Python behavior cases, MCP HTTP discovery/calls,
tenant isolation, JWT/PKCE/offline renewal, durable restart checkpoints, retry identity,
client cancellation, concurrent provisioning, pending capacity reservations,
suspension during readiness, rollback preserving existing resources and a complete
SQLite/config/certificate-link backup roundtrip. Go race tests and vet pass.
All 158 Python tests and Ruff pass. The legacy suite remains as the reference/adapter safety suite.

Display capacity uses a two-second timestamped observation cache with singleflight.
Allocation always obtains fresh physical data and current reservations. Network-only
plans skip compute inventory. Storage-retention accounting moves off ordinary creation
and reconciliation into maintenance and snapshot operations. SSH connections are reused.

## Live acceptance

The public service reports **0.6.0**, launched by `/usr/local/bin/carrel` in CT 100.
The existing MCP login survived both the Python-to-Go upgrade and a later Go restart,
without interactive reauthentication. All seven existing OAuth client records remain.
Installed binary and node-adapter hashes match the committed implementation and sandbox
builds. [Live evidence](2026-10-02-go-control-plane.json) records operations, timestamps,
adapter timings, deployed hashes and rollback locations.

| Workload | Measured time | Context |
| --- | ---: | --- |
| Default Debian VM, direct MCP call | 29.008 s | One call returned initialization and SSH readiness |
| Two further standalone VM operations | 29.288 / 28.265 s | Same development template; one used restricted ingress |
| Two independent default VM jobs | 38.917 s total | Submitted with `wait_seconds=0`; overlapping guest waits |
| Debian CT | 14.397 s | 1 vCPU, 512 MiB, 10 GiB |
| Private NICs, connection grant and HTTPS | 57.087 s | Two existing guests attached; one restricted connection and one publication |
| Capacity display, first / cached call | 0.359 / 0.014 s | Both returned the same observation timestamp |

The preceding 0.5.1 default VM sample took 34.696 seconds, so the new 29.008-second
sample is about 16% faster. The current MCP connector serialized two same-tool calls
before they reached Carrel, producing a 57.608-second pair. Immediate submissions
allow server overlap: the first job was `waiting_for_guest` while the second was
`applying`, and both completed in 38.917 seconds, about 32% less wall time than the
serialized pair. This measures a client submission effect and the new scheduler;
there is no measured concurrent-load baseline for the old server.

During the first VM operation, adapter timings were 0.321 seconds for inventory,
1.111 for node reconciliation, 0.626 for edge reconciliation and 7.876 for creation.
About 19 seconds remained outside those calls, primarily guest boot/readiness.
Go does not eliminate PVE mutation or guest boot time. These are small live samples,
not a latency SLA, and there is no warm pool.

Owner SSH confirmed cloud-init completion, the prepared C/C++, Python venv, Node 24,
Docker/Compose and Git environment, and the returned SSH alias. A managed private
network connected a VM and CT at 10.77.6.12/13; both directions returned SSH banners.
The primary route stayed unchanged and tenant DNS resolved. A designated VM reached
the restricted VM's HTTP port while an ungranted CT was blocked. External HTTPS with
certificate validation returned the exact expected application body.

A snapshot restored a changed file from `after` to `before`, restored running power
state and completed readiness. Separately, the control service was restarted after
a VM reached its persisted `waiting_for_guest` checkpoint. That VM intentionally
slept for 20 seconds during initialization to keep the recovery window open. The
same job completed on attempt two with exactly one node create action, preserving
its allocation. The delay is excluded from the default-VM comparisons.

The Go backup service completed successfully. Its actual ingress-host archive was
opened into an isolated temporary database and passed `PRAGMA integrity_check`,
preserving all seven OAuth clients, configuration and certificate entries. A unit
roundtrip additionally verifies certificate symlinks.

All seven disposable guests (reusing VMIDs 10301 to 10303), grants, snapshot and
private network were removed. PVE returned to its original 15 volumes, with no test
guest disks or SDN/gateway entries. Quota returned to the single original machine,
one IP and one SSH grant. The task private key was deleted. `dev-01` (10300) remained
running and its existing `ssh dev01` login passed after cleanup. The final control
backup was refreshed. The root-only Go reader credential remains intentionally
installed because production now uses it.

The core implementation is Go; bounded Python root mutation adapters, the guest
reporter and certbot remain. This release does not add multi-node scheduling,
unrestricted parallel network writes or SSH-triggered provisioning.
