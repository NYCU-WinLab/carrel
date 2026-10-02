# PVE observations and gateway updates, 0.5.1

On B09, fresh capacity inventory fell from 4.37 to 1.44 seconds and an unchanged
eight-tenant node network reconciliation fell from 4.83 to 2.02 seconds. One default
Debian VM returned initialized and SSH-ready from a single MCP call in 34.70 seconds.
The preceding 0.5.0 runs took 42.03 and 42.38 seconds. These are live samples, not
latency guarantees. Raw timings, operation IDs and installed hashes are in the
[JSON evidence](2026-10-02-pve-operations.json).

## Changes and admission behavior

`pve-read.pl` loads the PVE modules and CLI environment once, then invokes the same
local GET handlers used by `pvesh`. Its two fixed modes return inventory or tenant
VNet/subnet topology. It accepts no arbitrary API paths, remote nodes or mutations.
Each call starts a new observation process. There is no cross-request cache or
fallback to an earlier observation after a read failure.

Inventory still includes all local-lvm image/rootdir volumes, including templates,
secondary disks and unused volumes, plus current thin-pool data/metadata pressure.
Existing stopped-machine, unmanaged-resource and incomplete-operation reservation
accounting remains in place. Allocation checks still run under the existing writer
serialization. PVE mutation commands, ownership validation, firewall generation and
NAT behavior are unchanged.

`gateway-sync.py` applies the fixed DNS hosts and Caddy files through one entry into
CT 101. Unchanged content avoids reloads; a stopped service is started. Proposed
Caddy routes are validated before replacing the working file. Atomic file writes
and a receipt recorded only after successful service apply make a failed restart
or reload retryable even when its file was already replaced. External file drift
also causes reapplication. The helper accepts no caller-selected paths or services.

## Measurements

| Measurement | 0.5.0 | 0.5.1 | Samples |
| --- | ---: | ---: | --- |
| Node inventory | 4.3712 s | 1.4389 s | One each |
| Unchanged node network reconciliation, eight tenants | 4.8321 s | 2.0219 s | One each |
| Default Debian VM, MCP wall time | 42.025 / 42.376 s | 34.696 s | Two before, one after |
| Debian CT, server operation | Not measured here | 17.710 s | One after |

Node profiles exclude the outer SSH transport and measure the same installed
adapter entry points before and after replacement. Reconciliation uses the normal
infrastructure lock and existing desired state. Inventory improves by about 67%;
unchanged reconciliation improves by about 58%. During the new VM operation,
adapter logs record inventory at 1.614 s, node reconciliation with changed DNS at
2.275 s, edge reconciliation at 0.849 s and guest creation at 7.977 s. Total server
time is 34.649 s and includes readiness work beyond those adapter entries.

The public `capacity_get` call took 2.098 s, including transport. It ran concurrently
with a node read profile, so it is not an isolated HTTP latency benchmark.

Three additional process probes separate startup from observation work:

| Command | Median |
| --- | ---: |
| `python3 -c pass` | 0.0137 s |
| Load `PVE::API2` and `PVE::RPCEnvironment`, initialize CLI environment | 0.9860 s |
| `pve-read.pl inventory` | 1.3680 s |
| `pve-read.pl topology` | 0.9940 s |

These samples identify repeated PVE module/environment startup as a significant
cost. They do not compare Python and Rust implementations. Calling an already
running PVE HTTP API could avoid that startup in either language, but authenticated
direct HTTP access was neither implemented nor benchmarked in this release.
Python CPU work has not been comprehensively profiled.

## Acceptance and cleanup

All dependency installation, lint, tests and builds ran on sandbox VM 104:
157 pytest tests, Ruff lint/format, script compilation and wheel/sdist builds pass.
The new tests cover fresh inventory and pressure rejection, volume accounting,
fixed read modes, missing-subnet reconciliation, unchanged gateway content, file
drift, validation before replacement and retry after service failure.

Live acceptance used only two disposable guests, VM 10301 and CT 10302:

- Native MCP creation returned ready; owner SSH worked for both guests. The VM
  completed cloud-init. Both guests resolved each other's tenant internal names.
- A new managed private network attached to both guests, assigning 10.77.2.11/24
  and 10.77.2.12/24. Both private SSH endpoints returned their SSH banner from the
  other guest. The primary default route and DNS remained unchanged.
- A small HTTP server on the VM was published through the tenant gateway. An
  external HTTPS request with certificate verification returned the exact expected
  body. The combined private-network, NIC and publication operation took 87.315 s;
  that includes mutation, readiness and publication work, not just topology reads.
- The publication, both guests and the private network were removed through MCP.
  Quota returned to one real machine, one IP and one public port, with no domains
  or private networks. PVE guests/volumes, SDN config and gateway entries were
  checked for leftovers. The task SSH key was deleted. Existing `dev-01` remained
  running and `ssh dev01` still worked.
- The public service reports 0.5.1. Installed control source, installed package and
  all three changed node helper hashes match the implementation commit. Application,
  database and node-helper rollback archives were made before deployment.

The wheel SHA256 is
`d8e6cf6507280e6f171c1d7b0714031df82a1255cfa636bf3d63a101a9a09a55`.
Rollback archives remain on their hosts and contain private configuration; they
are not repository artifacts.

This is single-node acceptance. It does not establish multi-node support,
concurrent-user latency or a faster boot SLA. Warm pools, a language rewrite and
further PVE mutation/guest-readiness optimization are outside this change.
