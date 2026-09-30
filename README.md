```
 ██████╗ █████╗ ██████╗ ██████╗ ███████╗██╗
██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██║
██║     ███████║██████╔╝██████╔╝█████╗  ██║
██║     ██╔══██║██╔══██╗██╔══██╗██╔══╝  ██║
╚██████╗██║  ██║██║  ██║██║  ██║███████╗███████╗
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
```

# carrel

> Ask your agent for a machine. Get an SSH line back.

A carrel is the desk a library sets aside for one graduate student. This is the lab's version: every
WinLab member gets their own corner of a Proxmox VE cluster, with a quota, a private network, public
ports and `*.<you>.winlab.tw` domains. Members never touch Proxmox. Their agent talks to one MCP
endpoint, signs in with the lab Keycloak account, and the platform does the rest.

```
> "Open a VM on winlab for my SDN homework"
  ⚡ machine_create { name: "sdn-hw", kind: "vm", image: "ubuntu-24.04", size: "medium", dry_run: true }
✓ Planned: 4 vCPU, 8 GiB RAM, 40 GiB disk. Quota and capacity fit; supply a public key to create.
```

## Status and connection

The first B09 deployment is running at **https://carrel.winlab.tw/mcp** (Streamable HTTP,
OAuth through the WinLab Keycloak realm). Install for all projects in Claude Code:

```sh
claude mcp add --scope user --transport http carrel https://carrel.winlab.tw/mcp
claude mcp login carrel
```

Or install in Codex:

```sh
codex mcp add carrel --url https://carrel.winlab.tw/mcp --oauth-client-registration dcr
codex mcp login carrel --oauth-client-registration dcr
```

Run login in an interactive terminal, sign in with your WinLab account, and allow the application
in the browser. Complete each client's login before starting the next. Start a new client session
after setup so it loads the new MCP configuration.

Other MCP clients can use the same URL and OAuth discovery. Dynamic registration accepts
loopback callbacks and the explicitly configured ChatGPT callback. A new hosted client's callback
must be added by an administrator; arbitrary callback origins are refused.

Signing in accepts the lab use rules; eligible personal and project tenants are created automatically
on first use. There is no separate policy acknowledgement or registration step.
Use Carrel only for authorized lab work; abuse, scanning other tenants and outbound SMTP are prohibited.

Start with `whoami` for your default tenant, capabilities and all personal/project quotas, including
used, limit and remaining. `catalog_get` combines images and size presets; `capacity_get` reports
shared physical capacity and admission headroom without exposing other tenants' machines.
`quota_get` refreshes one tenant. `memory_mb` and `swap_mb` mean **MiB**; `disk_gb` means **GiB**.

Dry-run `machine_create` for one VM, or use the read-only `deployment_plan` for a group of new
machines, networks and NIC attachments. Plans resolve names within the selected tenant and check
their aggregate quota and capacity. Previews return `quota_before`, `delta`, `quota_after`,
`requirements` and `ready_to_apply`; they reserve nothing and write no resources. They record an
audit entry. No follow-up list or quota call is needed to establish that a preview did not create anything.
Missing SSH keys are reported as a requirement, so resource planning can still finish.

For creation, pass your **public** key inline or save it with `ssh_key_add`. Only actual creation
returns allocated identifiers and the public SSH command. VM user: `user`; CT user: `root`.
Apply a group with `deployment_apply` using the same specification as `deployment_plan`.
Infrastructure mutations return a durable `operation`, initially `queued`; **queued is not a capacity
reservation or success**. `operation_get` with an ID waits up to 20 seconds for completion (set
`wait_seconds=0` for an immediate response). Poll at the returned interval, inspect the terminal state,
and use `operation_retry` to resume a failure. Supply a stable `idempotency_key` when submitting;
resending identical arguments with that key returns the original job. `on_failure=rollback` (default)
cleans up only resources introduced by a deployment; `keep` preserves them for diagnosis. Failed
cleanup retains allocations and reports the remaining resources. Retry `cleanup_failed` to finish
cleanup, then retry the resulting `rolled_back` job if a fresh deployment is wanted.

Read-only tools do not wait for the infrastructure writer, including during VM provisioning and
certificate issuance. A single durable infrastructure writer currently serializes mutations to
preserve node admission and shared network configuration; this is not multi-node scheduling.
Jobs and node-side request receipts survive service restarts. Cancellation of a client connection
does not cancel an accepted job. Each retry remains bound to its original resource allocation.

For current VM images, readiness requires SSH **and** completed cloud-init, assigned managed
private NICs, and any requested `health_checks` (`service`, localhost `http`, or localhost `tcp`).
Without application checks, the result explicitly says `not_checked`. The fixed guest reporter
sends only status, check indices and an optional failed command index; no guest command output
or generic guest execution endpoint is exposed. Failed initialization leaves a standalone VM
available for owner diagnosis; a deployment follows its chosen failure policy.

Private networks default to `mode=managed`: an RFC1918 /24 or /25, fixed DHCP leases, MTU 1450,
and no default gateway or DNS override. DHCP runs in a separate unrouted namespace per network;
private bridge traffic cannot enter the host. New VM images auto-configure matching private NICs;
CT addresses are applied through Proxmox. Existing raw networks retain their behavior. Select
`mode=raw_l2` for experiments that manage their own addressing/DHCP, such as Mininet.

CPU/RAM admission counts every allocated Carrel machine, including stopped machines. Deleting or shrinking CPU/RAM while stopped releases the corresponding reservation only after the
hypervisor confirms the change.
Tenant quota remains an upper limit, not pre-reserved capacity for uncreated VMs. vCPU is shared,
not a dedicated physical core. Direct administrator changes outside Carrel can invalidate admission
assumptions; the capacity endpoint includes unmanaged running infrastructure in its accounting.

Snapshots use separate `snapshot_gb` (default 100 GiB) and `snapshots` (default 4) limits. A 40 GiB
VM with two snapshots consumes 40 GiB `disk_gb` and 80 GiB `snapshot_gb`. The latter is a worst-case
reservation, **not a claim about current physical usage**. Snapshot admission also checks safe
physical headroom; data or metadata pressure blocks new storage allocations. `quota_get` and
`snapshot_list` expose timestamped actual snapshot-retained bytes, sampled from a held thin metadata
snapshot as the union of snapshot mappings minus live mappings. Shared blocks are counted once.
Accounting sample failure does not release reservations. Rollback can briefly stop a VM, restores
its previous power state, and waits for readiness if it was running. It is still a disk-only rollback.

See the [0.3 reliability acceptance](docs/evaluations/2026-10-01-reliability.md) for live recovery,
networking, snapshot and native Codex test results.

Guest boot, package execution and connectivity are never verified by a plan. Never put private SSH keys or tokens in tool
arguments. Registration requires current `lab-member` membership or exact `winlab-admin` membership.
Project membership selects shared project tenants. All administrator tools check the admin group.

The server offers tools and empty MCP resource discovery. `images_list` and `sizes_list` remain
callable compatibility aliases but are omitted from discovery. Custom image storage is not yet
supported, so `images_gb` is hidden from quota responses and requests; stored limits are preserved.
GPU allocation is unsupported; hardware GPU inventory is unknown.

Snapshots cover disk contents. Rollback can stop the guest; the result reports its actual
`power_state` and, when stopped, the `machine_power` call needed to start it again.

Implemented: VM/CT lifecycle, stable image templates, public SSH/port grants, tenant HTTPS domains,
private L2 networks and NICs, explicit cross-tenant TCP grants, snapshots, quota requests/approval,
audit records, and reconciliation. [PLAN.md](PLAN.md#154-member-platform-deployment) records the
implementation and remaining milestones. This is an initial single-node deployment, not completion
of the entire product plan: custom images/imports, console/access recovery, special names, skills,
PBS/observability, alumni scheduling and multiple nodes remain to be implemented or accepted.

`carrel01` is `192.168.13.159`, with ext4 + hardware RAID + LVM-thin. The old PVE remains outside
its cluster. Public traffic uses its existing TLS gateway → new CT 207 proxy → WireGuard → B09.
CT 100 hosts the control plane; CT 101 provides tenant HTTP routing and DNS. Tenant SSH does not use
the management jump account. The new proxy holds no Keycloak or Cloudflare credentials.

[sites/b09/ssh-config.example](sites/b09/ssh-config.example) contains administrator aliases.
[sites/b09/platform-verification.json](sites/b09/platform-verification.json) records actual acceptance
checks. Hypervisor administrators can technically read disks; Carrel exposes no general guest
execution or file-reading API. Verification uses disposable guests and their owner's SSH key.

## Development and deployment

```sh
uv sync --locked
PYTHONPATH=src uv run pytest -q
uv run ruff check src tests
python3 -m compileall -q scripts
```

The scripts are site-specific administrator operations, not the planned general `install.sh`.
The deployment order is documented in [PLAN 15.4](PLAN.md#154-member-platform-deployment): prepare
owned infrastructure, install networking/templates, connect the edge, upgrade the new proxies,
then deploy and publish. For an existing deployment with SSH aliases `carrel01` and `pve`:

```sh
python3 scripts/deploy-control.py
```

Deployment installs hashed dependencies exported from `uv.lock` and preserves existing route/NAT
state. Secrets travel through SSH stdin and protected files. Never save a complete iptables ruleset
on the old host: its existing services and tailnet routes are independent of Carrel.

The `carrel-backup.timer` makes a consistent SQLite backup with config, service key and certificates
each day and stores 14 daily archives under `/var/lib/carrel-edge/backups` on the old PVE, mode 0600.
These are sensitive archives. They do not contain tenant disks and are not a replacement for PBS.
For restoration, stop the control service, restore `carrel.db` (remove stale `-wal`/`-shm` files),
`etc/carrel/`, and `certificates/` to their original locations, set the documented ownership,
then start the service and run `reconcile_run`. `/var/lib/carrel` is owned by `carrel:carrel`;
`/etc/carrel/config.json` is `root:carrel` mode 0640 and `node_key` is owned by `carrel`, mode 0600. The backup's database was restored to a temporary
location and passed SQLite integrity checking; a full infra/tenant disaster restore is pending.

## Private staging bootstrap

The following scripts prepare admin-only nested staging and preserve its existing disks. They do
not establish the CI installation acceptance for M0.

```sh
python3 scripts/host-preflight.py --config sites/b09/carrel01.json
python3 scripts/bootstrap-staging.py --admin-key /path/to/admin.pub  # check only
python3 scripts/bootstrap-staging.py --admin-key /path/to/admin.pub --apply
```

After the guest boots, copy the public `/usr/share/keyrings/proxmox-archive-keyring.gpg`
from the existing PVE host, plus your administrator public key, into it and run:

```sh
python3 scripts/install-staging-pve.py --archive-keyring /path/to/proxmox-archive-keyring.gpg --admin-key /path/to/admin.pub
python3 scripts/install-staging-pve.py --archive-keyring /path/to/proxmox-archive-keyring.gpg --admin-key /path/to/admin.pub --apply
```

Reboot the guest when the report says `reboot_required`, then run it again to verify convergence.
The installer refuses physical machines, unexpected guest names / addresses, and disks without
the staging data serial. It only initializes that dedicated disk when it has no signatures.
The public archive keyring is not a login credential; APT verifies repository signatures and
package hashes with it. The administrator public key is kept outside pmxcfs so PVE
initialization cannot remove staging SSH access. After successful provisioning, cloud-init
is disabled in this infrastructure guest; PVE owns its persistent hostname and network configuration.

The staging VM uses ID `190`, 8 vCPU, 24 GiB RAM, a 32 GiB boot disk and a 160 GiB data disk.
It is reached by administrators through `carrel01`, on `172.31.255.2`. The host's staging
firewall permits internet egress but blocks connections initiated towards the host and private
networks. It owns only its own nftables table, bridge and service. Repeated bootstrap runs
preserve the guest and its disks; this is not a reset command.

From your workstation, with the `carrel01` and `carrel-stg01` SSH aliases configured, run
`python3 scripts/verify-staging.py` to check HTTPS certificates, LVM-thin, services, management
isolation, outbound HTTPS and nested KVM startup. The recorded result is in
[sites/b09/bootstrap-verification.json](sites/b09/bootstrap-verification.json).

The optional `rename-empty-node.py` refuses nodes with guests or a cluster configuration and
backs up the PVE database and configuration before preparing a rename. It needs a reboot and
post-reboot verification; do not use it on an active cluster.

## License

Private to NYCU WinLab.
