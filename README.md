```
 ██████╗ █████╗ ██████╗ ██████╗ ███████╗██╗
██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██║
██║     ███████║██████╔╝██████╔╝█████╗  ██║
██║     ██╔══██║██╔══██╗██╔══██╗██╔══╝  ██║
╚██████╗██║  ██║██║  ██║██║  ██║███████╗███████╗
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
```

# carrel

> Describe the machines and connections you need. Get SSH commands and service URLs back.

A carrel is the desk a library sets aside for one graduate student. This is the lab's version: every
WinLab member gets their own corner of a Proxmox VE cluster, with a quota, a private network, public
ports and `*.<you>.winlab.tw` domains. Members never touch Proxmox. Their agent talks to one MCP
endpoint, signs in with the lab Keycloak account, and the platform does the rest.

```
> "Open a VM on winlab for my SDN homework"
  ⚡ machine_create { name: "sdn-hw", image: "ubuntu-24.04", ssh_keys: ["ssh-ed25519 ..."] }
✓ Ready: 2 vCPU, 2 GiB RAM, 20 GiB disk. SSH and initialization verified.
  ssh sdn-hw.<you>  # after installing the returned SSH config once
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

Login persists across browser and Carrel restarts. Access tokens last five minutes; the client
automatically renews them with a Keycloak offline token. Carrel does not impose a fixed expiry on
that token or its authorized client registration. Keycloak still enforces its offline session idle
and revocation policies; revoking Carrel in the [WinLab account console](https://auth.winlab.tw/realms/winlab/account/)
ends renewal. Removing lab membership blocks renewal; issued access tokens expire after five minutes
(with a small clock-skew allowance).
Signing out of the browser alone does not revoke offline access. Client logout removes its saved credentials;
clients supporting OAuth revocation can also call the advertised revocation endpoint.
Existing logins created before 0.4.1 need one new login to obtain offline access.

Other MCP clients can use the same URL and OAuth discovery. Dynamic registration accepts
loopback callbacks and the explicitly configured ChatGPT and Claude callbacks. A new hosted client's callback
must be added by an administrator; arbitrary callback origins are refused.

Signing in accepts the lab use rules; eligible personal and project tenants are created automatically
on first use. There is no separate policy acknowledgement or registration step.
Use Carrel only for authorized lab work; abuse, scanning other tenants and outbound SMTP are prohibited.

A request for one machine needs only `machine_create` with a name and public key (or previously saved keys).
It defaults to a prepared **Debian 13 minimal VM with 1 vCPU, 1 GiB RAM, 10 GiB disk and 1 GiB swap**.
The `debian-13-minimal` image includes SSH, cloud-init, Python for Carrel management, QEMU guest
agent, unattended security updates, curl, rsync and growpart. Node, Docker and compilers are not
preinstalled. Build applications on a suitably sized development machine and deploy their runtime
artifacts, or request a larger development VM for builds and Docker stacks.

Choose `image="debian-13"` or `image="ubuntu-24.04"` for the prepared development environment.
These images default to `small` (2 vCPU, 2 GiB RAM, 20 GiB disk) and include GCC/G++, make, CMake, Python with pip/venv, Node.js 24 LTS with npm,
Docker with Compose, Git, curl, jq, unzip and pkg-config. Docker starts automatically; the VM user
belongs to the docker group (equivalent to root access within their own VM). Use a Python venv
for project dependencies. CTs default to Debian 13, `tiny`, and no swap; use a VM for Docker.

| Preset | vCPU | RAM (GiB) | Disk (GiB) |
| --- | ---: | ---: | ---: |
| `tiny` (minimal default) | 1 | 1 | 10 |
| `small` | 2 | 2 | 20 |
| `medium` | 4 | 8 | 40 |
| `large` | 8 | 16 | 80 |

An explicit `size` replaces the image's default preset; individual `cpu`, `memory_mb` and `disk_gb`
override that preset. VM swap defaults to 1024 MiB within the disk; `swap_mb=0` disables it.
Resource choice and image choice are independent: a larger minimal VM still has a minimal environment.
`catalog_get.images` reports each image's environment, default size and default swap.
`catalog_get.vm_environment` identifies the environment installed at the current site. Admission checks run within
creation, so discovery and previews are optional. The call waits up to 55 seconds for SSH and
initialization readiness. If still pending, use the returned operation ID to continue waiting.

VM `runcmd` accepts command argument arrays with up to 64 KiB of UTF-8 data per argument.
The complete MCP HTTP request remains limited to 256 KiB. Small bootstrap scripts can include
application files directly; transfer larger projects over SSH with scp or rsync after creation.
Oversized arguments are rejected before queueing or reserving resources, including in previews.

### Everyday requests

Use the known machine name directly. Normal member work does not need operator memories,
infrastructure runbooks, hypervisor access, or a preliminary list/quota/catalog call.
Choose the tenant only for project resources or an explicitly selected account.
For feature questions, use `catalog_get`. If tool discovery is necessary, list names first and
inspect only the relevant tool definitions instead of dumping every description and repeated instructions.

| Request | Direct tool call |
|---|---|
| Create a sandbox | `machine_create(name="sandbox")`, using saved keys or an inline public key |
| Show status or connect | `machine_get(machine="sandbox")` |
| Start or wake a VM | `machine_power(machine="sandbox", action="start")` |
| Gracefully turn it off | `machine_power(machine="sandbox", action="shutdown")` |
| Restart | `machine_power(machine="sandbox", action="reboot")` |
| Pause / continue a VM | `machine_power(machine="sandbox", action="pause" / "resume")` |
| Change RAM | `machine_resize(machine="sandbox", memory_mb=4096)` |
| Save / restore disk contents | `snapshot_create` / `snapshot_rollback` with the machine and snapshot name |
| Publish a running service | `domain_add` for HTTPS, `port_open` for TCP/UDP |
| Permanently remove it | `machine_delete(machine="sandbox", confirm="sandbox")` |

Member infrastructure mutations wait up to 55 seconds by default, so quick actions finish in one
call. Inspect the returned operation. A successful result needs no extra poll/list/quota call.
Only pending jobs need `operation_get`. Set `wait_seconds=0` for immediate submission.
Successful responses default to a concise outcome, machine/access details and nonempty resource
delta. Use `detail="full"` for complete accounting and internal identifiers; durable results always
retain those details. Successful deployment summaries omit internal allocation bindings and cleanup
receipts; machine access, declared connections and public endpoints remain. Previews, errors, partial
cleanup and recovery instructions are preserved.
`machine_list` reports recorded state without probing every guest. `machine_get` observes power
and SSH now. Guest reports expire after 120 seconds; stale or previous-boot reports become unknown.
Live power or an SSH banner alone cannot imply healthy applications. Bootstrap failures remain
immediate; application checks get a 120-second warm-up window after initialization completes.
The deadline persists across control restarts. An explicit retry starts a new verification window.

Start also resumes a paused VM. Start, resume and reboot wait for SSH and initialization readiness;
reboot and a stopped-to-running transition require a fresh boot report. Repeating start, shutdown,
pause or resume in the requested state is safe. A repeated reboot is another reboot unless the same
idempotency key identifies a lost submission.

Pause freezes VM execution in RAM. It retains memory allocation, disks and quota, and cannot
survive host power loss. It sets automatic boot off until resume/start. CT pause/resume is
unsupported because PVE's CT suspension is experimental disk checkpointing. Graceful shutdown/reboot resume a paused VM as needed within the same operation. `stop` force-powers off and is only for explicit force-stop
requests; graceful shutdown never falls back to it. Shutdown preserves disks and reservations.
Deletion permanently removes disks, snapshots and grants, and must represent explicit deletion
intent. Its `confirm` field records that authorization; it does not require a redundant preview.

Only send the resource fields requested when resizing. CPU/RAM reductions require a stopped guest;
do not stop running work without authorization. Running guests may require a restart for configured
CPU/RAM changes. Disk shrinking is unsupported. `machine.resize` separates confirmed allocation
from unverified guest capacity and supplies owner SSH inspection/growth steps. VM disk growth does
not prove that the partition and filesystem grew; verify them before reporting usable space. Snapshot rollback restores disk contents, not a
paused process or RAM; resume or shut down a paused VM before disk rollback. Publishing configures routing; verify the actual application separately.

Save the client's chosen public key once with `ssh_key_add` to omit `ssh_keys` on future creations.
If no saved key is known, read only the known default public key and pass it inline. Do not inspect
unrelated SSH aliases or scan private keys. Inline public keys are not saved automatically.

Use `whoami` for the running `service.version`, your default tenant, capabilities and all personal/project quotas, including
used, limit and remaining. `catalog_get` also returns the version, images, size presets and VM/CT restrictions; `capacity_get` reports
shared physical capacity and admission headroom without exposing other tenants' machines.
`quota_get` refreshes one tenant. `memory_mb` and `swap_mb` mean **MiB**; `disk_gb` means **GiB**.
`machine_get` returns readiness, access rules, SSH and timestamped `runtime` power state/uptime;
it does not return the raw hypervisor payload. Use `machine_metrics` for detailed usage.

Personal and project tenants default to **8 machines / 8 IPs**, with aggregate limits of 8 vCPU,
16 GiB RAM and 100 GiB disk. Eight `tiny` VMs use 8 vCPU, 8 GiB RAM and 80 GiB disk. Increasing
CPU after filling that allocation requires releasing CPU quota or an approved quota increase.
Stopping or pausing a VM retains its reservations. Available quota does not reserve physical
capacity; creation and growth also pass the node's admission checks.
Each machine's SSH occupies one of 10 tenant public ports, so eight machines leave two ports for
additional TCP/UDP publications. Tenant HTTPS domains use the gateway without consuming these ports.
Defaults for domains (10), networks (4), snapshots (4) and snapshot space (100 GiB) are unchanged.

When a preview is wanted, dry-run `machine_create` for one VM, or use the read-only `deployment_plan` for a group of new
machines, allowed connections and public endpoints. Plans resolve names within the selected tenant and check
their aggregate quota and capacity. Previews return `quota_before`, `delta`, `quota_after`,
`requirements` and `ready_to_apply`; they reserve nothing and write no resources. They record an
audit entry. No follow-up list or quota call is needed to establish that a preview did not create anything.
Missing SSH keys are reported as a requirement, so resource planning can still finish.
`next_action` identifies missing requirements or directs the agent to `deployment_apply`.
`deployment_plan` is the complete preview; `deployment_apply` has no dry run.

For example, “an app and a database; only the app can connect to database TCP 5432;
publish the app over HTTPS” becomes this `deployment_plan` specification:

```json
{
  "machines": [
    {"name": "app", "kind": "vm", "image": "ubuntu-24.04", "network_access": "restricted"},
    {"name": "db", "kind": "vm", "image": "debian-13", "network_access": "restricted"}
  ],
  "connections": [{"from": "app", "to": "db", "protocol": "tcp", "port": 5432}],
  "publications": [{"machine": "app", "protocol": "https", "port": 80, "sub": "web"}]
}
```

Use that same specification with `deployment_apply` after supplying a public SSH key and the
application setup (`packages`, `runcmd`, optional `health_checks`). No application is installed by
this networking example. Publications can also reference an existing machine, or use `tcp`/`udp`
to request an assigned public port. Machine names belong to the selected tenant; no host, bridge,
VLAN, gateway or proxy selection is needed. The result includes SSH commands, connection rules and
public endpoints. `verification: routing_configured` means routing and TLS setup succeeded;
the agent must still test the actual application from its intended client.

`network_access=restricted` accepts declared connections, public port/domain grants and platform
access. Internet egress remains available. It does not allow extra experiment NICs, which would
bypass ingress filtering. The compatible default, `tenant`, allows traffic within the tenant.
Choose `restricted` explicitly when only designated callers should reach a service.

For an existing database, submit the authorized ingress change together with its allowed caller:

```json
{
  "access": [{"machine": "db", "network_access": "restricted", "confirm": "db"}],
  "connections": [{"from": "app", "to": "db", "port": 5432, "protocol": "tcp"}]
}
```

Use `deployment_plan` for a requested preview, or `deployment_apply` for an authorized change.
The preview explains lost or added same-tenant connectivity. Machine identity and disks remain;
SSH routes, publications and existing explicit peer grants are preserved and visible in the result.
Remove unwanted old grants explicitly. Detach experiment NICs before restricting ingress.
Changing back to `tenant` grants same-tenant ingress again. Rollback restores only a policy still
owned by that operation, never a newer edit or a replacement machine.

Managed NICs attached to stopped/paused VMs return `pending_guest_start` or `pending_guest_resume`
without starting them. The next authorized start/resume verifies a new interface report.
NIC removal from a paused VM requires an authorized resume or shutdown first, because the guest
cannot acknowledge hot unplug while paused. The request fails before changing its configuration. Running guests
require the reported address and MTU. Summaries retain private IPs, named NICs and ingress rules.
Route lists resolve machine names and endpoints; confirmed removals return `state=deleted`.

Follow typed recovery guidance before retrying: revise input, resolve capacity or prerequisites,
repair the retained guest, finish cleanup, or retry infrastructure. Deterministic input conflicts
are not requeued unchanged. Quota requests specify total limits, enforce fixed address ceilings,
and deduplicate tenant-scoped idempotency keys. Approval rechecks expiry and current limits.

HTTPS certificate preparation uses a durable stage outside the infrastructure writer, allowing
unrelated work during DNS propagation. Changes to the same machine remain ordered.


For creation, pass your **public** key inline or save it with `ssh_key_add`. Only actual creation
returns allocated identifiers and the public SSH command. VM user: `user`; CT user: `root`.
For an authorized group, call `deployment_apply` directly, or apply the same specification as a previous
`deployment_plan`. Creation returns a durable `operation` and waits up to 55 seconds by default.
Set `wait_seconds=0` for immediate submission. Other member infrastructure mutations also wait up to 55 seconds.
**Queued is not a capacity reservation or success**. A completed creation includes SSH and readiness in
`operation.result`; no polling call is needed. Otherwise, `operation_get` with an ID waits up to 55 seconds
(set `wait_seconds=0` for an immediate status). Poll at the returned interval, inspect the terminal state,
and follow `next_action`. Certificate-budget waits return `waiting` and `ready_at`, release the
infrastructure writer and resume automatically. Use `operation_retry` to resume a failure.
An invalid request with no remaining reservations returns `next_action=revise_request` instead:
correct the input, preview it and submit a new request. Retrying the old operation repeats its original arguments.
Supply a stable `idempotency_key` when submitting;
resending identical arguments with that key returns the original job. Changing only `wait_seconds`
does not change the operation identity. `on_failure=rollback` (default)
cleans up only resources introduced by a deployment; `keep` preserves them for diagnosis. Failed
cleanup retains allocations and reports the remaining resources. Retry `cleanup_failed` to finish
cleanup, then retry the resulting `rolled_back` job if a fresh deployment is wanted.

Each machine also returns `ssh_config` and `ssh_short`. For a local CLI agent, completing a creation
or connection request includes installing this stanza in the client's `~/.ssh/config` (or an included
file), preserving existing entries. Use the returned tenant-qualified alias, check its HostName/User/Port
with `ssh -G <machine>.<tenant>`, and present `ssh_short` as the primary connection command. This setup
is part of the request; do not wait for a separate request for an alias. Status-only requests need no
local changes. If local file access is unavailable, the user excludes setup, or setup fails, return the
direct `ssh -p ... user@carrel.winlab.tw` command and explain why the alias is not ready.
The alternate `ssh <machine>.<tenant>.winlab.tw` uses the same stanza. These are local client aliases,
not DNS routes. Machine deletion and name reuse can change the port and host key; refresh the relevant
stanza and verify the new host identity. Never disable host-key checking or replace unrelated aliases.
A bare SSH connection does not provision machines; creation remains authenticated through MCP.

Read-only tools do not wait for the infrastructure writer. The Go scheduler serializes admission and
shared network changes, then releases the writer while guests boot. Independent creations can overlap
that wait; edits to the same machine remain ordered. This is a single-node scheduler.
`capacity_get` coalesces concurrent reads and caches physical observations for two seconds, with an
observation timestamp. Allocation always reads fresh capacity and includes pending reservations.
Jobs and node-side request receipts survive service restarts. Cancellation of a client connection
does not cancel an accepted job. Each retry remains bound to its original resource allocation.

For current VM images, readiness requires SSH **and** completed cloud-init, assigned managed
private NICs, and any requested `health_checks` (`service`, localhost `http`, or localhost `tcp`).
Without application checks, the result explicitly says `not_checked`. The fixed guest reporter
sends only status, check indices and an optional failed command index; no guest command output
or generic guest execution endpoint is exposed. Failed initialization leaves a standalone VM
available for owner diagnosis; a deployment follows its chosen failure policy.
CTs do not support `packages`, `runcmd`, `health_checks` or nested virtualization; configure their
applications over SSH after creation, or choose a VM for automatic application setup and checks.

Private networks default to `mode=managed`: an RFC1918 /24 or /25, fixed DHCP leases, MTU 1450,
and no default gateway or DNS override. DHCP runs in a separate unrouted namespace per network;
private bridge traffic cannot enter the host. New VM images auto-configure matching private NICs;
CT addresses are applied through Proxmox. Existing raw networks retain their behavior. Select
`mode=raw_l2` for experiments that manage their own addressing/DHCP, such as Mininet.
These topology tools are for routing experiments; ordinary app-to-database connections use the
deployment specification above.

CPU/RAM admission counts every allocated Carrel machine, including stopped machines. Deleting or shrinking CPU/RAM while stopped releases the corresponding reservation only after the
hypervisor confirms the change.
Tenant quota remains an upper limit, not pre-reserved capacity for uncreated VMs. vCPU is shared,
not a dedicated physical core. Direct administrator changes outside Carrel can invalidate admission
assumptions; the capacity endpoint includes unmanaged running infrastructure in its accounting.
When a temporary quota grant expires, the limit returns to its previous value and `over_limit`
reports any excess. Existing machines keep running. Growth in the exceeded dimension is blocked;
cleanup and reductions remain available. Administrator suspension is a separate explicit action.

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
The [0.4 intent acceptance](docs/evaluations/2026-10-01-intent.md) records the composed deployment
and restricted connectivity checks.
The [0.4.2 native agent acceptance](docs/evaluations/2026-10-01-agent-intent.md) records natural-language
discovery, previews, actual VM/publication/connection workflows and independent connectivity probes.
The [0.5 direct creation acceptance](docs/evaluations/2026-10-02-fast-create.md) records 42-second Debian
and 46-second Ubuntu creation, prepared development environments and linked-clone isolation/rollback.
The [0.5.1 PVE operations acceptance](docs/evaluations/2026-10-02-pve-operations.md) records fresh
inventory at 1.44 seconds, unchanged node network reconciliation at 2.02 seconds and one Debian
creation at 34.70 seconds, with live private-network, DNS, HTTPS and cleanup checks.
The [Python/Rust read-path experiment](docs/evaluations/2026-10-02-pve-language-benchmark.md)
compares both languages with CLI and direct HTTPS access, including fresh-process and reused-client timings.

The [0.6 Go acceptance](docs/evaluations/2026-10-02-go-control-plane.md) records a 29-second
single-call Debian VM, two overlapping VM creations in 39 seconds, persisted-job recovery
across restart, existing login continuity and live network/snapshot/backup checks.

The [0.7 common actions acceptance](docs/evaluations/2026-10-02-common-actions.md) records
single-call power operations, VM memory pause/resume, concise results, direct publication endpoints
and live lifecycle/snapshot/publication checks with cleanup.

The [v0.7.2 scope audit](docs/evaluations/2026-10-02-scope-audit.md) records baseline gaps in readiness,
offline NIC configuration, recovery, result presentation and quota requests, with isolated
reproductions and a proposed implementation order. Version 0.8 addresses A1 through A8; see the [scope fix acceptance](docs/evaluations/2026-10-02-scope-fixes.md).

Guest boot, package execution and connectivity are never verified by a plan. Never put private SSH keys or tokens in tool
arguments. Registration requires current `lab-member` membership or exact `winlab-admin` membership.
Project membership selects shared project tenants. All administrator tools check the admin group.

The server offers tools and empty MCP resource discovery. `catalog_get` lists images and sizes.
Custom image storage is not yet
supported, so `images_gb` is hidden from quota responses and requests; stored limits are preserved.
GPU allocation is unsupported; hardware GPU inventory is unknown.

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

The runtime is Go (1.26 or newer; CI uses 1.27.1). Run builds and tests in a development VM:

```sh
go test -race ./... -count=1
go vet ./...
CGO_ENABLED=0 go build -trimpath -o dist/carrel ./cmd/carrel
uv sync --locked
uv run pytest -q
uv run ruff check tests
python3 -m compileall -q scripts
```

Go owns the MCP server, OAuth, durable jobs, admission, state and backups. The existing bounded
Python node/edge mutation adapters and guest reporter remain. Go issues certificates itself
(ACME DNS-01 through Cloudflare). The Python tests cover these scripts; the Go tests cover the
service. The live wire contract is `internal/carrel/contract.json`.

Prepared VM templates move operating-system updates and base-package installation out of the member
creation path. On the sandbox, use `scripts/prepare-template.py` with a verified vendor qcow2 and its
SHA-256. Select `debian-13-minimal` for the minimal environment, or `debian-13` / `ubuntu-24.04`
for the development environment with the verified official Node.js archive. Preparation discovers
the actual ext4 root partition, preserves its numbering, retains security updates, removes machine
identity and SSH keys, and emits a hashed manifest. Copy the prepared image/manifest to the node,
then run `scripts/build-templates.py --prepared-dir <directory> --image debian-13-minimal --vmid-base <fresh-id>` there.
Repeat `--image` to import several images; omitting it retains the two-development-image workflow.
Allow at least 6 GiB of free image workspace plus space for the libguestfs appliance cache.
Kernel access may require sudo. Check appliance DHCP/DNS if package downloads fail. When a
sandbox's `passt` backend cannot obtain a DHCP lease, a task-local PATH shim returning 127 for
`passt` selects libguestfs's SLIRP fallback without replacing the shared installation or resolver.
APT index failures abort preparation; a failed candidate must not be activated.
After verifying the candidates, pass their generated `templates.json` to
`scripts/deploy-go.py --artifacts <sandbox-built-directory> --templates <directory>/templates.json`.
The deployment merges candidates into the existing template map, validates immutable templates,
updates the catalog's installed-environment metadata, and retains rollback copies. The prepared
minimal template is required before activating 0.9.0; it never falls back to a development image.
Keep previous generations for rollback. Existing template IDs are never overwritten.
Each node keeps its own `templates.json` and imports the same prepared image at VMIDs from its own
block of 20 (PLAN 6.1), because a linked clone works only on the node that holds its template.
`build-templates.py` refuses a VMID that exists on another node. The guest storage id is `storage`
in `/etc/carrel/node.json` (default `local-lvm`, the R640 node); B09 cluster nodes use `local-zfs`.
Set it before `configure-reader.py` and template import. `configure-reader.py` creates the read-only
PVE API token that node-agent uses on every node; it lives in `/etc/pve/priv/carrel-reader.json`,
which the cluster shares and only root reads.
Several nodes are listed in `/etc/carrel/config.json` as
`"nodes": [{"name": "carrel01", "target": "carrel-node-01"}, ...]`, where `target` is a `Host` in
`/etc/carrel/ssh_config`. A new machine goes to the node that admits it with the most admission
memory left, and the new machines of one deployment share a node. Each machine record keeps its
node, and every machine request goes to that node. Without `nodes`, carrel uses `carrel-node`
alone and records no node. The first node must reconcile; the others catch up on the next pass.
A site with its own public address (PLAN 15.15) sets `"ingress": "exit"` and
`"public_address": "<IPv4>"`. Its first exit node then terminates TLS and publishes ports, and the
external edge only keeps the backups. The control plane issues carrel's own certificate (live pair
`_origin` under `certificate_dir`) through DNS-01. The gateway receives it on the next reconcile, and only then do
carrel's records (the origin and every `*.<slug>.winlab.tw`) move to that address. A control plane
without `public_address` never rewrites records, so an old site cannot move them back. Stop the old
control plane before the new one starts.
New VM disks are linked clones on the guest storage (LVM-thin or ZFS); guest writes remain isolated. Requested extra packages still
refresh APT and install during initialization. Daily unattended security updates stay enabled.
Without a prepared manifest, the original templates retain their first-boot package installation.

The scripts are site-specific administrator operations, not the planned general `install.sh`.
The deployment order is documented in [PLAN 15.4](PLAN.md#154-member-platform-deployment): prepare
owned infrastructure, install networking/templates, connect the edge, upgrade the new proxies,
then deploy and publish. For an existing deployment with SSH aliases `carrel01` and `pve`:

```sh
python3 scripts/deploy-go.py --artifacts /path/to/sandbox-built/dist
```

The Go upgrade requires the existing site bootstrap and a configured control CT. The upgrade checks idle jobs and full PVE volume visibility,
keeps database/configuration/OAuth/certificates, and saves private service/node rollback files.
It installs prebuilt static binaries without compiling on the workstation or hypervisor.
Existing route/NAT state remains in place. See [PLAN 15.9](PLAN.md#159-go-control-plane-06-2026-10-02)
for the reader credential and rollback details. Secrets travel through SSH stdin and protected files. Never save a complete iptables ruleset
on the old host: its existing services and tailnet routes are independent of Carrel.

The `carrel-backup.timer` makes a consistent SQLite backup with config, service key and certificates
each day and stores 14 daily archives under `/var/lib/carrel-edge/backups` on the old PVE, mode 0600.
These are sensitive archives. They do not contain tenant disks and are not a replacement for PBS.
For restoration, stop the control service, restore `carrel.db` (remove stale `-wal`/`-shm` files),
`etc/carrel/`, and `certificates/` to their original locations, set the documented ownership,
then start the service and run `reconcile_run`. The archive also holds
`nodes/<name>/{node.json,templates.json,site.json}` for each node; put them back under `/etc/carrel`
on each node, mode 0644 root, before the control service starts (it reconciles at once, and a node
without its `site.json` would serve private DHCP itself). The result lists the SSH target of a node
that did not answer, or whose files exceeded 256 KiB, as `missing_nodes`, and the service logs a
warning. `/var/lib/carrel` is owned by `carrel:carrel`;
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

Saved SSH keys apply to future creations; removing one does not rotate existing guest keys.
Lost-key console recovery remains unavailable. Control backups include SQLite, configuration and
certificates, not tenant disks. Full tenant disaster restoration and install-from-scratch acceptance
remain separate release gates.
