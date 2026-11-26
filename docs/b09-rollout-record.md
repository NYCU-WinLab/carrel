# B09 rollout record

Moved from PLAN section 15. Section numbers stay the same, so "PLAN 15.9" means "15.9" here.

## 15.1 Inventory (2026-09-30)

- Node `carrel01`, formerly `server-d3`, in site `b09`; SSH alias `carrel01` via `b09-jump`.
- Management `192.168.13.159/24` on `vmbr0` / `nic1`, gateway and DNS `192.168.13.254`.
- Dell PowerEdge R640, Xeon Gold 5218, 32 CPU threads, about 187 GiB usable memory.
- PERC H730P Mini exposes one approximately 1.6 TiB logical disk. Installed storage is
  ext4 root plus a roughly 1.5 TiB `local-lvm` thin pool. RAID level / physical disk health
  have not been verified. No guest or template existed at handover.
- PVE 9.1.1, kernel 6.17.2-1-pve, nested virtualization enabled. No cluster configured.
- One management NIC connected; the other seven NICs are not connected.
- Outbound HTTPS was verified against Debian. Public inbound reachability is not assigned
  or verified. Never infer a usable public endpoint from a NAT egress address.

`sites/b09/carrel01.json` is the non-secret deployment inventory. Run
`scripts/host-preflight.py --config sites/b09/carrel01.json` on the node to recheck it.
The report is a prerequisite check, not a claim that M0/M1, isolation or MCP are ready.

## 15.2 Private bootstrap scope

Admin-only nested staging is running as VM `190`, `carrel-stg01`, with 8 vCPU, 24 GiB RAM,
a 32 GiB boot disk and a 160 GiB data disk (150 GiB usable thin pool). Its
management subnet is `172.31.255.0/24` on an isolated host bridge, separate from the tenant
address plan. Access uses the administrator's SSH key and ProxyJump. Staging receives no
production DNS, Keycloak client secrets or Cloudflare credentials.

This was the initial private stage. The member-facing implementation now follows in 15.4.
The old lab host remains outside the B09 cluster and provides the external ingress.

## 15.3 Verified bootstrap and remaining work

`sites/b09/bootstrap-verification.json` records the checks after rebooting the physical host:

- The physical node and staging VM start automatically, with no failed systemd services.
- Both PVE HTTPS endpoints validate against their own CA, and both LVM-thin stores are active.
- Staging starts a nested KVM process and reaches public HTTPS.
- Staging cannot initiate connections to physical-host SSH or port 8006, through either the
  staging bridge or the B09 management address, nor to the jump host's private SSH address.
- Both bootstrap scripts report `changed: []` on a second apply after the reboot.

The physical host remains on PVE 9.1.1 / kernel 6.17.2-1-pve. The separate nested test node uses
PVE 9.2.21 / kernel 7.0.14-19-pve from the current no-subscription repository. Align the supported
PVE version before production acceptance; these nodes are not members of the same cluster.

These earlier results verify the private bootstrap only. The platform work in 15.4 supersedes
the earlier MCP/network/ingress blockers. No entire milestone in 11.3 is marked complete by
the bootstrap checks or by the component checks alone.


## 15.4 Member platform deployment

Historical initial rollout. Current contracts and acceptance are in sections 1.6, 4.2, 5 and 15.6;
the later releases supersede the initial DHCP, quota-expiry and operation behavior below.

The public endpoint is `https://carrel.winlab.tw/mcp`. The dedicated public Keycloak client is
`carrel-mcp` in realm `winlab`: authorization code + PKCE S256 only, exact callback
`https://carrel.winlab.tw/oauth/callback`, access-token audience `carrel-mcp`, and full-path group
claims. `sites/b09/keycloak-client.json` is the non-secret client definition. The existing
`api-manager` client has user-management rights, not client-management rights; it was not broadened.
The client was created using the operator's authenticated Keycloak administrator browser session.

The MCP OAuth facade stores client registrations, fixed redirects, browser state/cookie binding,
consent, one-use code binding and refresh bindings in SQLite. Every MCP request verifies RS256,
issuer, expiry, audience and authorized party. Personal tenancy uses stable Keycloak subject IDs;
project tenancy uses exact project groups. Alumni-only users and legacy VM groups do not authorize
access. New hosted callback origins require an explicit allowlist change.

| Component | Placement |
|---|---|
| Control plane | B09 CT 100, `carrel-control`, `10.200.0.3:8080`, service user `carrel` |
| Tenant HTTP and recursive/internal DNS | B09 CT 101, `carrel-gateway`, `10.200.0.2` |
| Public proxy | Old PVE CT 207, `carrel-proxy`, `10.10.10.207`, Caddy 2.11.4 |
| Public TLS | Existing old PVE CT 200, one managed Carrel import alongside existing sites |
| Tunnel | `wg-carrel`, old PVE `10.254.200.1`, B09 `.2`, UDP 51890, MTU 1420 |
| Infrastructure bridge | B09 `vmbr98`, `10.200.0.1/24`, MTU 1450 |
| Templates | Key-free Debian 13 VM 9000, Ubuntu 24.04 VM 9001; Debian/Ubuntu CT templates |
| Database | `/var/lib/carrel/carrel.db`, WAL; systemd service and periodic reconciliation |
| Backup | Daily consistent SQLite + config + certificates, old PVE `/var/lib/carrel-edge/backups`, 14 days |

Tenant primary networks use the `tenants` EVPN zone and private networks use the `private` VXLAN
zone. Both are single-node today. `N` determines `10.200.N.0/24`, VMIDs and public port block;
private VNets have no gateway or DHCP. Tagged machines and bounded JSON adapters are the only
operations exposed through forced SSH commands. There is no shell or arbitrary PVE passthrough.
Separate owned nftables tables preserve pre-existing Proxmox, staging and old-host rules.

Two deployment details are required with this PVE setup: cross-VRF reentry uses connection-tracking
zone 1 plus a default route through `xvrfp_tenants`; DHCP's `0.0.0.0` source is included in the
primary IP set, then rejected by ordinary output rules after PVE's DHCP exception. Host DHCP is
allowed on the tenant VRF. These were discovered and verified with real guests, not inferred from
configuration alone. The DNS service waits for networking, binds dynamically and retries while its
address is unavailable; a second full host reboot verified the corrected startup ordering. The normal host dnsmasq service is masked; `carrel-dhcp` owns only tenant
reservations. New Caddy proxies use the pinned official 2.11.4 binary because packaged 2.6.2 panicked
during a live route reload. Service restart policies and readable config permissions are installed.

Tenant wildcard DNS is ownership-marked. DNS-01 and wildcard issuance/renewal run in CT 100, with
an initial 30-new-certificates-per-seven-days budget. Only certificate bundles go to the existing
TLS terminator; the new public proxy holds no DNS or Keycloak credentials. Exact tenant routes go
through both new proxies, with a 404 fallback. Removing a tenant's final domain removes its owned
wildcard DNS record. The old gateway's existing Cloudflare token exposure remains open decision 12.

Administrator deployment order (scripts have fixed B09 IDs/addresses and refuse occupied IDs):

1. Run `bootstrap-platform.py --role site --admin-key <public-key-path>` on `carrel01`, and role
   `edge` on the old PVE. This creates only owned CTs and installs their required packages.
2. Run `install-network.py` and `build-templates.py` on `carrel01`.
3. Exchange the hosts' `/etc/wireguard/carrel.pub` values with `configure-link.py site|edge <peer-public-key>`.
4. From the workstation with the administrator SSH aliases, run `upgrade-proxies.py`,
   `deploy-control.py`, and `publish-entry.py`. Deploy uses hashed lockfile dependencies and preserves
   dynamic routes. Publish initializes empty NAT state only on a new installation.
5. Create/verify the Keycloak client definition through an authorized administrator; use disposable
   member accounts with `verify-oauth.py` and `verify-platform.py` for acceptance.

The initial quota was a conservative shared default: 8 vCPU, 16 GiB RAM, 100 GiB allocated disk
(raised to 16 vCPU, 32 GiB and 200 GiB on 2026-11-13: 9 creates failed on quota in 27 days while the nodes ran at about 15% of their admission limit),
4 machines/IPs (raised to 8 in section 15.14), 10 public ports/domains, 4 private networks and 4 snapshots. Project/subgroup-specific
policy remains open decision 2. Snapshots reserved a full disk size before adapter work (they count at the space they hold since 2026-11-17, section 5.2); rollback refuses changed NIC or
resource configuration. Interrupted disk growth keeps the larger quota reservation and can be
retried with the same `machine_resize` arguments. Temporary quota expiry stops over-limit machines and prevents restarting
until allocations fit. Mutations currently serialize through one process-wide lock; long image or
certificate work therefore delays other mutations.

`sites/b09/platform-verification.json` records acceptance facts and limitations. Tests use temporary
users/guests, never existing members' machines. Their permanent tenant serials are retired after
cleanup. This release implements the MCP/identity/network core of M1 to M5. It does not claim full
milestone acceptance: M0 clean nested CI install, M2 real agent-driven acceptance, M3 console/key
recovery, M4 special domains/ports, M5 multi-node cases, M6 images/ISOs, M7 skills, M8 PBS/telemetry/
notifications/alumni lifecycle, M9 import and M10 cluster expansion remain. TLS renewal exists in
code; a real expiry/renewal cycle still needs acceptance. The database backup restore check does
not substitute for a full disaster-recovery exercise. No email was sent during this deployment.

## 15.5 MCP planning and Codex acceptance (2026-10-01)

Historical 0.2 acceptance. The 0.3 reliability report and 15.6 supersede its tool/test counts and
snapshot power-state behavior. These numbers describe that run, not the latest release.

Member discovery now has 37 tools plus 9 admin-only tools. `whoami` returns all visible tenant
quotas with remaining amounts, default tenant and capabilities; `catalog_get` combines image/size
queries. The two previous list names remain callable compatibility aliases. Unsupported image
quota fields are hidden without deleting their stored values; units are MiB/GiB throughout.

Mutation previews share before/delta/after quota accounting and never reserve resource identifiers.
Missing SSH keys become planning requirements; actual creates still require valid public keys.
`deployment_plan` validates aggregate machines, networks and symbolic NIC attachments without
resource writes. `capacity_get` exposes aggregate hardware and admission policy, with no other
tenants' guest details. Admission counts all local-lvm volumes and incomplete reservations.
MCP resources and resource-template discovery return empty lists.

59 automated tests pass. Six fresh native Codex sessions and one resumed prompt use the same
inputs as the baseline: 48 to 21 MCP calls, no unexpected tool failures, one expected quota
rejection. These runs perform reads/previews only, with no shell or resource changes. See
[the evaluation and evidence](evaluations/2026-10-01-codex-mcp.md) for per-case results and
separate disposable-VM lifecycle acceptance. This does not establish multi-node or full M2
acceptance; unsupported features remain tracked in the product plan.

The subsequent disposable Ubuntu VM check also found and fixed rollback reporting: disk-only
snapshot rollback may stop a guest, and now returns/persists its actual power state with an
explicit start action. See the evaluation for public SSH/HTTPS, rollback and cleanup evidence.


## 15.6 Intent and reliability acceptance (0.4, 2026-10-01)

The member path is machine, connection and publication intent on `deployment_plan` / `deployment_apply`.
Explicit restricted ingress enforces exact source/protocol/port rules and prevents unfiltered NIC bypass
(superseded 2026-10-20, issue #75: restricted filters the primary NIC only).
The same deployment can publish an existing application. The five reliability fixes in sections 4.2,
5.3 and 1.6 are deployed: DNS failure isolation, quota expiry without blanket stopping, durable
certificate waits, independent tenant onboarding and immediate suspension admission blocking.

114 local tests pass; live OAuth/MCP acceptance passed with three restricted VMs and a separate tenant
CT, public SSH/HTTPS/TCP HTTP, designated database access, negative source/port/protocol checks,
publication reuse and complete cleanup. Member tools remain 40; admin tools remain 9. The public
service reports 0.4.0 and final installed hashes match. See the
[intent acceptance report](evaluations/2026-10-01-intent.md) and the preceding
[0.3 reliability report](evaluations/2026-10-01-reliability.md) for evidence and limits.


## 15.7 Direct creation and prepared development VMs (0.5, 2026-10-02)

An authorized single-machine request uses `machine_create` directly. Discovery and previews remain
available when requested. Creation calls wait up to 55 seconds for verified readiness; a bounded
wait or client disconnect preserves the durable worker. `wait_seconds` is response policy, excluded
from idempotency identity. Pending work is continued with `operation_get`.

New VM disks use linked LVM-thin clones of immutable templates. Prepared Debian 13 and Ubuntu 24.04
images contain current OS updates, GCC/G++, make, CMake, Python with pip/venv, Node.js 24 LTS with npm,
Docker with Compose, Git and common command-line utilities. Package installation moves to the template
build; user-requested packages still refresh APT and install at first boot. Daily unattended OS security
updates remain enabled. Node.js point releases are pinned by archive digest at template build time.
CTs retain their minimal distribution environment. No warm pool or SSH provisioning gateway is added.

Template preparation runs in the development sandbox with libguestfs. New template generations use fresh
VMIDs and hashed manifests; activation is a separate node configuration change. Existing guests and
previous templates remain intact. A creation receipt pins its template generation across retries.
Template sanitation removes SSH keys, guest status credentials, cloud-init state and machine identity.

Results include tenant-scoped SSH aliases and the client stanza required to use them. An alias can look
like `<machine>.<tenant>.winlab.tw`, but it selects the allocated port through local SSH configuration.
DNS alone cannot select guests sharing an IPv4 address and port because SSH sends no destination-hostname
routing field. In local CLI clients, creation and connection requests include merging the returned
tenant-qualified SSH stanza without replacing unrelated entries, checking HostName/User/Port with
`ssh -G`, and presenting the short command. No separate alias request is needed. Status-only requests
do not modify client configuration. Direct public-port commands remain the fallback when client file
access is unavailable, setup is excluded by the user, or setup fails. Host-key checks stay enabled.
Pure SSH provisioning and subsecond warm capacity are separate product decisions, not claims of this release.

Live [0.5 acceptance](evaluations/2026-10-02-fast-create.md) measured two Debian creations at
about 42 seconds and an Ubuntu creation at 46 seconds, each returning verified readiness from one
tool call. The prior Debian server operation took 97.71 seconds, including 39.205 seconds of base
package installation. Adapter timing attributes the remaining time primarily to PVE operations
and guest readiness. Optimize these paths before considering a language rewrite. The current
serialized writer can add queueing under concurrent demand; no concurrency SLA is established.

## 15.8 PVE observations and gateway updates (0.5.1, 2026-10-02)

Fixed local read helpers load the PVE API handlers once for each inventory/topology observation.
Admission still obtains fresh data and counts all local-lvm image/rootdir volumes, current pool
pressure and existing reservations. No cross-request cache is introduced. Ownership checks,
mutation serialization and generated firewall policy remain unchanged.

Tenant DNS and Caddy updates now enter CT 101 once. Unchanged configurations avoid reloads;
stopped services recover. Caddy validation precedes replacement, writes are atomic and successful
apply receipts ensure retries after a failed service action. The helper only writes fixed paths.

157 tests and live VM/CT SSH, internal DNS, managed private networking, external HTTPS and full
cleanup pass. Node inventory falls from 4.37 to 1.44 seconds and unchanged eight-tenant node network
reconciliation from 4.83 to 2.02 seconds. A default Debian VM returns ready in 34.70 seconds from
one MCP call. Sample counts, remaining limitations and deployed hashes are in the
[PVE operations acceptance](evaluations/2026-10-02-pve-operations.md).

Startup probes measure Python at about 14 ms and the PVE module/environment at about one second.
Direct HTTP API access may remove the remaining module startup regardless of language, but no
Rust/HTTP comparison was run. Warm pools and a language rewrite are not part of this release.

A subsequent [read-path experiment](evaluations/2026-10-02-pve-language-benchmark.md)
compares Python and Rust across 12 interleaved fresh-process trials and five reused-client blocks.
Direct HTTPS inventory/topology medians are 409/80 ms in Python and 347/16.4 ms in Rust. Reusing
the client yields 335/11.22 ms and 338/10.98 ms. Rust saves about 63 ms in the per-request process
design; direct API access provides most of the improvement over either language spawning `pvesh`.
The experiment also catches PVE API volume filtering under audit-only credentials. Any production
HTTP reader must preserve all-volume visibility. No production transport change is part of this experiment.


## 15.9 Go control plane (0.6, 2026-10-02)

The Go service owns Streamable HTTP MCP, Keycloak OAuth/PKCE, SQLite state, intent planning,
admission, a durable FIFO mutation queue, readiness and backups. Existing SQLite tables and
OAuth bindings remain compatible; migration does not require member login. Python remains for
the bounded root mutation adapters, guest reporter and deployment tooling. The former
Python control plane served as a test reference until it was removed on 2026-10-20.

Admission and shared PVE/network mutations use one writer. A persisted `prepared_result` releases
that writer during SSH/guest-report readiness. Other allocations can begin, while edits to the
same allocation wait. Deployment groups start all new guests before waiting. Report arrival wakes
readiness immediately; a periodic SSH probe remains. Cancellation does not cancel accepted work.
Recovery resumes the checkpoint; adapter receipts are keyed by a hash of the request (plain JSON
since 2026-10-20; deploys wait for idle jobs, so no receipt spans the change).
This does not introduce multi-node scheduling or independent parallel network writers.

Display capacity observations have a two-second cache and coalesce simultaneous reads. Every
admission reads fresh inventory and current SQLite reservations. Network-only plans skip compute
inventory. Physical snapshot accounting runs in maintenance and snapshot operations, outside the
ordinary network/create path. SSH transports reuse authenticated connections for up to 120 seconds.

node-agent reads the local PVE API over HTTPS in-process (changed 2026-10-20): one
connection per adapter run, the PVE CA and the node's own name verified, no arbitrary paths and
no stale fallback. Every read uses it, including ownership and power checks; writes stay with
`pvesh` and `qm`/`pct` as root. A `pvesh` start costs about a second per read. The earlier fixed
Go helper `carrel-pve-read` and the Perl batch reader were removed: the helper reached only the
first node, so the other nodes kept the slow reader. Full volume visibility is mandatory:
PVEAuditor alone returns filtered storage content, so every inventory first checks the token's
permissions on the guest storage. `scripts/configure-reader.py` provisions the
privilege-separated `root@pam!carrel-reader` token with PVEAuditor at `/` and a custom role with
Datastore.Audit and Datastore.Allocate at `/storage/<guest storage>`. This credential has a
storage management privilege, even though node-agent issues only GET requests with it. Its file
`/etc/pve/priv/carrel-reader.json` is cluster-wide and root-only, so every node reads the same
token without a copy step. It never reaches CT 100, guests or clients, and backups leave it out.

Build static binaries in the development sandbox. `scripts/deploy-go.py --artifacts <directory>`
checks no active jobs and runs `configure-reader.py`. It saves a consistent database/config/certificate/service
archive under CT 100's `/opt/carrel/rollback/` and node files in the printed node stage directory.
Existing OAuth, certificates and guest templates are preserved. The
backup timer runs `carrel -backup`, retaining the existing private archive destination and format.
A failed initial health check restores service/node files without overwriting newly written data.

For a manual rollback, stop the control service, restore the saved service units and previous binary
(if any), restore the saved node adapter and `node.json`, reload systemd and restart. Restore an older database only as an explicit disaster-recovery
operation after reconciling all resource changes since that backup. `configure-reader.py --remove`
removes the reader token, its ACLs, role and file.

Go race tests, 79 Python behavior fixtures and the existing Python reference tests validate the rewrite.
The [Go evaluation](evaluations/2026-10-02-go-control-plane.md) records live read-path measurements
and rollout acceptance. This release adds no warm pool or SSH provisioning gateway.

Live 0.6 acceptance: the public service reports 0.6.0, installed hashes match and existing
MCP authentication survives both migration and restart. One default VM takes 29.008 seconds
(previous 0.5.1 sample 34.696); two immediate submissions finish in 38.917 seconds together.
Private VM/CT networking, restricted ingress, external HTTPS, snapshot file restoration,
checkpoint restart without duplicate creation and real backup integrity all pass. All seven
disposable guests are removed, original volumes/quotas restored and `ssh dev01` remains valid.
These small samples do not establish an SLA. See the evaluation for client serialization,
resource sizes, operation IDs, precise timings and retained Python helpers.


## 15.10 Common member actions (0.7, 2026-10-02)

Ordinary lifecycle guidance ships in the MCP instructions and relevant tool descriptions. It does
not require another skill lookup, operator memory or topology discovery. The larger skill catalog
in section 4.5 remains planned. The 40-tool member discovery surface is unchanged.

- Extend the existing `machine_power` with VM `pause`/`resume`, using in-memory QEMU suspension.
  CT suspension is deliberately unsupported because PVE implements it as experimental disk
  checkpointing. Pause retains allocations, disables automatic boot, and does not survive host
  power loss. Start resumes a paused VM; graceful shutdown/reboot perform any needed resume internally.
- Verify power transitions at the node, including QMP paused state. Repeated target-state requests
  are no-ops. Graceful shutdown explicitly disables forced-stop fallback. CPU/RAM reservations
  remain allocated when stopped or paused. Normal start/resume is allowed with existing
  reservations even if a temporary quota grant has expired; no capacity is added.
- All member infrastructure mutations and operation retries wait up to 55 seconds by default.
  Start/reboot/resume persist the readiness checkpoint outside the shared writer. Start from stopped
  and reboot require a new boot report; resume can keep its existing boot. Restart recovery reuses
  the node receipt and persisted baseline rather than replaying an acknowledged mutation.
- MCP summary presentation removes full before/after quota tables and internal allocation details
  from successful operations. `detail=full` and durable storage retain them. Previews, pending
  operations, failures, cleanup evidence and recovery instructions remain complete. Presentation
  options do not affect idempotency identity. Machine list is explicitly recorded state; machine
  get performs one live observation and cannot label a paused process SSH-ready.
- The current Go contract is maintained directly. No new scheduler, cache or warm pool is
  introduced by this release.

Validation: Go race tests/vet and static builds, 177 Python tests, Ruff and script compilation run
on sandbox VM104. Live acceptance passed on disposable VM/CT guests, including paused restart/shutdown,
owner SSH, snapshot rollback, external HTTPS/TCP and complete cleanup. See
`docs/evaluations/2026-10-02-common-actions.md` and its JSON evidence.

## 15.11 Bootstrap and discovery follow-up (0.7.2, 2026-10-02)

A native CLI system-information web demo hit the old 4,096-character command argument limit with
a 13,297-character bootstrap script, then succeeded after splitting the source across arguments.
VM command arguments now allow up to 64 KiB of UTF-8 data each, checked before queueing or admission
for individual creation, deployment previews and deployment application. The existing 256 KiB HTTP
request ceiling stays in place. Larger projects should transfer files over SSH after creation.
This extends the existing bootstrap mechanism without adding an upload API or another tool.

Successful deployment summaries omit the internal allocation/cleanup receipt while retaining
machine access, declared connections and published endpoints. Full results, durable records and
pending/error recovery data retain the receipt. Discovery guidance directs feature questions to
`catalog_get` and asks clients to inspect only relevant tool definitions, avoiding repeated server
instructions across a dump of every tool. Local SSH alias setup remains the default completion step.

## 15.12 Member scope audit (v0.7.2 baseline, 2026-10-02)

The [scope audit](evaluations/2026-10-02-scope-audit.md) maps all 40 member tools to user
outcomes and records seven reproduced behavior problems plus an existing-machine isolation gap.
These findings describe the v0.7.2 baseline; section 15.13 records their implementation. First address stale readiness, offline NIC
configuration and premature application-health rollback. Then make summaries, deletion receipts
and recovery guidance usable without extra discovery; align quota request validation and
idempotency with approval. Existing-machine isolation changes and guest-visible resize completion
need explicit acceptance cases. The audit adds no runtime feature or deployment requirement.


## 15.13 Consistent outcomes across scopes (0.8, 2026-10-02)

A1 through A8 are addressed by the existing tools. Summaries preserve private IPs, named NICs and
ingress grants; port/domain/peer lists resolve user-facing identities. Removal receipts say deleted
only after cleanup. Live power/SSH and report freshness are separate signals. Offline managed NIC
configuration preserves power state and verifies interfaces on the next authorized start/resume.

Application checks get `application_ready_timeout` (default 120 seconds) after cloud-init completion,
bounded by `guest_ready_timeout`. Deadlines survive restarts; explicit retries start a new window.
Bootstrap failures remain immediate. Typed recovery covers input conflicts, capacity, prerequisites,
guest repair and cleanup. Backend failures include bounded component/error codes and operation/request
correlation, never arbitrary adapter output. Quota requests share approval validation and deduplicate
keys after approval/expiry. Approval and expiry save quota and decision in one transaction.

`deployment_plan` and `deployment_apply` accept `access` entries for existing machines, with machine,
network_access and confirm (the machine name for a mode change). Previews explain connectivity lost
or enabled. The operation reserves policy changes and connections atomically, binds allocations and
reconciles. Experiment NICs no longer prevent restricted ingress (superseded 2026-10-20, issue #75):
restricted filters the primary NIC only, and private NICs stay unfiltered.
SSH, publications and old peer grants remain. Rollback restores a prior policy only if the operation
still owns it on the same allocation. Results include affected existing machines.

Resize separates allocated block capacity from unverified guest filesystem growth, with owner SSH
follow-up and no implicit reboot or guest execution API. HTTPS preparation persists reserved domains
before DNS/ACME work outside the writer; issuers serialize separately from it.
Finalization checks allocation/domain identities and tenant status again. Renewal also runs outside
the writer. Same-machine mutations stay ordered, unrelated jobs proceed during propagation.

See [scope fixes](evaluations/2026-10-02-scope-fixes.md) for acceptance. Saved-key changes still
only affect future guests; control backups exclude tenant disks. Live acceptance passed on three
disposable guests with all temporary resources removed. Paused NIC removal now rejects before
PVE can write a pending unplug; resume or shutdown is an explicit prerequisite. Full disaster recovery, custom images,
multi-node scheduling and console/key recovery remain deferred. Member tool count remains 40.

## 15.14 Minimal defaults and eight-machine quota (0.9, 2026-10-04)

The default VM is `debian-13-minimal`, `tiny`: 1 vCPU, 1024 MiB RAM, 10 GiB disk and
1024 MiB swap. Explicit development images keep their prior `small` preset. Single-machine
creation and deployment plan/apply resolve the same defaults; MCP schemas, instructions and
catalog explain both environments and resource overrides. Guest management and isolation
remain identical across prepared images. Minimal preparation performs no Node download or
Docker installation and never assigns a nonexistent docker group.

A one-time transactional migration raises untouched 4-machine/IP defaults to 8, with audit
events. Custom lower/higher limits, explicit admin decisions and approved temporary grants
are preserved, including their expiry behavior. Other dimensions and existing guests remain
unchanged. A failed migration prevents startup and rolls back its transaction. Physical
admission and ten-port blocks remain enforced; this is not unlimited creation or guaranteed
future resize capacity.

Build and inspect the new image in the sandbox, import at a fresh template ID, and merge its
manifest during deployment. Activation requires an immutable prepared minimal template and
updates the catalog environment metadata together with the control/node programs. Existing
development templates remain available. Rollback restores programs, template selection and
configuration; it does not blindly restore an older database or guest disks.

Resize still separates confirmed block allocation from owner-verified guest capacity. Agents
inspect the actual root device over owner SSH, grow its partition/filesystem where appropriate,
and verify `df` before reporting usable space. CPU/RAM changes may require an authorized restart;
reductions require a stopped guest and disk shrinking remains unsupported.

## 15.15 Four-node cluster (2026-10-19)

**Hardware**, the same on every node (`carrel01` to `carrel04`, management `192.168.19.101` to
`.104/24`, gateway `.254`):

- Intel D51B-1U, 2x Xeon E5-2630 v4 (40 threads), 125 GiB RAM.
- 2x 300 GB 10k SAS disks. The installer made `rpool` a ZFS stripe of both disks: 552 GiB, no
  redundancy. The stripe stays by decision (section 1.5).
- 4x X540 10GBase-T and 4x X710 SFP+ ports. One port links at 1 Gbit/s (`nic1` on `carrel01`,
  `nic2` on the others). The other ports have no cable.
- Management is untagged. VLAN 60 arrives tagged on the same port: `140.113.60.160/27`, gateway
  `140.113.60.190`. carrel uses `140.113.60.184`. A capture on `carrel01` saw the tagged frames,
  and the gateway's ARP requests for `.184` got no answer, so the address is free.

**Done on 2026-10-19**:

1. Apt: the enterprise repositories are disabled. PVE and Ceph `no-subscription`, Debian and
   Debian security use `mirror.twds.com.tw`. The original files are in `/root/apt-backup-20261019`.
2. `full-upgrade` to `pve-manager` 9.2.21 on every node. The kernel did not change, so no reboot
   is pending.
3. Cluster `carrel`: created on `carrel01`, then the other three joined. Corosync link 0 uses the
   management addresses. 4 votes, quorum 3.
4. `/etc/hosts` on every node lists all four nodes.

The bridge is not VLAN-aware yet. SDN, the firewall and carrel itself are not installed, and no
guest exists.

**Gaps to close before the move**. One change per pull request, each tested on this cluster while
it is empty:

1. **Storage and templates per node.** `local-lvm` is hardcoded in `node-agent.py`,
   `build-templates.py`, `deploy-go.py`, `bootstrap-platform.py`, `pve-read.pl`,
   `internal/pveread` and `configure-go-reader.py`, and `lvs pve/data` assumes LVM-thin. Read the
   storage id from site configuration. `templates.json` maps each image to one VMID; make it map
   each image to one VMID per node, from that node's block of section 6.1, and import one prepared
   image on every node. Linked clones work only on the node that holds the template.
2. **A node on every machine.** The Go `Backend` targets one `carrel-node`, machine records have no
   node, and admission reads one node under the scope `carrel01`. Add per-node targets, placement
   by free capacity, admission over all nodes and a `node_list` that returns every node. Existence
   checks read `/etc/pve/nodes/*/`, not the local symlink. cloud-init snippets on `local` exist only
   on the node that wrote them, so the snippet must exist wherever the machine starts.
3. **Underlay.** Implement the rule of section 6.3 on the management interface, the only link
   today. The `peers` of both zones list the four management addresses. Today the nftables rules
   drop UDP 4789 and TCP 179 on every interface.
4. **Exit node and ingress.** `vmbr0` becomes VLAN-aware, and the exit node holds
   `140.113.60.184/27` on `vmbr0.60`. That change also decides the exit node's routing: the host
   default moves to `.190`, or policy routing keeps management on `.254`. The public port DNAT
   uses `.184`, and so does tenant egress (corrected 2026-10-20): traffic leaving the VRF goes
   out `vmbr0.60` and is SNATed to `.184`. The hosts and the infra CTs keep the management path
   through the lab router (`140.113.60.189`). The infra gateway serves HTTPS on `.184:443`. CT 207 and
   `wg-carrel` retire for carrel. `public_entries` and `protected_addresses` change to the new
   address. The Cloudflare records of `carrel.winlab.tw` and every `*.<slug>.winlab.tw` move from
   `140.113.194.229` to `.184`. This step changes DNS and certificates, so it gets an independent
   review.
5. **Control plane reach.** CT 100 must reach the node agent on every node. Today `infra.nft` drops
   CT 100 traffic to `192.168.0.0/16`, and node `authorized_keys` accept only
   `from="10.200.0.3"`. CTs 100 and 101 stay on the exit node.
6. **Private DHCP.** The `carrel-pNNNNN` namespace puts the subnet's `.1` on every node that
   reconciles. On a layer 2 network shared by four nodes, exactly one node may hold it.
7. **Installer.** `install-network.py` accepts only `carrel01` and `carrel-stg01`,
   `bootstrap-platform.py` asserts the hostname, and the deploy scripts hardcode the SSH aliases
   `carrel01` and `pve`.
8. **Backups.** `carrel -backup` leaves out `node.json`, `templates.json`, `pve-read.json`, the
   nftables files and the WireGuard key. Tenant disk backups need storage outside the cluster
   (open decision 13.14).

**Status on 2026-10-19 (late)**:

- Closed: gap 1 (#42), gap 2 (#43, #44), gap 3 and gap 6 (#46), gap 4 (#47 ports and the public
  address, #49 TLS on the gateway, #50 the origin certificate and DNS records). Each was tested on
  this cluster while it was empty; the reviews found and fixed cross-node conntrack zones (VXLAN and
  L3VNI ports), a reconcile stopped by one down node, a tenant slug colliding with the origin
  certificate, and record moves before the gateway held the certificate.
- Installed on the cluster: the site file on every node, `install-network.py` (SDN peers, underlay
  filter), `140.113.60.184/27` with its protection on carrel01, and `bootstrap-platform.py` (CT 100
  without the control plane yet, CT 101 with Caddy 2.11.4 and `carrel-dns`).
- Gap 5: `scripts/configure-nodes.py` on the first exit node copies the node programs to every
  node, authorizes CT 100's node key once in the cluster-wide `authorized_keys`
  (`from="10.200.0.3,<exit node address>"`), and writes CT 100's SSH targets, pinned host keys
  and `config.json` `nodes`. `infra.nft` lets CT 100 reach the other nodes' SSH.
- Gap 7 (#54): the site role and deploys run on the first exit node of the site file
  (`deploy-go.py --host`), and a deploy runs `configure-nodes.py`, rolling back CT 100's node
  files if it fails.
- Gap 8: the control backup keeps `nodes/<name>/{node.json,templates.json,site.json}`.
- Every gap is closed. Follow-ups: #45, #48, #51.
- `ingress: exit` and `public_address` stay unset until the move: the new control plane then moves
  the records itself, after its gateway confirms each certificate.

**The move, done on 2026-10-20**: the R640 and the cluster share the lab router's public address
(`140.113.60.189`) but not a route between their management networks, so a temporary WireGuard
tunnel from the R640 to `140.113.60.184` carried the data (about 100 MB/s; removed afterwards).
The templates were restored once on carrel01 and streamed to each node at its own VMIDs. CT 100
moved whole, the current main was deployed with `deploy-go.py --host`, and the nine tenant VMs
moved one at a time (35 to 112 seconds of downtime each) to carrel01. With `ingress: exit` the
control plane moved the tenant records once the gateway held their certificates, then issued the
origin certificate and moved `carrel.winlab.tw`. Two findings: the infra CTs need MTU 1450 on
`vmbr98` (large replies to direct clients were dropped), and node-agent now takes the TLS gateway
mode from the control plane's `origin` instead of the site file. The R640 guests stay stopped
(onboot off) for 14 days.

**The move** (the steps as planned):

1. Install carrel on the cluster. Restore the CT 100 database and configuration from the latest
   `carrel -backup`, and recreate CT 101. Then run `configure-nodes.py` again: the restored
   `ssh_config`, `known_hosts` and node key come from the R640 site.
2. Import the templates on every node.
3. Lower the Cloudflare TTLs one day ahead.
4. Tell the owners, then move the tenant VMs with `qm remote-migrate`, one tenant at a time. The
   target storage is `local-zfs`, and the VNets keep their names. On 2026-10-19 the R640 node held
   9 tenant VMs of 5 tenants: 12 vCPU, 15 GiB RAM, 130 GiB allocated. Staging VM 190 does not move.
   Set each moved machine's `node` to the node it lands on. A record without a node belongs to the
   first entry of `nodes`, so a restored database or a reordered list would move it silently.
5. Switch the records to `.184` and check from outside the campus (section 10.7).
6. Keep the sources stopped on the R640 node for 14 days, then retire it. Its name `carrel01` is
   also on the tailnet, in admin SSH aliases and in sensorium. Rename those before the new
   `carrel01` joins the tailnet.

## 15.16 Node agents (0.13.0, 2026-11-26)

All 4 nodes moved from SSH to `carrel-agent` (PLAN 8.6, #604), one node per deploy, with no
machine change. Each deploy was `deploy-go.py --release v0.13.0` after adding the node to
`agent_nodes` in `/etc/carrel/site.json` on carrel01 (backups `site.json.bak-20261126-*`).

1. carrel01 first. Before the other nodes, `bootstrap-platform.py --firewall` added one rule to
   `/etc/carrel/infra.nft`: port 8443 from `192.168.19.102` to `.104` on `vmbr0` to `10.200.0.3`.
   `/etc/pve/firewall/102.fw` did not change.
2. carrel02, carrel03 and carrel04 followed. Each logged `agent_started` and `agent_connected`
   within the deploy's wait.
3. Check: `node_list` shows all 4 agents connected, with `stream`, and no stale or lagging node.
   The control plane logged no WARN or ERROR in the 15 minutes after. A snapshot of a test machine
   on carrel01 was created and deleted through the agent (`qmdelsnapshot` in the agent's log).

The same day, before the agents:

- The backup host takes `service_key` only (#606). Its 2 `node_key` lines are gone; a manual
  `carrel-backup.service` run logged `backup_complete` through the control socket.
- Root on every node also takes lab SSH certificates for the principals in `node_ssh_ca` (#647).

`node_key` and its `authorized_keys` line stay until the agents sign in with step-ca certificates
(#601) and the boot replay passes a reboot test (#603), so `agent_nodes` can still go back to SSH.
