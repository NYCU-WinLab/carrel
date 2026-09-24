# carrel product plan

This is the only design document. When the design changes, this file changes in the same pull
request. Sections are numbered so issues and commits can cite them (for example "PLAN 5.2").

## 1. Positioning

### 1.1 What it is

carrel turns one or more Proxmox VE hosts into a self-service machine platform for NYCU WinLab.
A member asks their own agent (Claude Code, Codex, any MCP client) for a VM or a container. The
agent calls the carrel MCP endpoint, the member signs in with their lab Keycloak account, and the
platform creates the machine inside the member's quota and hands back an SSH line.

### 1.2 One sentence

Ask your agent for a machine, get an SSH line back, and never touch Proxmox.

### 1.3 Who it is for

- **Members**: current lab members and project teams. Their only entry point is MCP.
- **Admins**: members of the Keycloak group `winlab-admin`. Only admins touch Proxmox, and they
  also work through MCP (admin tools, section 4.4). SSH to a host is the break-glass path.

### 1.4 What it is not

- Not a manifest or container platform. Members get pet machines they SSH into and change by
  hand. Declarative workloads belong to kitbash (`zyx1121/kitbash`), which carrel does not extend.
- Not a public cloud. One installation serves one organization, and tenants are lab members and
  lab projects.
- Not a place where admins look inside tenant machines (section 7.7).
- Not a human web UI. Version 1 has none. Onboarding is the README.

### 1.5 Decisions already made

| Date | Decision |
|---|---|
| 2026-09-24 | Machines are pet VMs and CTs with SSH, so carrel is its own project and not a kitbash run kit |
| 2026-09-24 | winfra-paas is retired. Its Keycloak OAuth MCP layer may be reused as code |
| 2026-09-24 | Members reach the platform only through MCP. Only admins touch Proxmox |
| 2026-09-24 | Domains are `<sub>.<tenant>.winlab.tw`, knowing that tenant sites can set `.winlab.tw` cookies |
| 2026-09-24 | Admins do not enter tenant machines (policy plus hardening, section 7.7) |
| 2026-09-24 | Tenants include projects, not only members. Quota requests and member self-rescue are in scope |
| 2026-09-24 | Images are LTS or stable releases still under vendor security support, at most 3 per distribution |
| 2026-09-24 | Everything is built fresh on a new Proxmox host. The existing lab host is reference only |

## 2. Object model

| Object | What it is | Key |
|---|---|---|
| Site | One Proxmox cluster in one room. Sites never share a corosync ring | `site` slug |
| Node | One Proxmox host in a site | node name (`pve1`, `pve2`, ...) |
| Tenant | A member or a project. Owns quota, a network, machines, ports and domains | serial `N`, slug |
| Machine | A VM or an unprivileged CT owned by one tenant | VMID |
| Grant | One allocation against quota: a port, a domain, a peer rule, a snapshot | id |
| Request | A quota request waiting for an admin | id |

The platform database is the single source of truth. Proxmox state, firewall rules, NAT rules,
DNS records and proxy routes are all derived from it and rebuilt by the reconciler (section 9.2).
Nobody hand-edits a derived rule, on a host or anywhere else.

## 3. Identity and tenancy

### 3.1 Keycloak

Keycloak already runs at `https://auth.winlab.tw`, realm `winlab`. On 2026-09-24 it held 265 users
and these groups:

| Group | Members | carrel meaning |
|---|---|---|
| `lab-member/112` to `lab-member/115`, `master`, `doctoral`, `undergrad`, `assistant`, `teacher` | 54 distinct users | may use carrel; the subgroup picks the default quota |
| `lab-member/alumni` | 23 | may not create machines (lifecycle, section 10.3) |
| `winlab-projects/<project>` | 6 projects | each project is a tenant with a project quota |
| `winlab-admin` | 4 | carrel admins |
| `vm-users`, `vm-sudoers` | 0 | created earlier by someone else; open decision 13.1 |

The MCP endpoint is an OAuth protected resource. Keycloak is the authorization server. The platform
reads `preferred_username` and the `groups` claim from the token and never trusts a tenant name
sent as a tool argument.

### 3.2 Tenants and serials

Every tenant gets a permanent serial `N` when it is first seen. Members and projects share one
serial space. `N` is never reused, so a stale rule can never point at a new owner.

- `N = 0` is the platform itself (infra network).
- `N = 1` to `254` are tenants. A second site or a larger range is a later change to this section.

### 3.3 Slugs

A tenant slug names its DNS zone and appears in machine names. It is derived once and then fixed.

1. Lowercase the Keycloak username (or the project group name).
2. Replace every `.` and `_` with `-`, collapse repeated `-`, trim `-` at both ends.
3. Refuse slugs longer than 32 characters or made only of digits.
4. Refuse any slug that is reserved (section 6.5) or already a live label under `winlab.tw`.
5. On refusal an admin assigns an alias. The alias is stored and never recomputed.

On 2026-09-24, 49 of the 265 usernames contained `.` or `_` (3 of them active members), and one
username (`claude`) collided with an existing record. No `*.winlab.tw` wildcard exists.

## 4. MCP surface

### 4.1 Transport

Streamable HTTP at `https://carrel.winlab.tw/mcp`, OAuth through Keycloak. The server declares an
output schema for every tool, including the error shape, so an error is a tool result and never a
protocol error.

### 4.2 Conventions for every tool that changes state

- `dry_run: true` validates, prices the change against quota and returns what would happen.
- Success returns `quota_after`.
- Failure returns one of a closed set of codes: `quota_exceeded` (with the dimension),
  `capacity_exhausted` (with the member's idle machines), `not_found`, `conflict`, `forbidden`,
  `invalid`, `pending_approval`.
- Every call is written to the audit log with arguments, and values named like secrets are masked
  before the write.
- `tenant` is optional. It defaults to the member and may name a project the member belongs to.

### 4.3 Member tools

| Family | Tool | Main arguments |
|---|---|---|
| Account | `whoami` | none; returns tenants the member can act for |
| | `quota_get` | `tenant` |
| | `quota_request` | `tenant`, `dimension`, `amount`, `reason`, `until` |
| | `request_list` | own requests and their state |
| Catalog | `images_list` | `kind: vm \| ct`; returns version, end of support date, default flag |
| | `sizes_list` | presets `small`, `medium`, `large` |
| Machines | `machine_create` | `kind`, `name`, `image`, `size` or `cpu` + `memory_mb` + `disk_gb`, `ssh_keys[]`, `packages[]`, `runcmd[]`, `nested_virt`, `swap_mb`, `tags[]` |
| | `machine_get`, `machine_list` | state, private address, SSH line, image support status |
| | `machine_resize` | grow only; disk never shrinks |
| | `machine_power` | `start \| stop \| shutdown \| reboot` |
| | `machine_rebuild` | new `image`; keeps address, ports and domains |
| | `machine_delete` | `confirm: <name>` |
| Rescue | `machine_console_log` | read-only serial output (section 7.6) |
| | `machine_reset_access` | new `ssh_keys[]` through cloud-init, then reboot |
| Keys | `ssh_key_add`, `ssh_key_list`, `ssh_key_remove` | account keys applied to new machines |
| Snapshots | `snapshot_create`, `snapshot_list`, `snapshot_rollback`, `snapshot_delete` | count and size against quota |
| Ingress | `port_open`, `port_close`, `port_list` | `machine`, `port`, `proto: tcp \| udp`; the public port is assigned |
| | `domain_add`, `domain_remove`, `domain_list` | `machine`, `sub`, `target_port` |
| Peering | `peer_allow`, `peer_revoke`, `peer_list` | `machine`, `port`, `from_tenant` or `from_machine` |
| Insight | `machine_metrics` | CPU, memory, disk and network from the hypervisor |
| | `audit_log` | own calls only |
| Skills | `skills_list` | name, description, version, verified date |
| | `skill_get` | `name`; returns the skill body and its version |

`machine_create` returns only after SSH answers, and returns the line to paste into
`~/.ssh/config`. The agent sends the member's public key. The platform never generates or returns
a private key.

### 4.4 Admin tools

Callable only by `winlab-admin`: `quota_set`, `request_approve`, `request_reject`, `tenant_list`,
`tenant_suspend`, `usage_report`, `node_list`, `node_drain`, `reconcile_run`, `image_build`.

### 4.5 Skills

A skill is guidance an agent reads before it acts: which tools to call in which order, which
defaults to pick, and which traps to avoid. The tools say what is possible. Skills say what is
wise for a given intent.

#### 4.5.1 Catalog

Version 1 ships these skills. Each one is named after an intent a member actually has.

| Skill | Intent | What it steers |
|---|---|---|
| `getting-started` | first contact | `whoami`, the use policy, uploading the member's public key, writing `~/.ssh/config` |
| `choose-machine` | "I need a machine for X" | VM or CT, image, size, `nested_virt`; Docker, OVS and Mininet always get a VM |
| `sdn-coursework` | SDN and NFV homework | Ubuntu LTS VM with `nested_virt`, Mininet, Open vSwitch and a controller, and the address ranges to avoid inside the VM |
| `web-service` | publish a web app | a systemd service, `port_open` or `domain_add`, TLS handled by the gateway, never a public database port |
| `continuous-deployment` | deploy on every push from GitHub or GitLab | a self-hosted runner inside the machine, or an SSH deploy through the tenant's port; tokens and deploy keys stay inside the machine |
| `docker-host` | run containers | Docker in a VM, compose files, where volumes live, disk sizing |
| `database` | a PostgreSQL database for an app or a project | PostgreSQL in a VM (stateful work never goes in a CT), listening on the private address only, other machines let in with `peer_allow` and never `port_open` on 5432, SCRAM passwords kept inside the machine, `pg_dump` on a timer plus a snapshot before upgrades, disk sized for data and dumps |
| `k3s-cluster` | a lightweight Kubernetes cluster | one server VM and agent VMs in the tenant's `/24`, `swap_mb: 0` on every node, `kubectl` and `k9s` on the server, the kubeconfig reached through an SSH tunnel instead of a public 6443, ingress through `domain_add` to the bundled Traefik |
| `kubernetes-cluster` | upstream Kubernetes with kubeadm | control plane and worker VMs with at least 2 vCPU and 2 GB each, `swap_mb: 0`, containerd, a CNI with its default pod range, `kubectl` and `k9s`, the same tunnel and ingress rules as `k3s-cluster` |
| `team-project` | a project shared by several members | the project tenant, `peer_allow` between machines, who owns what |
| `rescue` | "I cannot get in" | `machine_console_log`, then `machine_reset_access`, and the host key warning that follows |
| `quota-and-cleanup` | out of room | idle machines, snapshots to drop, then `quota_request` with a reason |

Both cluster skills check `quota_get` first, because a cluster needs several machines at once.
Their pod and service defaults (k3s `10.42/16` and `10.43/16`, kubeadm `10.96.0.0/12`, flannel
`10.244/16`) do not overlap the tenant networks (section 6.1).

Candidates for later, each added only with its own evaluation (4.5.3): `jupyter`, and GPU skills
once GPUs exist.

#### 4.5.2 Source, delivery and versions

- **One source**: `skills/<name>/SKILL.md` in this repository, next to the server code, so a skill
  and the tools it names change in the same pull request.
- **Served by the server**: `skills_list` and `skill_get` return the skills of the running
  release, so every MCP client (Claude Code, Codex, anything else) reads guidance that matches the
  tools it can actually call. The server instructions tell the agent to read the matching skill
  before its first state change.
- **Claude Code copy**: a release workflow opens a pull request against `NYCU-WinLab/plugin` with a
  generated copy, so Claude Code can also trigger skills by description. The copy is never edited
  by hand.
- **Frontmatter**: `name`, `description`, `version` (SemVer), `requires_tools`, and `verified`
  (the date and the carrel version the skill last passed its evaluation against).
- **What a version bump means**: major when the agent's actions change (different tools, a
  different order), minor when guidance is added, patch for wording.
- **CI checks on every pull request**: frontmatter is valid, a changed `SKILL.md` has a higher
  `version`, every name in `requires_tools` exists in the server's tool list, and the description
  stays short enough to trigger reliably.

#### 4.5.3 Evaluation

A skill exists only if it measurably helps. Every skill is evaluated offline before release and
watched in production after it.

**Offline bench** (runs on staging, section 10.5):

1. Each skill has cases in `skills/<name>/evals/<case>.yaml`: the member's sentence, the starting
   state (quota, existing machines), and outcome checks.
2. Checks look at results through the admin API, never at the transcript: the machine exists with
   the right image and flags, SSH works with the member's key, no port is open that the intent did
   not need, no private key or token appears in any tool argument. Stateful skills are checked
   after a reboot as well: a database keeps its rows, and every cluster node is `Ready` again
   (a node left with swap on passes at first and fails here).
3. Every case runs in two arms, with the skill and with that skill hidden from `skills_list`, 5
   runs per arm, with a clean agent that has only the carrel connector. Claude Code and Codex both
   run it.
4. Measured per arm: pass rate, tool calls, error results, cost, wall time, and safety violations.
5. Results are committed as `skills/<name>/evals/results/<version>.json`, so every version has a
   record to compare against.

**Release gate**: a new skill ships only if its pass rate with the skill beats the arm without it
and it has zero safety violations. A changed skill ships only if it does not score below the
previous version. Transcripts are masked before they are stored, because agents write secret
values into tool arguments.

**Production signal**: every `skill_get` is a span. `usage_report` shows, per skill and version,
how often it was read and how the session went after it: whether the machine reached ready, and
how many error results followed. A skill that is read often and still followed by errors is the
next one to fix.

## 5. Resources and quotas

### 5.1 Dimensions

`vcpu`, `memory_mb`, `disk_gb`, `machines`, `ips`, `public_ports`, `domains`, `snapshots`.
Every dimension exists for member tenants and project tenants alike.

### 5.2 Quota versus admission

Quota is a promise. Admission is physics. They are checked separately.

| Layer | Rule (initial values, tuned after the hardware inventory) |
|---|---|
| Quota | The sum of all quotas may exceed capacity, because most tenants are idle most of the time |
| CPU admission | Allocated vCPU of running machines at most 4 times the host threads |
| Memory admission | Memory of running machines at most 90 percent of host memory after the host reserve. Stopped machines do not count |
| Disk admission | Allocated disk at most 1.5 times the pool. Alert at 80 percent real use |
| Addresses, ports, domains | Fixed allocations, never oversubscribed |

When admission fails the tool returns `capacity_exhausted` and lists the tenant's idle machines.

### 5.3 Quota requests

1. A member calls `quota_request` with a reason and an optional end date.
2. Admins are notified on a push channel (open decision 13.3).
3. An admin approves or rejects with a tool call. The result appears in the member's next tool
   response and in `request_list`.
4. A request with `until` becomes a temporary grant and is withdrawn on that date. Machines that
   no longer fit are stopped, never deleted.

### 5.4 Idle machines

A machine with near-zero CPU and network for 14 days is announced to its owner, then stopped 7 days
later. Stopping frees memory admission. Nothing is deleted automatically.

## 6. Network

### 6.1 Address plan

| Resource | Rule | Example, `N = 17` |
|---|---|---|
| Tenant network | `10.200.N.0/24` | `10.200.17.0/24` |
| VNet name | `t` + 3 digits (Proxmox caps VNet ids at 8 characters) | `t017` |
| Gateway | `.1`, anycast on every node | `10.200.17.1` |
| Machine addresses | `.10` to `.250`, static, written by cloud-init | `10.200.17.10` |
| VMID | `10000 + N * 100 + i`, at most 100 machines per tenant | `11700` to `11799` |
| Public ports | `20000 + N * 10`, 10 per tenant | `20170` to `20179` |
| Domains | `<sub>.<slug>.winlab.tw` | `hw1.zyx1121.winlab.tw` |
| Infra | `10.200.0.0/24`, VMIDs `100` to `199` | Caddy gateway machine `10.200.0.2` |
| Templates | VMIDs `9000` to `9099`, 20 per node | `9000` to `9019` on `pve1` |

Why these ranges:

- `10.200.0.0/16` avoids the lab's other networks (`10.10.10.0/24` on the old host, the tailnet
  `100.64.0.0/10`, the lab Wi-Fi `192.168.1.0/24`) and the defaults tenants will run inside their
  machines: k3s `10.42/16` and `10.43/16`, kubeadm services `10.96.0.0/12`, flannel `10.244/16`,
  Docker `172.17/16`.
- Ports `20000` to `29999` are below the Linux ephemeral range (`32768` to `60999`), so they never
  meet the host's own outgoing connections. Admin forwards live elsewhere.
- VMIDs are unique across the whole site, so machines can move between nodes.

### 6.2 Zones

One SDN EVPN zone carries every tenant VNet, even while the site has one node. A simple zone only
exists on one node, and replacing a zone later means recreating every VNet. The node that holds
the public address is the exit node and does the SNAT. FRR is installed by the installer.

### 6.3 Isolation

Every tenant machine gets the security group of its tenant:

1. Accept to its own `/24`.
2. Accept DNS to the infra resolver.
3. Accept the peer rules granted to it (section 4.3), inserted above the drops.
4. Drop the rest of `10.200.0.0/16`.
5. Drop traffic addressed to any node itself. Routing through the anycast gateway still works.

`ipfilter` is on for every tenant NIC, so a tenant cannot take another tenant's address. The
nftables `proxmox-firewall` is used, because VNet level rules need it. Host management ports
(`8006`, `3128`, SSH) listen only on the admin network, never on tenant VNets.

### 6.4 Ingress

- **SSH and opened ports**: DNAT on the exit node from the tenant's public port block to the
  machine. The rules are generated from the database.
- **Domains**: `*.winlab.tw` names point at the exit node. A gateway machine on the infra network
  runs Caddy with on-demand TLS; its `ask` endpoint is carrel, which answers yes only for domains
  in the database. Wildcard certificates do not cover two labels, so every name gets its own.
- **Hairpin**: tenants reaching a public name from inside are sent to the gateway directly.

### 6.5 Reserved names

A slug may not equal any label that already exists under `winlab.tw` (68 records on 2026-09-24,
including personal wildcards such as `*.ben` and `*.stanley`), nor the static list: `carrel`,
`www`, `auth`, `mail`, `admin`, `api`, `mcp`, `status`, `internal`. Registration checks the live
Cloudflare zone, not a copy.

### 6.6 Egress and abuse

One compromised tenant machine can get the lab's public address blocked by the campus. Version 1:

- Outbound TCP 25 is dropped for tenants.
- Per-tenant egress rate limit (value in open decision 13.4).
- Connection-rate alerts for scanning patterns.
- An acceptable use policy in the README, accepted on first `whoami`.

### 6.7 Internal DNS

The infra resolver answers `<machine>.<slug>.internal` for every machine and forwards the rest.
Guests get only this resolver, with no public fallback, so internal names always resolve.

## 7. Machines

### 7.1 Images

Only LTS or stable releases still under vendor security support, at most 3 per distribution, the
newest is the default. Interim releases (Ubuntu 25.04, 25.10) are never offered.

| Distribution | Offered on 2026-09-24 | Not offered |
|---|---|---|
| Ubuntu | 22.04 (standard support ends 2027-04), 24.04, 26.04 | interim releases |
| Debian | 12 (LTS until 2028-06), 13 | 11 (support ended 2026-08-31) |

`images_list` returns the end of support date. `machine_get` warns when a machine runs an image
within 90 days of it.

### 7.2 Templates

- Built by the installer (and `image_build`) from vendor cloud images: Ubuntu cloud images and
  Debian `genericcloud`. CTs use the Proxmox `standard` templates.
- 10 GB disk. `disk_gb` grows the clone; growpart resizes on first boot.
- No SSH keys, no users beyond the cloud-init default, no admin material of any kind.
- One copy per node, because a template on local storage cannot clone to another node.

### 7.3 VM defaults

| Setting | Why |
|---|---|
| Campus apt mirror, `qemu-guest-agent`, 4 GB swap file unless `swap_mb` says otherwise (`0` for Kubernetes nodes), `vm.swappiness=10` | Carried from the old host's cloud-init snippet |
| `fstrim.timer` on, disks `discard=on`, `ssd=1`, `iothread=1`, `virtio-scsi-single` | Space freed in the guest returns to the pool |
| Unattended security upgrades, timezone Asia/Taipei | Tenants forget |
| CPU type `x86-64-v2-AES`; `host` only with `nested_virt` | Machines can migrate between nodes |
| Serial console on | Needed for `machine_console_log` |

### 7.4 CT defaults

- Unprivileged, `nesting=1` (current systemd needs it).
- The Debian 13 journald fix (drop the `ImportCredential=` lines, reset-failed, restart), learned
  on the old host.
- Docker, Mininet and OVS are steered to VMs by the skill and the tool description.

### 7.5 Power state across reboots

A machine comes back in the state its owner left it. Stopping sets `onboot=0`, starting sets
`onboot=1`. Boot order: infra first, then tenants in batches with a delay, so a power cut does not
start everything at once.

### 7.6 Self-rescue

| Tool | Mechanism | Risk and mitigation |
|---|---|---|
| `machine_console_log` | Read-only serial output. The capture mechanism is chosen in M3 (open decision 13.5) | None beyond what the owner can already see |
| `machine_reset_access` | Write new keys into cloud-init, change the instance id, reboot | A stolen Keycloak session could take over a machine. Every reset emails the owner and is audited. Host keys change, and the README says so |

### 7.7 Admins do not enter tenant machines

A hypervisor root can always read a guest disk, so this is a promise backed by hardening, and the
README says exactly that.

- Templates carry no keys.
- `qemu-guest-agent` runs with `guest-exec`, `guest-file-*` and `guest-set-user-password` blocked.
- Every admin action on a tenant machine is audited and visible to the tenant in `audit_log`.

## 8. Hosts and sites

### 8.1 The installer

`install.sh` converges a fresh Proxmox VE host into a carrel node. Running it again is how a node
is repaired or upgraded: it compares and fixes, never assumes a blank slate.

- `install.sh` on the first host creates the site.
- `install.sh --join <existing node>` adds a node. The new node must hold no guests.

### 8.2 Decided on the first host, because they cannot change later

| Item | Decision |
|---|---|
| Node names and management addresses | neutral names `pve1`, `pve2`; fixed addresses |
| Storage | ZFS, same storage id on every node (`local-zfs`), so replication and migration work |
| Tenant network | EVPN zone (section 6.2) |
| VMIDs and templates | site-unique ranges (section 6.1) |
| Data model | site then node from day one (section 2) |

### 8.3 Adding nodes

1. Same room, under 5 ms between nodes. A dedicated corosync link plus a second link for
   redundancy.
2. Same Proxmox VE version on every node.
3. Two nodes need a QDevice outside the cluster. Three or more nodes can enable HA.
4. The exit node is a single point for ingress. A second public address as a VIP removes it.
5. `/etc/pve` is shared by the cluster (firewall, SDN, pools, permissions, storage definitions).
   Interfaces, disks, templates and NAT are per node, and the installer keeps them identical.

### 8.4 Another room

A host that cannot meet 8.3 is a separate site with its own cluster. The platform manages sites
side by side. A tenant's machines stay in one site in version 1.

## 9. Observability

### 9.1 Signals

| Source | Path | Consumer |
|---|---|---|
| Node and guest metrics | Proxmox OpenTelemetry metric server (cluster-wide in `/etc/pve/status.cfg`) to sensorium | admin agents via sensorium MCP |
| carrel control plane | OTel SDK traces and logs, one span per tool call | admin agents |
| Host journald, Caddy, Keycloak | an OTel Collector (journald receiver, Prometheus scrape) to sensorium | admin agents |
| Tenant view | `machine_metrics` reads Proxmox RRD data, `audit_log` reads the database | the tenant only |

sensorium accepts OTLP over HTTP only (JSON or protobuf, no gzip, no gRPC), which is why the
Collector sits in front of anything that speaks another format. Its MCP token reads every project,
so tenants never get it. Machine insides are the tenant's business and are not collected.

### 9.2 Reconciler

A loop compares the database with Proxmox, firewall, NAT, DNS and Caddy every 5 minutes and at
boot. It repairs drift it owns and reports drift it does not understand. `reconcile_run` triggers
it on demand.

### 9.3 Alerts

sensorium only answers queries, so a scheduled job queries it and pushes alerts to a phone.

1. Pool or disk over 80 percent, node memory saturated.
2. Node offline, quorum lost.
3. Reconciler drift it could not repair.
4. Backup failure, certificate renewal failure.
5. sensorium freshness: no new data for 10 minutes. Healthy services with stale data are the
   failure mode seen before.

An external heartbeat covers the case where the whole site is down: carrel pings an outside
service, and silence is the alert.

## 10. Maintenance

### 10.1 Backups

Proxmox Backup Server on a separate machine. Priority: the carrel database and Keycloak client
configuration, then infra machines, then tenant machines (opt-in, counted against quota).

### 10.2 Upgrades

- Several nodes: drain one (`node_drain`), upgrade, reboot, return, next.
- One node: a maintenance window announced through tool responses a week ahead.
- Snapshot infra machines before an upgrade and delete the snapshot after verification; a kept
  snapshot costs pool space.

### 10.3 Tenant lifecycle

A member disabled in Keycloak or moved to `alumni` enters a 30 day grace period (machines keep
running, nothing new), then machines stop, then after another 30 days they are archived or
deleted and the quota and serial are retired. Projects follow their Keycloak group the same way.

### 10.4 Releases

The installer and the control plane are released together with SemVer and Conventional Commits
through Release Please. Container images, if any, are tagged by git SHA.

### 10.5 Staging

A nested Proxmox VE runs inside a VM on the first host. CI installs carrel into it from scratch on
every release candidate and runs the acceptance sentences of section 11.3 against it.

## 11. Version 1

### 11.1 Scope

One site, growing to several nodes. VMs and CTs, member and project tenants, quotas and requests,
SSH, ports, domains, peering, self-rescue, observability and backups.

### 11.2 Not doing in version 1

- GPU passthrough or sharing.
- VPN access into tenant networks (public SSH ports are the path).
- IPv6 (open decision 13.6).
- Machines spanning sites, live migration across sites.
- A web UI.
- A build and deploy pipeline inside carrel. Deployment runs inside the tenant's machine, guided
  by the `continuous-deployment` skill.

### 11.3 Milestones

| Milestone | Done when |
|---|---|
| M0 Staging | CI installs a nested node from scratch and the install is idempotent: a second run changes nothing |
| M1 Host baseline | A bare host after `install.sh` has ZFS, the EVPN zone, the infra network, the firewall, the gateway and all templates, and a tenant address cannot reach host port 8006 |
| M2 Control plane | A clean agent with only the MCP connector, given "Open a VM on winlab for my SDN homework", signs in through Keycloak and ends with a working SSH session |
| M3 Access | The same agent opens a port and a domain, a second tenant cannot reach the machine until `peer_allow`, and `machine_reset_access` recovers a machine whose keys were deleted |
| M4 Quotas | A project tenant runs out of quota, files `quota_request`, an admin approves it, and the retry succeeds; a temporary grant expires on its date |
| M5 Skills | Every skill in 4.5.1 has evaluation cases, passes the release gate of 4.5.3 on staging for both Claude Code and Codex, and `usage_report` shows reads per skill version |
| M6 Operations | Killing the metric pipeline raises the freshness alert, a restore from Proxmox Backup Server brings back a deleted infra machine, and an alumni member's machines stop on schedule |
| M7 Second node | `install.sh --join` adds a node, `node_drain` empties the first one with no tenant noticing, and machines land on both nodes |

## 12. Lessons carried from the old host

| Lesson | Rule here |
|---|---|
| A saved `iptables-save` with Proxmox chains broke every NAT rule at boot, and a helper script silently dropped a SNAT rule twice | Rules are generated from the database and reconciled (section 9.2) |
| Guests on the shared network could reach host 8006 and SSH | Host protection in section 6.3 |
| The VM template carried admin and service keys into every clone | Templates carry no keys (section 7.2) |
| The template disk was 100 GB, the floor for every clone | 10 GB templates (section 7.2) |
| The thin pool was overcommitted with nothing watching it | Disk admission and alerts (sections 5.2, 9.3) |
| sensorium looked healthy while it stored nothing for a day | Freshness alert (section 9.3) |
| A public fallback resolver bypassed internal DNS | No fallback (section 6.7) |

## 13. Open decisions

1. `vm-users` and `vm-sudoers` already exist in Keycloak with no members. Reuse them as the carrel
   access groups, or delete them after finding who made them.
2. Default quota per `lab-member` subgroup and per project. Needs the hardware inventory.
3. The push channel for admin notifications and alerts: a Telegram bot, email, or the portal.
4. Egress rate limit per tenant.
5. How `machine_console_log` captures serial output: a QEMU chardev log file, or a capture of the
   Proxmox terminal proxy.
6. Whether the campus offers IPv6 for the new host. With it, every machine could have a public
   address and port NAT becomes optional.
7. Where the carrel database lives and how it is backed up before Proxmox Backup Server exists.

## 14. Vocabulary

| Term | Meaning |
|---|---|
| admission | the physical capacity check at create or start, separate from quota |
| exit node | the node with the public address; does SNAT and DNAT |
| grant | one allocation against quota: a port, a domain, a peer rule, a snapshot |
| reconciler | the loop that rebuilds derived state from the database |
| serial `N` | a tenant's permanent number; addresses, VMIDs and ports derive from it |
| site | one Proxmox cluster in one room |
| slug | a tenant's DNS-safe name, fixed at registration |
| tenant | a member or a project |
