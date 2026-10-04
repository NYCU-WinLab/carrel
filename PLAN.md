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
- Not a human web UI. The one browser page carrel serves is the machine console (section 7.8).
  OAuth login also has a small consent page that binds a registered MCP client to its callback.
  Onboarding is the README.
- Not a home for services tied to hardware or to a room (Bluetooth, Wi-Fi uplinks, USB devices),
  nor for tailnet infrastructure such as the DERP relay. They live outside carrel (section 10.7).

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
| 2026-09-24 | Everything is built fresh on a new Proxmox host. The existing lab host is reference only (superseded for its guests on 2026-09-27) |
| 2026-09-27 | Selected guests of the old host move to carrel through an admin import tool (section 10.6) |
| 2026-09-27 | Names and ports outside a tenant's own subtree and block are requested by members and approved by admins (section 6.10) |
| 2026-09-27 | Services bound to hardware or a room, and the DERP relay, stay outside carrel |
| 2026-09-27 | Tenants get private networks and machines with several NICs (section 6.8) |
| 2026-09-27 | Tenants may import cloud images and ISOs (section 7.8) |
| 2026-09-27 | carrel ignores the Keycloak groups `vm-users` and `vm-sudoers` |
| 2026-09-27 | Admin notifications and alerts go by email |
| 2026-09-27 | The old host keeps running outside carrel. Selected guests move; the rest stay, with the room-bound services, the DERP relay and the tailnet subnet router (section 10.7) |
| 2026-09-30 | B09 first node is `carrel01` at `192.168.13.159`; future nodes get distinct names instead of reusing the room name as an SSH alias |
| 2026-09-30 | Keep the installed LVM-thin storage on the PERC hardware RAID; do not use the ZFS design or reinstall the host for it |
| 2026-09-30 | B09 has no allocated public ingress. Use the old PVE public address, existing CT 200 TLS gateway, a new CT 207 proxy, and a dedicated WireGuard link to B09; the old PVE stays outside the cluster |

### 1.6 Current core and deferred work

The first release is accepted around three member outcomes: create one VM/CT and SSH into it;
publish an application on an existing machine; create an app/database pair with only the declared
connection allowed. Agents provide machine, connection and publication intent through the existing
`deployment_plan` / `deployment_apply` tools. Physical nodes, bridges and ingress hops are operator
implementation details. Advanced L2 tools remain available for network experiments.

Reliability, tenant isolation, ownership-safe retries, quota accounting and cleanup are core work.
The longer catalog below is a roadmap, not a claim that every tool exists or a requirement to ship
all of it before the core is useful. Custom ISO/image import, legacy workload migration, special
names/ports, a full skill catalog, issue workflow, alumni scheduling and multiple nodes are deferred
until there is a concrete need. This change adds no scheduler, workflow language or separate intent
service. Live tool discovery and the acceptance reports are the authority for implemented features.

## 2. Object model

| Object | What it is | Key |
|---|---|---|
| Site | One Proxmox cluster in one room. Sites never share a corosync ring | `site` slug |
| Node | One Proxmox host in a site | stable node name (`carrel01`, `carrel02`, ...) |
| Tenant | A member or a project. Owns quota, networks, machines, images, ports and domains | serial `N`, slug |
| Machine | A VM or an unprivileged CT owned by one tenant | VMID |
| Network | A private layer 2 segment owned by one tenant (section 6.8) | VNet id |
| Image | A cloud image or ISO a tenant imported (section 7.8) | tenant, name |
| Grant | One allocation: a port, a domain (own or special), a peer rule, a snapshot | id |
| Request | A quota, domain or port request waiting for an admin (section 5.3) | id |
| Zone | A DNS zone carrel manages, and the tenants it is open to (section 6.10) | zone name |
| Source | A Proxmox host that machines are imported from (section 10.6) | host |

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
| `vm-users`, `vm-sudoers` | 0 | origin unknown; carrel ignores them |

The MCP endpoint is an OAuth protected resource. Keycloak is the authorization server. The platform
reads `preferred_username` and the `groups` claim from the token and never trusts a tenant name
sent as a tool argument.

### 3.2 Tenants and serials

Every tenant gets a permanent serial `N` when it is first seen. Members and projects share one
serial space. `N` is never reused, so a stale rule can never point at a new owner.

- `N = 0` is the platform itself (infra network).
- `N = 1` to `254` are tenants. A second site or a larger range is a later change to this section.
- `N = 255` is the fetch network, used only by the image fetcher (section 7.8).

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
- Completed mutations return `quota_after`. Infrastructure changes first return a durable operation;
  `queued` means accepted, not reserved or complete. Poll `operation_get` and follow `next_action`.
- Failure returns one of a closed set of codes: `quota_exceeded` (with the dimension),
  `capacity_exhausted` (with the member's idle machines), `not_found`, `conflict`, `forbidden`,
  `invalid`, `pending_approval`.
- A certificate-budget wait persists `waiting` with `ready_at`, releases the infrastructure writer
  and resumes automatically. A domain is `ready` only after certificate, DNS and route application.
  `operation_retry` resumes failed work against its original allocations. Deployment rollback removes
  only its own new resources; incomplete cleanup stays charged until cleanup succeeds.
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
| Catalog | `images_list` | `kind: vm \| ct`; platform images with version, end of support date and default flag, plus the tenant's own images and ISOs |
| | `sizes_list` | presets `tiny`, `small`, `medium`, `large` |
| Machines | `machine_create` | `kind`, `name`, `image` (platform, `tenant:<name>`) or `iso`, `size` or `cpu` + `memory_mb` + `disk_gb`, `networks[]`, `ssh_keys[]`, `packages[]`, `runcmd[]`, `nested_virt`, `swap_mb`, `firmware`, `tpm`, `tags[]` |
| | `machine_get`, `machine_list` | state, primary address, SSH line, image support status |
| | `machine_resize` | CPU/RAM may shrink while stopped; disk only grows |
| | `machine_power` | `start \| stop \| shutdown \| reboot` |
| | `machine_rebuild` | new `image`; keeps address, ports and domains |
| | `machine_delete` | `confirm: <name>` |
| | `machine_media` | `machine`, `iso` or `none`; insert or eject an ISO |
| | `machine_console_url` | `machine`; a single-use browser console link, bound to the requester's Keycloak login, valid 15 minutes (section 7.8) |
| Deployments | `deployment_plan`, `deployment_apply` | `machines`, `connections`, `publications`; optional experiment `networks`, `attachments` |
| Operations | `operation_get`, `operation_retry` | durable job state, endpoints, failure and next action |
| Networks | `network_create` | `name`, `mode: managed \| raw_l2`, optional `cidr` |
| | `network_list`, `network_delete` | `network_delete` needs `confirm: <name>` and no attached NIC |
| | `machine_nic_attach` | `machine`, `network`, `ip` (optional static address through cloud-init) |
| | `machine_nic_detach` | `machine`, `nic` |
| Images | `image_import` | `name`, `url`, `sha256`, `format: qcow2 \| raw`; a cloud image |
| | `iso_import` | `name`, `url`, `sha256` |
| | `image_delete` | `name` |
| Rescue | `machine_console_log` | read-only serial output (section 7.6) |
| | `machine_reset_access` | new `ssh_keys[]` through cloud-init, then reboot |
| Keys | `ssh_key_add`, `ssh_key_list`, `ssh_key_remove` | account keys applied to new machines |
| Snapshots | `snapshot_create`, `snapshot_list`, `snapshot_rollback`, `snapshot_delete` | count and size against quota |
| Ingress | `port_open`, `port_close`, `port_list` | `machine`, `port`, `proto: tcp \| udp`; the public port is assigned |
| | `domain_add`, `domain_remove`, `domain_list` | `machine`, `sub` or an owned special domain, `target_port` |
| | `domain_request` | `name`, `kind: exact \| wildcard \| delegated \| srv`, `machine`, `target_port`, `reason` (section 6.10) |
| | `port_request` | `machine`, `public_port`, `proto`, `reason` (section 6.10) |
| Peering | `peer_allow`, `peer_revoke`, `peer_list` | `machine`, `port`, `from_tenant` or `from_machine` |
| Insight | `machine_metrics` | CPU, memory, disk and network from the hypervisor |
| | `audit_log` | own calls only |
| Skills | `skills_list` | name, description, version, verified date |
| | `skill_get` | `name`; returns the skill body and its version |
| Issues | `issue_search` | `query`, `state: open \| fixed \| closed \| any`, `skill`; searches before anything is filed |
| | `issue_get` | `id`; the issue, its comments, its state and the release that fixed it |
| | `issue_create` | `title`, `body`, `category`, `machine`, `skill`, `confirm_new`; context is attached by the server (section 4.6) |
| | `issue_comment` | `id`, `body`; more detail or "same here" |
| | `issue_confirm` | `id`, `works: true \| false`; the reporter checks a fix, which closes or reopens the issue |

Member infrastructure mutations return a durable operation and wait up to 55 seconds by default
(`wait_seconds=0` submits immediately). Successful creation or start/resume/reboot requires SSH readiness,
initialization completion and requested guest health checks, and includes the SSH command. The
agent sends the member's public key; Carrel never generates or returns a private key. ISO support
is deferred (section 7.8). Public endpoint results report `routing_configured`; application reachability
from outside still needs a client-side check.

### 4.4 Admin tools

Callable only by `winlab-admin`: `quota_set`, `request_approve`, `request_reject`, `tenant_list`,
`tenant_suspend`, `usage_report`, `node_list`, `node_drain`, `reconcile_run`, `image_build`,
`issue_triage` (label, merge a duplicate), `issue_resolve` (`id`, `fixed_in`, `note`),
`machine_import` and `source_add` (section 10.6), `zone_add` and `zone_list` (section 6.10).

### 4.5 Skills

A skill is guidance an agent reads before it acts: which tools to call in which order, which
defaults to pick, and which traps to avoid. The tools say what is possible. Skills say what is
wise for a given intent.

#### 4.5.1 Catalog

Version 1 ships these skills. Each one is named after an intent a member actually has.

| Skill | Intent | What it steers |
|---|---|---|
| `getting-started` | first contact | sign in, automatic tenant registration, `whoami`, uploading the member's public key, writing `~/.ssh/config` |
| `choose-machine` | "I need a machine for X" | VM or CT, image, size, `nested_virt`; Docker, OVS and Mininet always get a VM |
| `sdn-coursework` | SDN and NFV homework | Ubuntu LTS VM with `nested_virt`, Mininet, Open vSwitch and a controller, and the address ranges to avoid inside the VM |
| `web-service` | publish a web app | a systemd service, `port_open` or `domain_add`, TLS handled by the gateway, never a public database port, names outside the tenant's subtree through `domain_request` |
| `continuous-deployment` | deploy on every push from GitHub or GitLab | a self-hosted runner inside the machine, or an SSH deploy through the tenant's port; tokens and deploy keys stay inside the machine |
| `nextjs` | a Next.js site or app | Node LTS in a VM sized for `next build` (at least 2 GB), `output: "standalone"` run by systemd, `domain_add` to its port with TLS at the gateway, environment in a `0600` file, database and cache reached through `peer_allow`, deploys through `continuous-deployment` |
| `docker-host` | run containers | Docker in a VM, compose files, where volumes live, disk sizing |
| `database` | a PostgreSQL database for an app or a project | PostgreSQL in a VM (stateful work never goes in a CT), listening on the primary address only, other machines let in with `peer_allow` and never `port_open` on 5432, SCRAM passwords kept inside the machine, `pg_dump` on a timer plus a snapshot before upgrades, disk sized for data and dumps |
| `redis` | a cache, queue or session store | Redis in a VM (a cache with persistence off may use a CT), bound to the primary address with an ACL user and password, never `port_open` on 6379, `maxmemory` with an eviction policy, AOF `everysec` when the data matters, `vm.overcommit_memory=1` so background saves do not fail |
| `k3s-cluster` | a lightweight Kubernetes cluster | one server VM and agent VMs in the tenant's `/24`, `swap_mb: 0` on every node, `kubectl` and `k9s` on the server, the kubeconfig reached through an SSH tunnel instead of a public 6443, ingress through `domain_add` to the bundled Traefik |
| `kubernetes-cluster` | upstream Kubernetes with kubeadm | control plane and worker VMs with at least 2 vCPU and 2 GB each, `swap_mb: 0`, containerd, a CNI with its default pod range, `kubectl` and `k9s`, the same tunnel and ingress rules as `k3s-cluster` |
| `network-topology` | "build a network with routers and hosts" | private networks with `network_create`, machines with several NICs, a router VM that does NAT for the topology, MTU 1450, addresses chosen inside the tenant |
| `custom-image` | "I need an OS that is not in the list" | a cloud image first (managed), an ISO only when no cloud image exists, the checksum from the vendor page, `firmware` and `tpm`, the console link, and what an unmanaged machine loses |
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
- **A skill ships with its tools**: a skill lands in the same release as every tool in its
  `requires_tools`, never earlier.

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
3. Composite cases cover the common stack across skills: "a Next.js app with PostgreSQL and
   Redis, deployed on every push" must end with the site answering on its domain, the database
   and cache reachable only from the app machine, and a push that changes the page.
4. Every case runs in two arms, with the skill and with that skill hidden from `skills_list`, 5
   runs per arm, with a clean agent that has only the carrel connector. Claude Code and Codex both
   run it.
5. Measured per arm: pass rate, tool calls, error results, cost, wall time, and safety violations.
6. Results are committed as `skills/<name>/evals/results/<version>.json`, so every version has a
   record to compare against.

**Release gate**: a new skill ships only if its pass rate with the skill beats the arm without it
and it has zero safety violations. A changed skill ships only if it does not score below the
previous version. Transcripts are masked before they are stored, because agents write secret
values into tool arguments.

**Production signal**: every `skill_get` is a span. `usage_report` shows, per skill and version,
how often it was read and how the session went after it: whether the machine reached ready, and
how many error results followed, and how many issues name it (section 4.6). A skill that is read
often and still followed by errors or issues is the next one to fix.

### 4.6 Issues

Agents hit the same problems again and again. Issues let one member's agent learn from another's:
search first, read how it was solved, and file only what is new.

- **Where they live**: GitHub Issues on this repository, written by a GitHub App that only the
  server holds. Members never need a GitHub account; admins fix them in the normal loop, and a
  pull request that says "Fixes #n" moves the issue to `fixed` with the release that carries it.
- **States**: `open`, then `fixed` (an admin or a merged pull request, with `fixed_in`), then
  `closed` when the reporter's agent runs `issue_confirm` with `works: true`, or back to `open`
  with `works: false`. A `fixed` issue with no confirmation closes itself after 14 days.
- **Search before create**: `issue_create` runs `issue_search` on the title first. When similar
  issues exist it returns them with `conflict` and files nothing, unless `confirm_new: true`.
  The server instructions tell agents to search as soon as a tool returns an error they cannot
  explain.
- **Context the server attaches**: tenant slug, machine kind and image, carrel version, skill and
  skill version, and the error codes of the reporter's last 20 calls. Never addresses, keys,
  environment values or anything the audit mask would hide. Bodies pass the same mask.
- **Who sees what**: every member can search and read every issue; only the reporter confirms.
  `issue_create` is limited to 10 per tenant per day.
- **Categories**: `bug`, `question`, `skill` (the guidance was wrong or missing), `capacity`,
  `request`. `skill` issues are labelled with the skill name and feed the production signal of
  4.5.3.

## 5. Resources and quotas

### 5.1 Dimensions

`vcpu`, `memory_mb`, `disk_gb`, `machines`, `ips`, `public_ports`, `domains`, `snapshots`,
`snapshot_gb`, `networks`. Member and project tenants use the same dimensions. `images_gb` is
reserved for deferred image support and hidden from the current API. Each snapshot reserves the
machine disk size against `snapshot_gb`; measured retained bytes are reported separately.
Special domains and ports are not a dimension: each one needs an admin's approval (section 6.10).

### 5.2 Quota versus admission

Quota is a ceiling, not a guarantee of unused physical capacity. Admission is checked separately.

Personal and project defaults are 8 machines, 8 IPs, 8 vCPU, 16384 MiB RAM and 100 GiB disk.
Eight default 1 vCPU / 1024 MiB / 10 GiB machines consume 8 vCPU / 8 GiB / 80 GiB. CPU growth
then requires quota headroom or approval; stopping does not release reservations. Every machine
uses one of the tenant's 10 public ports for SSH, leaving two for extra TCP/UDP publications.
HTTPS domains do not consume this port block. Domains (10), networks (4), snapshots (4) and
snapshot space (100 GiB) retain their existing defaults. More than 10 SSH machines requires
an address/port allocation design change, not merely a larger machine quota.

| Layer | Rule (initial values, tuned after the hardware inventory) |
|---|---|
| Quota | The sum of all quotas may exceed capacity, because most tenants are idle most of the time |
| CPU admission | All allocated Carrel machines, including stopped ones, reserve vCPU; shared vCPU at most 4 times host threads |
| Memory admission | All allocated Carrel machines, including stopped ones, reserve RAM; unmanaged running infrastructure also counts |
| Disk admission | Allocated disk at most 1.5 times the pool. Alert at 80 percent real use |
| Addresses, ports, domains | Fixed allocations, never oversubscribed |

When admission fails the tool returns `capacity_exhausted` and lists the tenant's idle machines.

### 5.3 Requests

Three kinds share one flow: `quota_request` (more of a dimension), `domain_request` and
`port_request` (special names and ports, section 6.10).

1. A member files a request with a reason. A quota request may carry an end date.
2. Admins are notified by email.
3. An admin approves or rejects with a tool call. The result appears in the member's next tool
   response and in `request_list`.
4. A request with `until` becomes a temporary grant and restores its previous limit on that date.
   Existing machines keep running. `over_limit` reports excess; growth in that dimension is blocked,
   while cleanup/reduction remains available. Stopping a tenant requires explicit admin suspension.

### 5.4 Idle machines

Idle shutdown scheduling is deferred. Stopping an allocated machine does not release its CPU/RAM
admission reservation; deletion or a confirmed reduction while stopped does. Nothing is deleted
automatically.

## 6. Network

### 6.1 Address plan

| Resource | Rule | Example, `N = 17` |
|---|---|---|
| Tenant network | `10.200.N.0/24` | `10.200.17.0/24` |
| VNet name | `t` + 3 digits (Proxmox caps VNet ids at 8 characters) | `t017` |
| Gateway | `.1`, anycast on every node | `10.200.17.1` |
| Machine addresses | `.10` to `.250`, static by cloud-init and reserved in carrel's DHCP (section 6.9) | `10.200.17.10` |
| Primary VNet VNI | `100000 + N` | `100017` |
| Private networks | VNet `p` + `N` (3 digits) + `k` (2 digits), VNI `200000 + N * 100 + k`, `k` from 1 to 99 | `p01703`, VNI `201703` |
| VMID | `10000 + N * 100 + i`, at most 100 machines per tenant | `11700` to `11799` |
| Public ports | `20000 + N * 10`, 10 per tenant | `20170` to `20179` |
| Domains | `<sub>.<slug>.winlab.tw` | `hw1.zyx1121.winlab.tw` |
| Infra | `10.200.0.0/24`, VMIDs `100` to `199` | Caddy gateway machine `10.200.0.2` |
| Fetch network | `N = 255`: `10.200.255.0/24`, VNet `t255`, no machines; node `k` uses `.10 + k` | `10.200.255.11` on `carrel01` |
| Templates | VMIDs `9000` to `9099`, 20 per node | `9000` to `9019` on `carrel01` |

Why these ranges:

- `10.200.0.0/16` avoids the lab's other networks (`10.10.10.0/24` on the old host, the tailnet
  `100.64.0.0/10`, the lab Wi-Fi `192.168.1.0/24`) and the defaults tenants will run inside their
  machines: k3s `10.42/16` and `10.43/16`, kubeadm services `10.96.0.0/12`, flannel `10.244/16`,
  Docker `172.17/16`.
- Ports `20000` to `29999` are below the Linux ephemeral range (`32768` to `60999`), so they never
  meet the host's own outgoing connections. Ports outside the blocks are special (section 6.10).
- VMIDs are unique across the whole site, so machines can move between nodes.

### 6.2 Zones

Two SDN zones exist from the first host on, even while the site has one node.

- `tenants`, an EVPN zone, carries every tenant's primary network (`tNNN`). Every node is its
  anycast gateway, and the node that holds the public address is the exit node that does the SNAT.
  A simple zone only exists on one node, and replacing a zone later means recreating every VNet.
- `private`, a VXLAN zone, carries private networks (section 6.8): layer 2 across nodes, with no
  gateway and no routing. The installer keeps its peer list equal to the site's nodes.

FRR is installed by the installer. Both zones encapsulate in VXLAN, which costs 50 bytes, so tenant
networks run at MTU 1450 unless the underlay carries jumbo frames. Every VM NIC is created with
`mtu=1`, which makes the guest inherit the bridge MTU; CT NICs get the MTU set explicitly.

### 6.3 Isolation

Every tenant machine gets the security group of its tenant:

1. Default `network_access=tenant` accepts same-tenant traffic. Explicit `restricted` ingress accepts
   only declared source/protocol/port connections, public grants and platform access. Connections
   in deployment intent require a restricted destination. Restricted machines cannot attach
   unfiltered experiment NICs. Egress policy remains the same.
2. Accept DNS to the infra resolver.
3. Accept the peer rules granted to it (section 4.3), inserted above the drops.
4. Drop every private and internal range: the rest of `10.200.0.0/16`, all of `10.0.0.0/8`,
   `172.16.0.0/12`, `192.168.0.0/16` and `100.64.0.0/10`, and the admin and underlay networks
   wherever they are addressed. Exit nodes forward between the real network and the EVPN network,
   so without this rule a tenant could reach hosts such as Proxmox Backup Server, the QDevice or
   the old host's guests.
5. Drop traffic addressed to any node itself, except DHCP (section 6.9). Routing through the
   anycast gateway still works.

`ipfilter` is on for every primary NIC, so a tenant cannot take another tenant's address. The
nftables `proxmox-firewall` is used, because VNet level rules need it. Host management ports
(`8006`, `3128`, SSH) listen only on the admin network, never on tenant VNets. Private network
NICs are the one exception to filtering (section 6.8).

**Underlay**: VXLAN (UDP 4789) and BGP (TCP 179) are accepted only when all three hold: the packet
arrives on the underlay interface (the second link or its own NIC, section 8.3), it is addressed to this node's own underlay
address, and its source is another node's underlay address. On every other interface, the public
one included, both are dropped, and with a single node they are dropped everywhere. The source
check alone is not enough: UDP sources can be forged, and Proxmox's SDN guidance sets `rp_filter`
to 0 on multi-gateway nodes, so nothing else would stop a forged node address arriving on the
public interface. Proxmox creates VXLAN devices that listen on every address and learn remote
MACs, so without this filter anyone who can reach a node could inject frames into a tenant network
by guessing its VNI. VNIs are not secrets; this filter is the protection.

### 6.4 Ingress

- **SSH and opened ports**: DNAT on the exit node from the tenant's public port block to the
  machine. The rules are generated from the database.
- **Tenant domains**: a tenant's first `domain_add` creates `*.<slug>.winlab.tw` in Cloudflare
  (DNS only) pointing at the exit node, and one wildcard certificate for it. Caddy on the infra
  gateway routes only names that exist in the database; any other name under the wildcard gets 404.
- **Who issues certificates**: the control plane, through the DNS-01 challenge with the Cloudflare
  token it already holds for records, and it pushes the certificates to the gateway. The
  internet-facing gateway never holds a DNS token, because a zone token can
  rewrite every record in the zone, `auth.winlab.tw` included.
- **Certificate budget**: Let's Encrypt allows 50 new certificates per registered domain per 7 days,
  shared with every other `winlab.tw` site, the ones on Vercel included. Only renewals made through
  ARI are exempt (rate limit page, checked 2026-09-27), so carrel renews through ARI. Issuing on
  first use keeps new certificates near the number of tenants that publish something, and carrel
  keeps a rolling 7-day count per registered domain that stops at 30 for `winlab.tw`, leaving the
  rest to the lab's other sites. Past that budget `domain_add` returns `queued` with `ready_at`.
- **Special domains and ports**: section 6.10.
- **Hairpin**: tenants reaching a public name from inside are sent to the gateway directly.

### 6.5 Reserved names

A slug may not equal any label that already exists under `winlab.tw` (68 records on 2026-09-24,
including personal wildcards such as `*.ben` and `*.stanley`), nor the static list: `carrel`,
`www`, `auth`, `mail`, `admin`, `api`, `mcp`, `status`, `internal`. Registration checks the live
Cloudflare zone, not a copy. A special domain that already exists is not refused outright: an admin
may adopt the record (section 6.10). That covers migrated names and stale records such as
`afc.winlab.tw`, which on 2026-09-27 still pointed at the old host with no route behind it.

### 6.6 Egress and abuse

One compromised tenant machine can get the lab's public address blocked by the campus. Version 1:

- Outbound TCP 25 is dropped for tenants.
- Egress limits: a per-tenant cap on the exit node, shaped by the tenant's `/24`, plus a per-NIC
  cap with the Proxmox `rate` option. `rate` limits both directions of one NIC, so it guards the
  node, not the tenant. Values in open decision 13.4.
- Connection-rate alerts for scanning patterns.
- An acceptable use policy in the README, accepted by signing in. Eligible tenants are registered automatically on first use; no separate acknowledgement is required.

### 6.7 Internal DNS

The infra resolver answers `<machine>.<slug>.internal` for every machine and forwards the rest.
Guests get only this resolver, with no public fallback, so internal names always resolve.

### 6.8 Private networks and several NICs

Tenants build their own topologies: isolated layer 2 segments and machines with several NICs, for
routing, SDN and other network experiments.

- **Primary network**: every machine's `net0` sits on the tenant's primary network. It carries the
  SSH line, egress and domains, and it cannot be removed. A machine that must stay off the internet
  brings `net0` down inside the guest.
- **Private networks**: `network_create` makes a segment in the `private` zone owned by one tenant.
  It has no gateway, NAT or host-routable address. Default `managed` mode supplies fixed DHCP
  leases from an isolated, unrouted namespace, without a default route or DNS override.
- **Addresses**: managed segments use an RFC1918 /24 or /25; current images configure assigned
  addresses and MTU 1450. Choose `raw_l2` for guest-controlled addressing, DHCP, bridges, Open
  vSwitch and VLAN experiments. Existing raw segments retain their behavior.
- **Filtering**: private NICs run without the firewall, `ipfilter` or MAC filtering, so bridging
  and address experiments work. The blast radius is the tenant's own segment. Private NICs get
  their own `rate` cap, higher than the primary NIC's, so a loop inside a topology cannot flood the
  node while ordinary traffic between the tenant's machines stays fast.
- **Limits**: `networks` is a quota dimension (4 per tenant to start, at most 99). A machine has at
  most 8 NICs. A network is deleted only when no NIC is attached. Projects own networks like
  members do; a segment shared by several members belongs to a project tenant.
- **Internet for a topology**: the tenant runs its own router VM, with `net0` plus private NICs,
  and does NAT itself. carrel never routes a private network.

### 6.9 DHCP

carrel runs dnsmasq on every node for the primary networks, as DHCP only (`port=0`, no DNS on the
nodes) and with reservations only: each machine's MAC maps to its assigned address, and there is no
dynamic range. Proxmox's built-in SDN DHCP works
only in simple zones, and three kinds of machine need DHCP: ISO installs (section 7.8), imported
guests configured for DHCP (section 10.6), and images without cloud-init. Cloud-init machines keep
their static configuration, which matches the reservation. `ipfilter` still enforces the address,
so a guest that ignores DHCP cannot take another one.

### 6.10 Special domains and ports

Anything outside a tenant's own subtree (`*.<slug>.winlab.tw`) and port block is special. Members
request it; admins approve it.

| Kind | Example | DNS | TLS |
|---|---|---|---|
| exact | `afc.winlab.tw` | A record to the exit node | one certificate, DNS-01 by the control plane |
| wildcard | `*.afc.winlab.tw` | wildcard A record | one wildcard certificate, DNS-01 by the control plane |
| delegated | `*.kitbash.zyx.tw`, names two levels deep | wildcard A record | on demand at the gateway (HTTP-01), asking an `ask_url` on the tenant's machine, under a weekly cap; single-tenant zones only |
| srv | `_minecraft._tcp.mc.winlab.tw` | SRV record to one of the tenant's public ports | none |
| port | public TCP 25565 | none | none |

1. `domain_request` or `port_request` files a request (section 5.3).
2. carrel validates it before an admin sees it:
   - the zone is managed and open to this tenant, and the name is not reserved;
   - a name equal to or under a slug (`bob.winlab.tw`, `x.bob.winlab.tw`) may be requested only by
     that slug's tenant;
   - a wildcard is never `*.<zone>` (its certificate would cover `auth.winlab.tw`), and never
     covers an existing name that belongs to someone else;
   - `delegated` is allowed only in a zone open to this tenant alone;
   - the port is not on the never list.
3. An admin approves with `request_approve`. A name that already exists in the zone needs
   `adopt: true`, which replaces the old record.
4. The approved name or port becomes a grant of the tenant. `domain_add` can later point it at
   another of the tenant's machines without a new approval. Deleting the machine leaves the grant
   unattached for 30 days, then it is released.

**Zones**: admins add DNS zones with `zone_add`: the Cloudflare token, kept as a server secret, and
the tenants the zone is open to. `winlab.tw` is open to every tenant; a personal zone such as
`zyx.tw` can be open to one tenant only. Records are DNS only by default. An admin may turn on the
Cloudflare proxy for an HTTP special domain one label under its zone; Cloudflare's free certificate
covers only one label, so a proxied `x.afc.winlab.tw` would fail.

**Ports that are never granted**: 22, 25, 53, 80, 443, 111, 3128, 8006, the tenant blocks (`20000`
to `29999`), and any port the nodes themselves use. A protocol that supports SRV records gets an
`srv` domain on its normal tenant port instead of a scarce well-known port.

**Certificate budget**: `delegated` names mint certificates on demand, so each such grant carries a
weekly cap. They exist only in single-tenant zones, so they never spend the `winlab.tw` budget of
section 6.4.

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
| Debian 13 minimal, 1 vCPU / 1024 MiB RAM / 10 GiB disk (`tiny`); 1024 MiB swap unless `swap_mb` says otherwise (`0` for Kubernetes nodes), `vm.swappiness=10` | Small service default with explicit growth |
| `fstrim.timer` on, disks `discard=on`, `ssd=1`, `iothread=1`, `virtio-scsi-single` | Space freed in the guest returns to the pool |
| Unattended security upgrades, timezone Asia/Taipei | Tenants forget |
| CPU type `x86-64-v2-AES`; `host` only with `nested_virt` | Machines can migrate between nodes |
| Serial console on | Needed for `machine_console_log` |

The prepared `debian-13-minimal` image contains cloud-init, SSH, sudo, Python for management,
QEMU guest agent, security updates, curl, rsync and growpart. It excludes Node, Docker and
compilers. The existing `debian-13` and `ubuntu-24.04` VM images retain their prepared development
environment and default to `small` (2 vCPU / 2048 MiB / 20 GiB). `medium` and `large` remain
4/8192/40 and 8/16384/80. Explicit size/resource fields override defaults without changing the
image. Catalog image metadata declares environment, default_size and default_swap_mb. New CTs
use their existing minimal distribution images with `tiny` and zero swap.

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
- Imported guests (section 10.6) are the exception until their owner hardens them: they arrive with
  the old host's guest agent settings and with whatever keys the old template baked in. carrel
  reports both at import and puts them on the owner's checklist.
- Machines from custom images (section 7.8) keep whatever guest agent settings the tenant's image
  has. carrel reads `guest-info` on first boot and shows in `machine_get` whether `guest-exec` and
  the file commands are enabled.

### 7.8 Custom images and ISOs

Tenants may bring their own operating system. Quota and metrics work unchanged, because carrel
counts vCPU, memory and disk from the machine's Proxmox configuration and reads metrics from the
hypervisor; nothing depends on software inside the guest. What depends on the guest is management:
key injection, the SSH check and graceful shutdown.

| Kind | How it arrives | Managed? | What the member gets |
|---|---|---|---|
| Cloud image (`qcow2`, `raw`) | `image_import` with `url` and `sha256`, through carrel's fetcher | yes when the image carries cloud-init: keys, addresses and the SSH check work as usual | `machine_create` with `image: "tenant:<name>"` |
| ISO | `iso_import` with `url` and `sha256`, through carrel's fetcher | no | an empty disk with the ISO attached, a browser console for the installer, and the reserved address by DHCP |

- **Fetcher**: imports are downloaded by carrel, not by Proxmox's `download-url`, which runs from
  the node's own network (Proxmox guards it with the `Sys.AccessNetwork` privilege for that
  reason). The fetcher runs on every node as a dedicated unprivileged user with no capabilities,
  inside its own network namespace whose only interface sits on the fetch network (`N = 255`,
  section 6.1). Without capabilities it can neither change that namespace's rules nor enter the
  host's namespace. It resolves the name once and pins that address; refuses private, loopback,
  link-local, `100.64.0.0/10` and the site's own addresses; follows at most 3 redirects and checks
  each one the same way; streams into its own staging directory with a hard stop at the smaller of
  20 GB and the tenant's remaining `images_gb`; and verifies the checksum.
- **Rules on the host side**: the fetch network's rules sit on the host end of the fetcher's
  interface, out of the fetcher's reach: the drops of section 6.3, outbound TCP 80 and 443 only,
  DNS to the infra resolver only, no traffic between fetchers on different nodes, and a bandwidth
  cap (section 6.6). The host end is named `veth...`, because a Proxmox SDN reload keeps only
  bridge ports named `tap`, `veth` or `fwpr`; the reconciler checks that it stays attached.
- **Limits**: one import per tenant and one per member, 3 per site at a time, so a member of
  several projects cannot take every slot; more return `queued` (section 4.2). A download that
  stays under 2 MB/s for 60 seconds, or runs longer than 3 hours, is aborted, so a slow server
  cannot hold a slot; at 2 MB/s a 20 GB file still finishes inside 3 hours.
- **Storage**: a root step on the node, not the fetcher, checks each accepted file against the
  checksum in the database and moves it, read-only, from staging into `carrel-images`. That storage
  is a dedicated, size-limited logical volume with its own ext4 filesystem, separate from the root
  filesystem, so a server that lies about size cannot fill the root filesystem. It is configured
  with `is_mountpoint`, so Proxmox refuses writes when the volume is not mounted. Physical thin-pool
  space still needs admission and monitoring (5.2, 9.3); a volume size limit alone does not reserve
  pool capacity. A full image volume makes new imports on that node return `capacity_exhausted`.
  When a machine lands on a node that lacks its image, carrel copies it from a node that has it, over
  the nodes' own SSH trust, the way templates keep one copy per node (section 7.2); copies do not
  count again against `images_gb`. The checksum is checked again before every copy and every
  `import-from`, so a swapped file is caught.
- **Migration**: Proxmox refuses to migrate a VM whose CD-ROM sits on storage it believes is local.
  `carrel-images` is therefore marked `shared`, and carrel keeps that promise itself: before any
  migration, `node_drain` included, it copies every attached ISO to the target node and checks the
  checksum.
- **Hand-off to Proxmox**: `qemu-img info` runs as the unprivileged fetcher user, under CPU and
  memory limits, on every cloud image, and the image is refused if its format differs from the
  `format` argument or it names a backing file or a qcow2 data file. A backing file that points at
  another tenant's disk would otherwise copy that disk into the attacker's machine. Files go into
  `carrel-images` as `import` content (ISOs as `iso` content), never as `images`, because Proxmox
  applies its own untrusted-image checks only to `import` volumes, so those checks still hold if a
  compromised fetcher lies about an image. Nothing goes through the upload API, which spools to
  `/var/tmp` on the root file system first. A machine created from the image counts its virtual
  size against `disk_gb`.
- **Unmanaged machines**: `machine_create` returns in state `installing`, without an SSH line.
  The member installs through `machine_console_url` and ejects the ISO with `machine_media`, which
  marks the machine ready. The SSH check is only a hint for these machines, because systems such as
  Windows may never run SSH. `machine_reset_access` is not available, snapshots are
  crash-consistent (no guest agent to freeze the file system), and shutdown uses ACPI.
- **Firmware**: `firmware: bios | uefi` and `tpm: true` for systems that need them, such as
  Windows 11. The virtio driver ISO can be attached as a second drive. Licences are the tenant's
  responsibility.
- **Browser console**: `machine_console_url` returns a single-use link, valid for 15 minutes.
  Opening it requires a Keycloak browser login as the member who asked for it, so a forwarded link
  is useless to anyone else. This page is the one exception to 1.4. Every link is emailed to the
  machine's owner (for a project, its members) and audited, like `machine_reset_access`, because a
  console is as strong as a key reset. The proxy sits in front of the Proxmox VNC console and is
  the one new component custom ISOs need.
- **Quota**: image and ISO files count against `images_gb`, at most 20 GB per file. A checksum is
  mandatory, and imports stay private to the tenant.
- **CTs** keep to the platform images in version 1.

## 8. Hosts and sites

### 8.1 The installer

`install.sh` converges a fresh Proxmox VE host into a carrel node. Running it again is how a node
is repaired or upgraded: it compares and fixes, never assumes a blank slate.

- `install.sh` on the first host creates the site.
- `install.sh --join <existing node>` adds a node. The new node must hold no guests.

### 8.2 Decided on the first host, because they cannot change later

| Item | Decision |
|---|---|
| Node names and management addresses | stable names `carrel01`, `carrel02`; fixed management addresses; site `b09` identifies the room |
| Storage | LVM-thin on the existing hardware RAID, with storage id `local-lvm` on every B09 node. Migrations copy local disks. No ZFS replication; recovery uses independent backups |
| Tenant networks | EVPN zone for primary networks, VXLAN zone for private networks (section 6.2) |
| VMIDs and templates | site-unique ranges (section 6.1) |
| Data model | site then node from day one (section 2) |

### 8.3 Adding nodes

1. Same room, under 5 ms between nodes. A dedicated corosync link plus a second link for
   redundancy. VXLAN and BGP between nodes use the second link or a NIC of their own, never the
   dedicated corosync link, because tenants control that traffic (section 6.3).
2. Same Proxmox VE version on every node.
3. Two nodes need a QDevice outside the cluster. Three or more nodes can provide quorum for
   HA, but local LVM-thin alone cannot restart a failed node's guests elsewhere: their disks are
   still on that failed node. Planned migrations copy disks while the source is healthy; host
   failure recovery uses independent backups until shared storage is supplied and tested.
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

A loop compares the database with Proxmox, firewall, NAT, DHCP, DNS and Caddy every 5 minutes and
at boot. It repairs drift it owns and reports drift it does not understand. `reconcile_run` triggers
it on demand.

### 9.3 Alerts

sensorium only answers queries, so a scheduled job queries it and sends alerts by email.

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
every release candidate and runs the acceptance sentences of section 11.3 against it, with two
differences from production: staging has its own DNS zone (open decision 13.11) and uses the
Let's Encrypt staging CA, so a run never issues real certificates or touches `winlab.tw` records.
M9 (import) is production only and is checked once, by hand, against its sentence.

### 10.6 Importing machines

`machine_import` (admin only) brings an existing guest into carrel under a tenant.

- **Sources**: a Proxmox host registered with `source_add` (an API token on that host), moved with
  Proxmox's `qm remote-migrate` or `pct remote-migrate`, which leaves the source stopped as a
  rollback; or a vzdump archive, restored. Proxmox marks remote migration experimental, so staging
  proves it on test guests before M9, and the archive path is the fallback.
- **Plan first**: `dry_run` returns the target VMID and address, disk sizes, the quota it takes,
  every configuration change, and warnings. The call with `confirm` runs it.
- **Normalization**: the NIC moves to the tenant's primary network with `firewall=1`, `mtu=1`, the
  tenant's security group, `ipfilter` and the `rate` limit. The new address goes into cloud-init
  (`ipconfig0` and the resolver) for VMs, into `net0` for CTs, and into the DHCP reservation for
  guests that use DHCP. Keys that are not the owner's leave the cloud-init configuration, and an
  old `cicustom` snippet is replaced by carrel's own vendor data. The CPU type becomes
  `x86-64-v2-AES` unless the owner asks for `nested_virt`.
- **Verification**: carrel boots the guest and checks the new address through the guest agent's
  read-only network report and the SSH port. It also reads `guest-info` to learn whether
  `guest-exec` and the file commands are still enabled. A guest that fails is marked
  `needs_owner_fix` with the reason; no admin logs in to fix it (section 7.7).
- **Grants in the same call**: the admin can attach the guest's existing names and ports as
  approved special domains and ports (section 6.10), with `adopt: true` for names already in the
  zone.
- **What the owner checks**: `machine_get` lists what carrel cannot fix from outside: keys the old
  template left in `authorized_keys`, a guest agent that still allows `guest-exec`, SSH host keys
  that change once (a new `ipconfig0` changes the cloud-init instance id), applications bound to
  old addresses, and resolvers that cloud-init does not rewrite (Alpine).

### 10.7 Living next to the old host

The old lab host (`140.113.194.229`, 7 VMs and 7 CTs on 2026-09-27) keeps running outside carrel.
Selected guests move to carrel. Everything else stays, including the room-bound services (display
bridge, HomeKit door, Wi-Fi uplink), the DERP relay and the tailnet subnet router. Which guests
move, and to which owner, is decided guest by guest (open decision 13.10); the table is the
starting proposal.

| Guests | Owner if moved | Notes |
|---|---|---|
| sandbox 104, kilo 116, vivado 100, agent-noir 105, sensorium-zyx 205 | tenant `zyx1121` | vivado has a 250 GB disk |
| minecraft 103, kitbash 115 | tenant `zyx1121` | 25565 as a special port or `mc.winlab.tw` as an `srv` domain; `*.kitbash.zyx.tw` as a `delegated` domain in the `zyx.tw` zone |
| video 114, agent-oai 201, agent-portal 203, dst 204, hams-bridge 206 | a lab services project tenant | `video`, `hams` and `door` names adopted as special domains |
| sensorium-winlab 202 | infra (`N = 0`) | carrel's own telemetry goes there (section 9.1) |
| gateway 200, template 9000 | stay | the old gateway keeps serving the names of the guests that stay |

**Two gateways, one zone**: the old gateway keeps serving the names of the guests that stay, and
carrel serves the names in its database. Each Cloudflare record points at whichever host serves
it. carrel changes only records it owns; a name moves from the old gateway to carrel only through
adoption (section 6.10). Both gateways draw on the same `winlab.tw` certificate budget
(section 6.4).

**Moving one guest**:

1. Lower the Cloudflare TTL of its records a day ahead.
2. Run `machine_import` with the guest's names and ports attached (section 10.6).
3. Switch each record and check from outside the campus (check-host or `curl --resolve`), never
   only from inside.
4. Keep the source stopped on the old host for 14 days as a rollback.

**Checks before a guest with outside dependencies moves**:

- hams-bridge reaches the door controller (`140.113.194.254`) inside the same `/27` today. It moves
  only after the controller is shown to accept connections from the new site's address.
- `door.winlab.tw` passes through the lab router's port forward to the door relay, which accepts
  only `140.113.194.229`. If its route moves to carrel's gateway, that rule changes first.
- Guests that talk to each other across the two hosts (minecraft 103 sends telemetry to dst 204
  today) either move together or switch to public names.

## 11. Version 1

### 11.1 Scope

One site, growing to several nodes. VMs and CTs, member and project tenants, quotas and requests,
SSH, ports, domains, special domains and ports, peering, private networks and several NICs,
custom images and ISOs, self-rescue, observability, backups, and importing selected guests of the
old host.

### 11.2 Not doing in version 1

- GPU passthrough or sharing.
- VPN access into tenant networks (public SSH ports are the path).
- IPv6 (open decision 13.6).
- Machines spanning sites, live migration across sites.
- A web UI, apart from the machine console page (section 7.8).
- A build and deploy pipeline inside carrel. Deployment runs inside the tenant's machine, guided
  by the `continuous-deployment` skill.

### 11.3 Milestones

| Milestone | Done when |
|---|---|
| M0 Staging | CI installs a nested node from scratch and the install is idempotent: a second run changes nothing |
| M1 Host baseline | A bare host after `install.sh` has the configured LVM-thin storage, both SDN zones, the infra network, the firewall, DHCP reservations, the gateway and all templates; a tenant address cannot reach host port 8006, a guest set to DHCP receives exactly its reserved address, and a VXLAN or BGP packet is dropped when it comes from an address that is not a node or carries a forged node address on the public interface |
| M2 Control plane | A clean agent with only the MCP connector, given "Open a VM on winlab for my SDN homework", signs in through Keycloak and ends with a working SSH session |
| M3 Access | The same agent opens a port and a domain under the tenant's wildcard certificate, a second tenant cannot reach the machine until `peer_allow`, and `machine_reset_access` recovers a machine whose keys were deleted |
| M4 Quotas and requests | A project tenant runs out of quota, files `quota_request`, an admin approves it, and the retry succeeds; a temporary grant expires on its date; the project requests a name that already exists, such as `afc.winlab.tw` (its twin in the staging zone on staging), an admin approves it with `adopt: true`, and the site answers over HTTPS on that name |
| M5 Private networks | Two host VMs on two private networks reach each other only through a router VM, a machine of another tenant on the same node captures no frame from those networks, a frame sent from outside with a guessed VNI never arrives, and 1450 byte packets pass end to end |
| M6 Custom images | A tenant imports a cloud image by URL and checksum and gets a managed machine with an SSH line; another installs Debian from an ISO through `machine_console_url`, gets its reserved address by DHCP, and both files show in `quota_get`; an import URL that points at an internal address such as `10.0.0.0/8` is refused, and so is a qcow2 image with a backing file; a second import by the same tenant waits in `queued` until the first ends |
| M7 Skills | Every skill in 4.5.1 has evaluation cases, passes the release gate of 4.5.3 on staging for both Claude Code and Codex, `usage_report` shows reads per skill version, and an agent that hits a known problem finds its issue with `issue_search` instead of filing a duplicate |
| M8 Operations | Killing the metric pipeline raises the freshness alert, a restore from Proxmox Backup Server brings back a deleted infra machine, and an alumni member's machines stop on schedule |
| M9 Import (production only) | Every guest chosen under section 10.7 runs on the new site under its owner, its names answer from outside the campus, every check of 10.7 that applies to it passes, and its source stays stopped on the old host for 14 days |
| M10 Second node | `install.sh --join` adds a node, `node_drain` empties the first one with no tenant noticing (a machine with an ISO attached included), and machines land on both nodes; with real peers now, a VXLAN or BGP packet carrying a forged node address on the public interface and a frame with a guessed VNI never arrive (the cases of M1 and M5); a machine created on the new node from an image fetched on the first gets a verified copy |

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
| The old gateway's internal DNS kept 5 stale records of 11, and a Cloudflare record outlived its machine | DNS is derived from the database; an old record moves to carrel only by adoption (sections 6.7, 6.10) |

## 13. Open decisions

1. Resolved 2026-09-27: carrel ignores `vm-users` and `vm-sudoers`.
2. Default quota per `lab-member` subgroup and per project. Needs the hardware inventory.
3. Resolved 2026-09-27: admin notifications and alerts go by email.
4. Initial B09 limit: 100 Mbit/s aggregate IPv4 tenant egress, plus 12.5 MB/s primary NIC limits. Private experiment NICs have a 100 MB/s limit. Revisit after real usage.
5. How `machine_console_log` captures serial output: a QEMU chardev log file, or a capture of the
   Proxmox terminal proxy.
6. Whether the campus offers IPv6 for the new host. With it, every machine could have a public
   address and port NAT becomes optional.
7. Resolved for B09: SQLite/WAL in CT 100. Daily consistent database/config/certificate backups go to the independent old PVE, with 14 daily archives. Full guest backups still need PBS.
8. Resolved 2026-09-30 for B09: admin SSH uses ProxyJump through the B09 jump host. This is
   separate from member-facing ingress (13.13).
9. Resolved 2026-09-27: the old host stays outside carrel and does not join the site.
10. Which of the old host's guests move, and their owners (section 10.7). Decided guest by guest.
11. Which DNS zone staging uses (section 10.5). It must not be `winlab.tw`, and its token must not
    reach any production zone.
12. The old gateway (CT 200 on the old host) still holds a Cloudflare token for the whole
    `winlab.tw` zone, the exposure section 6.4 keeps off carrel's gateway, and it stays while both
    gateways run. Keep it, scope it down, or move DNS changes for the old host's names into carrel's
    control plane.
13. Resolved 2026-09-30: public TLS and explicit tenant port grants on `140.113.194.229`,
    through CT 207 and WireGuard. The management ProxyJump account is not member ingress.
    Real OAuth, public SSH and tenant HTTPS were verified; see 15.4.
14. B09 additional-node links: only `nic1` (1 Gbit/s) is connected on the first node. Dedicated
    corosync and underlay links, a QDevice for two nodes, and backup storage must be supplied before
    expansion.

## 14. Vocabulary

| Term | Meaning |
|---|---|
| admission | the physical capacity check at create or start, separate from quota |
| exit node | the node with the public address; does SNAT and DNAT |
| fetch network | the reserved network `N = 255`, used only by the image fetcher's namespace on each node |
| grant | one allocation: a port, a domain (own or special), a peer rule, a snapshot |
| managed machine | a machine carrel can configure and check from outside: cloud-init keys and addresses, the SSH check |
| primary network | the tenant's routed `/24`, where every machine's `net0` sits |
| private network | a layer 2 segment of one tenant, with no gateway and no filtering (section 6.8) |
| reconciler | the loop that rebuilds derived state from the database |
| serial `N` | a tenant's permanent number; addresses, VMIDs and ports derive from it |
| site | one Proxmox cluster in one room |
| slug | a tenant's DNS-safe name, fixed at registration |
| source | a Proxmox host that machines are imported from |
| special domain, special port | a name or public port outside the tenant's own subtree or block, granted by an admin (section 6.10) |
| tenant | a member or a project |
| unmanaged machine | a machine installed from an ISO: quota and metrics work, key injection and the SSH check do not |

## 15. B09 rollout record

### 15.1 Inventory (2026-09-30)

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

### 15.2 Private bootstrap scope

Admin-only nested staging is running as VM `190`, `carrel-stg01`, with 8 vCPU, 24 GiB RAM,
a 32 GiB boot disk and a 160 GiB data disk (150 GiB usable thin pool). Its
management subnet is `172.31.255.0/24` on an isolated host bridge, separate from the tenant
address plan. Access uses the administrator's SSH key and ProxyJump. Staging receives no
production DNS, Keycloak client secrets or Cloudflare credentials.

This was the initial private stage. The member-facing implementation now follows in 15.4.
The old lab host remains outside the B09 cluster and provides the external ingress.

### 15.3 Verified bootstrap and remaining work

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


### 15.4 Member platform deployment

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

The initial quota was a conservative shared default: 8 vCPU, 16 GiB RAM, 100 GiB allocated disk,
4 machines/IPs (raised to 8 in section 15.14), 10 public ports/domains, 4 private networks and 4 snapshots. Project/subgroup-specific
policy remains open decision 2. Snapshots reserve a full disk size before adapter work; rollback refuses changed NIC or
resource configuration. Interrupted disk growth keeps the larger quota reservation and can be
retried with the same `machine_resize` arguments. Temporary quota expiry stops over-limit machines and prevents restarting
until allocations fit. Mutations currently serialize through one process-wide lock; long image or
certificate work therefore delays other mutations.

`sites/b09/platform-verification.json` records acceptance facts and limitations. Tests use temporary
users/guests, never existing members' machines. Their permanent tenant serials are retired after
cleanup. This release implements the MCP/identity/network core of M1–M5. It does not claim full
milestone acceptance: M0 clean nested CI install, M2 real agent-driven acceptance, M3 console/key
recovery, M4 special domains/ports, M5 multi-node cases, M6 images/ISOs, M7 skills, M8 PBS/telemetry/
notifications/alumni lifecycle, M9 import and M10 cluster expansion remain. TLS renewal exists in
code; a real expiry/renewal cycle still needs acceptance. The database backup restore check does
not substitute for a full disaster-recovery exercise. No email was sent during this deployment.

### 15.5 MCP planning and Codex acceptance (2026-10-01)

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
[the evaluation and evidence](docs/evaluations/2026-10-01-codex-mcp.md) for per-case results and
separate disposable-VM lifecycle acceptance. This does not establish multi-node or full M2
acceptance; unsupported features remain tracked in the product plan.

The subsequent disposable Ubuntu VM check also found and fixed rollback reporting: disk-only
snapshot rollback may stop a guest, and now returns/persists its actual power state with an
explicit start action. See the evaluation for public SSH/HTTPS, rollback and cleanup evidence.


### 15.6 Intent and reliability acceptance (0.4, 2026-10-01)

The member path is machine, connection and publication intent on `deployment_plan` / `deployment_apply`.
Explicit restricted ingress enforces exact source/protocol/port rules and prevents unfiltered NIC bypass.
The same deployment can publish an existing application. The five reliability fixes in sections 4.2,
5.3 and 1.6 are deployed: DNS failure isolation, quota expiry without blanket stopping, durable
certificate waits, independent tenant onboarding and immediate suspension admission blocking.

114 local tests pass; live OAuth/MCP acceptance passed with three restricted VMs and a separate tenant
CT, public SSH/HTTPS/TCP HTTP, designated database access, negative source/port/protocol checks,
publication reuse and complete cleanup. Member tools remain 40; admin tools remain 9. The public
service reports 0.4.0 and final installed hashes match. See the
[intent acceptance report](docs/evaluations/2026-10-01-intent.md) and the preceding
[0.3 reliability report](docs/evaluations/2026-10-01-reliability.md) for evidence and limits.


### 15.7 Direct creation and prepared development VMs (0.5, 2026-10-02)

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

Live [0.5 acceptance](docs/evaluations/2026-10-02-fast-create.md) measured two Debian creations at
about 42 seconds and an Ubuntu creation at 46 seconds, each returning verified readiness from one
tool call. The prior Debian server operation took 97.71 seconds, including 39.205 seconds of base
package installation. Adapter timing attributes the remaining time primarily to PVE operations
and guest readiness. Optimize these paths before considering a language rewrite. The current
serialized writer can add queueing under concurrent demand; no concurrency SLA is established.

### 15.8 PVE observations and gateway updates (0.5.1, 2026-10-02)

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
[PVE operations acceptance](docs/evaluations/2026-10-02-pve-operations.md).

Startup probes measure Python at about 14 ms and the PVE module/environment at about one second.
Direct HTTP API access may remove the remaining module startup regardless of language, but no
Rust/HTTP comparison was run. Warm pools and a language rewrite are not part of this release.

A subsequent [read-path experiment](docs/evaluations/2026-10-02-pve-language-benchmark.md)
compares Python and Rust across 12 interleaved fresh-process trials and five reused-client blocks.
Direct HTTPS inventory/topology medians are 409/80 ms in Python and 347/16.4 ms in Rust. Reusing
the client yields 335/11.22 ms and 338/10.98 ms. Rust saves about 63 ms in the per-request process
design; direct API access provides most of the improvement over either language spawning `pvesh`.
The experiment also catches PVE API volume filtering under audit-only credentials. Any production
HTTP reader must preserve all-volume visibility. No production transport change is part of this experiment.


### 15.9 Go control plane (0.6, 2026-10-02)

The Go service owns Streamable HTTP MCP, Keycloak OAuth/PKCE, SQLite state, intent planning,
admission, a durable FIFO mutation queue, readiness and backups. Existing SQLite tables and
OAuth bindings remain compatible; migration does not require member login. Python remains for
the bounded root mutation adapters, guest reporter, deployment tooling and certbot. The former
Python control plane is a test reference, not the service launched by systemd.

Admission and shared PVE/network mutations use one writer. A persisted `prepared_result` releases
that writer during SSH/guest-report readiness. Other allocations can begin, while edits to the
same allocation wait. Deployment groups start all new guests before waiting. Report arrival wakes
readiness immediately; a periodic SSH probe remains. Cancellation does not cancel accepted work.
Recovery resumes the checkpoint, and adapter receipts retain Python-compatible request hashes.
This does not introduce multi-node scheduling or independent parallel network writers.

Display capacity observations have a two-second cache and coalesce simultaneous reads. Every
admission reads fresh inventory and current SQLite reservations. Network-only plans skip compute
inventory. Physical snapshot accounting runs in maintenance and snapshot operations, outside the
ordinary network/create path. SSH transports reuse authenticated connections for up to 120 seconds.

The fixed `carrel-pve-read` Go helper uses PVE HTTPS with the host CA and hostname verification,
bounded parallel reads and no arbitrary paths, writes or stale fallback. Its only modes are
`inventory` and `topology`. Full volume visibility is mandatory: PVEAuditor alone returns filtered
storage content. The root-only `/etc/carrel/pve-read.json` credential has a privilege-separated
`root@pam!carrel-go-reader` token, PVEAuditor at `/` and a custom role containing Datastore.Audit
and Datastore.Allocate at `/storage/local-lvm`. This credential has a storage management privilege,
even though the helper issues only GET requests. It never reaches CT 100, guests or clients.
`scripts/configure-go-reader.py` provisions it, preserves it on repeat runs, and verifies removal
before unlinking its configuration. Permissions are rechecked on each inventory query.

Build static binaries in the development sandbox. `scripts/deploy-go.py --artifacts <directory>`
checks no active jobs and compares all-volume identities with the old reader before enabling
`go_pve_reader` in `/etc/carrel/node.json`. It saves a consistent database/config/certificate/service
archive under CT 100's `/opt/carrel/rollback/` and node files in the printed node stage directory.
Existing OAuth, certificates, guest templates and the certbot environment are preserved. The
backup timer runs `carrel -backup`, retaining the existing private archive destination and format.
A failed initial health check restores service/node files without overwriting newly written data.

For a manual rollback, stop the control service, restore the saved service units and previous binary
(if any), restore the saved node adapter and `node.json`, reload systemd and restart. The legacy
Python environment remains available. Restore an older database only as an explicit disaster-recovery
operation after reconciling all resource changes since that backup. If the Go reader is retired,
disable its flag before removing its owned token/ACL/role with `configure-go-reader.py --remove`.

Go race tests, 79 Python behavior fixtures and the existing Python reference tests validate the rewrite.
The [Go evaluation](docs/evaluations/2026-10-02-go-control-plane.md) records live read-path measurements
and rollout acceptance. This release adds no warm pool or SSH provisioning gateway.

Live 0.6 acceptance: the public service reports 0.6.0, installed hashes match and existing
MCP authentication survives both migration and restart. One default VM takes 29.008 seconds
(previous 0.5.1 sample 34.696); two immediate submissions finish in 38.917 seconds together.
Private VM/CT networking, restricted ingress, external HTTPS, snapshot file restoration,
checkpoint restart without duplicate creation and real backup integrity all pass. All seven
disposable guests are removed, original volumes/quotas restored and `ssh dev01` remains valid.
These small samples do not establish an SLA. See the evaluation for client serialization,
resource sizes, operation IDs, precise timings and retained Python helpers.


### 15.10 Common member actions (0.7, 2026-10-02)

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
- The current Go contract is maintained directly. The Python exporter writes a separate reference
  contract, preserving the frozen Python behavior baseline. No new scheduler, cache or warm pool
  is introduced by this release.

Validation: Go race tests/vet and static builds, 177 Python tests, Ruff and script compilation run
on sandbox VM104. Live acceptance passed on disposable VM/CT guests, including paused restart/shutdown,
owner SSH, snapshot rollback, external HTTPS/TCP and complete cleanup. See
`docs/evaluations/2026-10-02-common-actions.md` and its JSON evidence.

### 15.11 Bootstrap and discovery follow-up (0.7.2, 2026-10-02)

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

### 15.12 Member scope audit (v0.7.2 baseline, 2026-10-02)

The [scope audit](docs/evaluations/2026-10-02-scope-audit.md) maps all 40 member tools to user
outcomes and records seven reproduced behavior problems plus an existing-machine isolation gap.
These findings describe the v0.7.2 baseline; section 15.13 records their implementation. First address stale readiness, offline NIC
configuration and premature application-health rollback. Then make summaries, deletion receipts
and recovery guidance usable without extra discovery; align quota request validation and
idempotency with approval. Existing-machine isolation changes and guest-visible resize completion
need explicit acceptance cases. The audit adds no runtime feature or deployment requirement.


### 15.13 Consistent outcomes across scopes (0.8, 2026-10-02)

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
reconciles. Experiment NICs, including attachments in the same plan, prevent restricted ingress.
SSH, publications and old peer grants remain. Rollback restores a prior policy only if the operation
still owns it on the same allocation. Results include affected existing machines.

Resize separates allocated block capacity from unverified guest filesystem growth, with owner SSH
follow-up and no implicit reboot or guest execution API. HTTPS preparation persists reserved domains
before DNS/ACME work outside the writer; issuers serialize separately for certbot's shared directories.
Finalization checks allocation/domain identities and tenant status again. Renewal also runs outside
the writer. Same-machine mutations stay ordered, unrelated jobs proceed during propagation.

See [scope fixes](docs/evaluations/2026-10-02-scope-fixes.md) for acceptance. Saved-key changes still
only affect future guests; control backups exclude tenant disks. Live acceptance passed on three
disposable guests with all temporary resources removed. Paused NIC removal now rejects before
PVE can write a pending unplug; resume or shutdown is an explicit prerequisite. Full disaster recovery, custom images,
multi-node scheduling and console/key recovery remain deferred. Member tool count remains 40.

### 15.14 Minimal defaults and eight-machine quota (0.9, 2026-10-04)

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
