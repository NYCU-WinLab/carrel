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
| 2026-09-30 | B09 first node is `carrel01` at `192.168.13.159`; future nodes get distinct names instead of reusing the room name as an SSH alias (superseded 2026-10-19) |
| 2026-09-30 | Keep the installed LVM-thin storage on the PERC hardware RAID; do not use the ZFS design or reinstall the host for it (superseded 2026-10-19) |
| 2026-09-30 | B09 has no allocated public ingress. Use the old PVE public address, existing CT 200 TLS gateway, a new CT 207 proxy, and a dedicated WireGuard link to B09; the old PVE stays outside the cluster (superseded 2026-10-19) |
| 2026-10-12 | Apps deploy on push: GitHub Actions builds, a GitHub OIDC token authorizes the upload, and an agent the member installs in the machine switches releases (section 7.9) |
| 2026-10-19 | B09 becomes the four-node cluster `carrel` (`carrel01` to `carrel04`, `192.168.19.101` to `.104`). The R640 node retires after its guests move. carrel supports several nodes before the move (section 15.15) |
| 2026-10-19 | B09 storage is ZFS `local-zfs` on a stripe of two disks per node, with no disk redundancy. Recovery uses independent backups |
| 2026-10-19 | Public ingress uses `140.113.60.184/27` on VLAN 60 at the exit node. CT 207 and the WireGuard hop through the old PVE retire for carrel |
| 2026-10-19 | No QDevice: every place it could run fails together with B09 |
| 2026-10-20 | `network_access=restricted` filters the primary NIC only. Restricted machines may have private NICs, which stay unfiltered on the tenant's own segments (issue #75) |
| 2026-10-22 | carrel can push machines, networks and addresses to NetBox, off by default and best effort. One shared VRF for tenant segments, one VRF per private network, all owned by carrel; the `owner` is set at creation (section 9.4, issue #141) |

### 1.6 Current core and deferred work

The first release is accepted around three member outcomes: create one VM/CT and SSH into it;
publish an application on an existing machine; create an app/database pair with only the declared
connection allowed. Agents provide machine, connection and publication intent through the existing
`deployment_plan` / `deployment_apply` tools. Physical nodes, bridges and ingress hops are operator
implementation details. Advanced L2 tools remain available for network experiments.

Reliability, tenant isolation, ownership-safe retries, quota accounting and cleanup are core work.
The longer catalog below is a roadmap, not a claim that every tool exists or a requirement to ship
all of it before the core is useful. Custom ISO/image import, legacy workload migration, special
names/ports, a full skill catalog, issue workflow and alumni scheduling are deferred until there is
a concrete need. Multiple nodes became core work on 2026-10-19 (section 15.15). This change adds no scheduler, workflow language or separate intent
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
| App | A repository branch bound to one machine, deployed on every push (section 7.9) | tenant, name |
| Release | One built artifact of an app, with its commit SHA and state | app, id |
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

Streamable HTTP at `https://carrel.winlab.tw/mcp`, OAuth through Keycloak. Every result is a tool
result with `ok`; a failure sets `isError` and carries `error.code`, never a protocol error. Tools
declare no output schema: one identical envelope on every tool cost 24 KB of each tool listing.

OAuth endpoints are limited per client address (the address the gateway saw): 60 requests per
minute and 20 client registrations per hour. A registration expires after a day unless it reaches
a token exchange, which extends it to 90 days, so unused registrations cannot fill the cap of
10,000 clients.

### 4.2 Conventions for every tool that changes state

- `dry_run: true` validates, prices the change against quota and returns what would happen.
  `deployment_apply` has none: `deployment_plan` is its read-only preview.
- Completed mutations return `quota_after`. Infrastructure changes first return a durable operation;
  `queued` means accepted, not reserved or complete. Poll `operation_get` and follow `next_action`.
- Failure returns one of a closed set of codes: `quota_exceeded` (with the dimension),
  `capacity_exhausted` (with the member's idle machines), `not_found`, `conflict`, `forbidden`,
  `invalid`, `pending_approval`.
- A certificate-budget wait persists `waiting` with `ready_at`, releases the infrastructure writer
  and resumes automatically. A domain is `ready` only after certificate, DNS and route application.
  `operation_retry` resumes failed work against its original allocations. Deployment rollback removes
  only its own new resources; incomplete cleanup stays charged until cleanup succeeds.
- Finished operations stay 30 days for `operation_get`, `operation_retry` and idempotent
  resubmission, then the maintenance loop deletes them; the audit log keeps the history.
  `cleanup_failed` operations stay until their retry releases what they hold.
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
| Catalog | `catalog_get` | platform images with version, end of support date and default flag, the size presets `tiny`, `small`, `medium`, `large`, and the installed environments |
| Machines | `machine_create` | `kind`, `name`, `image` (platform, `tenant:<name>`) or `iso`, `size` or `cpu` + `memory_mb` + `disk_gb`, `networks[]`, `ssh_keys[]`, `packages[]`, `runcmd[]`, `nested_virt`, `swap_mb`, `firmware`, `tpm`, `tags[]` |
| | `machine_get`, `machine_list` | state, primary address, SSH line, image support status |
| | `machine_resize` | CPU/RAM may shrink while stopped; disk only grows |
| | `machine_power` | `start \| stop \| shutdown \| reboot` |
| | `machine_rebuild` | new `image`; keeps address, ports and domains |
| | `machine_delete` | `confirm: <name>` |
| | `machine_media` | `machine`, `iso` or `none`; insert or eject an ISO |
| | `machine_console_url` | `machine`; a single-use browser console link, bound to the requester's Keycloak login, valid 15 minutes (section 7.8) |
| Deployments | `deployment_plan`, `deployment_apply` | `machines`, `connections`, `publications`; optional experiment `networks`, `attachments`. The plan is the read-only preview; apply has no dry run |
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
| | `domain_add`, `domain_remove`, `domain_list` | `machine`, `sub` or `name` under a special domain grant, `target_port` |
| | `domain_request` | `name`, `kind: exact \| wildcard \| delegated \| srv`, `reason` (section 6.10) |
| | `port_request` | `machine`, `public_port`, `proto`, `reason` (section 6.10) |
| Apps | `app_link` | `machine`, `name`, `repo`, `branch`, `start`, `port`; returns the install line and the workflow snippet (section 7.9) |
| | `app_get`, `app_list` | linked repository, agent state, current and previous release, last result |
| | `app_deploy` | `app`, `release`; deploys a stored release again |
| | `app_rollback` | `app`; switches back to the previous release |
| | `app_unlink` | `confirm: <name>`; deletes stored releases and revokes the agent token, leaves the machine as it is |
| Peering | `peer_allow`, `peer_revoke`, `peer_list` | `machine`, `port`, `from_tenant` or `from_machine` |
| Virtual addresses | `vip_add`, `vip_list`, `vip_remove` | `name`, `machines` (section 6.3) |
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
`tenant_suspend`, `usage_report`, `node_list`, `node_drain`, `node_undrain`, `machine_migrate`, `reconcile_run`, `image_build`,
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
| `continuous-deployment` | deploy on every push from GitHub or GitLab | GitHub: `app_link`, the install line over SSH, the workflow with `carrel-deploy`, runtime secrets in the app's `env` file (section 7.9); GitLab: a self-hosted runner inside the machine, or an SSH deploy through the tenant's port, with tokens and deploy keys inside the machine |
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
snapshot space (100 GiB) retain their existing defaults. A machine created with
`public_ssh: false` takes no public port and is reached through the platform SSH jump host
(CT 102, issue #98), so the machine quota, not the port block, bounds how many a tenant runs.

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
| Machine addresses | `.10` to `.250`, static by cloud-init (no DHCP, section 6.9) | `10.200.17.10` |
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
   in deployment intent require a restricted destination. The mode filters the primary NIC
   only: private experiment NICs stay unfiltered and reach only the tenant's own machines on that
   segment (issue #75, 2026-10-20). Egress policy remains the same.
2. Accept DNS to the infra resolver.
3. Accept the peer rules granted to it (section 4.3), inserted above the drops.
4. Drop every private and internal range: the rest of `10.200.0.0/16`, all of `10.0.0.0/8`,
   `172.16.0.0/12`, `192.168.0.0/16` and `100.64.0.0/10`, and the admin and underlay networks
   wherever they are addressed. Exit nodes forward between the real network and the EVPN network,
   so without this rule a tenant could reach hosts such as Proxmox Backup Server, the QDevice or
   the old host's guests.
5. Drop traffic addressed to any node itself. Routing through the
   anycast gateway still works. Public entry points listed in `node.json` `public_entries` are
   accepted above this drop: TCP 443 on the public address (`140.113.60.184`), the HTTPS gateway
   the internet already reaches, so tenants can use carrel and lab sites by their public names
   (the hairpin in section 6.4), TCP 443 on each protected host the site file lists in its own
   `public_entries` (the lab host's gateway `140.113.194.229`, which serves door, display and other
   lab sites), and the tenants' public port blocks (TCP and UDP 20010 to 22549,
   issue #28): what the internet reaches, tenants reach too. The first exit node gives a tenant
   reaching another tenant's public port the public address as its source, so the answer comes
   back through it. The node itself and CT 100 and 101 reach the public address as well (issue
   #48). Every other port on that address stays dropped.

**Virtual addresses** (issue #96): a highly available service inside a tenant (Kubernetes
control planes, a database pair) needs one address that moves between machines. `vip_add` keeps
`.251` to `.254` of the tenant network for that, 4 per tenant, outside every machine address. The
address joins the `ipfilter` set of each listed machine and nothing else changes: keepalived or
kube-vip in the guests decides which machine holds it and announces the move with gratuitous ARP,
and EVPN carries the new MAC to the other nodes. A remote EVPN neighbour entry is `NOARP`, so the
kernel ignores the new holder's ARP until the old node withdraws its route, and the old node's
entry stays `STALE` while nothing uses it: a move between nodes then never finished (measured on
B09, 2026-10-21). Every node therefore runs `carrel-vip-probe`, which probes its own entries of
registered virtual addresses each second; an address that left fails within about 4 seconds, FRR
withdraws it, and the holder's next gratuitous ARP is learned. Guests repeat gratuitous ARP for at
least 5 seconds after taking the address, as keepalived and kube-vip do by default. VRRP multicast is dropped with the rest of
`224.0.0.0/4`, so keepalived runs with unicast peers. Inbound rules have no destination, so a
holder accepts at the virtual address what it accepts at its own. Deleting a machine drops it from
the holders and keeps the address. carrel neither balances load nor checks health; a load balancer
object stays a later option.

A public port or domain can target a virtual address instead of a machine (issue #146):
`port_open` and `domain_add` take `vip` in place of `machine`. The exit node DNATs, or the gateway
forwards, to the address, and every holder admits the port, so the public entry follows the
address. A virtual address without holders cannot be published, and `vip_remove` refuses while a
port or domain targets it. In NetBox such a service belongs to the address's FHRP group.
A deployment publication takes `vip` the same way (issue #151); the deployment records the
address's identity, so a retry after the address was replaced is refused.

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
  gateway routes only names that exist in the database; any other name under the wildcard gets 404,
  unless the tenant registered the catch-all `sub: "*"` (issue #95). The catch-all forwards every
  name that has no domain of its own to one machine and port, counts as one domain, and uses the
  same wildcard certificate, so an ingress controller in the tenant can route by Host. Names with
  two labels stay outside: they would need another certificate per tenant.
- **Who issues certificates**: the control plane, through the DNS-01 challenge with the Cloudflare
  token it already holds for records. It renders the gateway's Caddyfile and hosts file, checks
  each pair (name, expiry, key) and sends them over SSH to a forced command in CT 101
  (`gateway-sync.py`, CT 100's key from `10.200.0.3` only), so private keys never pass through a
  node (since 2026-10-20; node-agent relayed them with `pct exec` before). It runs the
  ACME client in-process (`golang.org/x/crypto/acme`, since 2026-10-20; certbot before): it writes
  the challenge TXT record, polls the resolver until it serves the value, and keeps each issued pair
  in its own directory behind a `live/<name>` symlink that one rename replaces. It renews when a
  third of the lifetime is left. The
  internet-facing gateway never holds a DNS token, because a zone token can
  rewrite every record in the zone, `auth.winlab.tw` included.
- **Certificate budget**: Let's Encrypt allows 50 new certificates per registered domain per 7 days,
  shared with every other `winlab.tw` site, the ones on Vercel included. A renewal with the same
  names is exempt from that limit, with or without ARI (rate limit page, checked 2026-10-20), so
  carrel does not use ARI. Issuing on
  first use keeps new certificates near the number of tenants that publish something, and carrel
  keeps a rolling 7-day count per registered domain that stops at 30 for `winlab.tw`, leaving the
  rest to the lab's other sites. Past that budget `domain_add` returns `queued` with `ready_at`.
- **Special domains and ports**: section 6.10.
- **Hairpin**: tenants reaching a public name from inside are sent to the gateway directly; a
  tenant's public port works from inside too (section 6.3).

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

Primary networks have no DHCP server (removed 2026-10-20: dnsmasq ran on every node and answered
nobody). Every machine gets a static address: cloud-init network configuration for VMs, `pct`
`ip=` for CTs. `ipfilter` enforces the address. Managed private networks (section 6.8) keep their
DHCP, one server in its own namespace on the first exit node.

The machines that would need DHCP on a primary network are ISO installs (section 7.8), imported
guests configured for DHCP (section 10.6) and images without cloud-init. When one of those ships,
it brings back a reservations-only server (each MAC to its address, no dynamic range); Proxmox's
built-in SDN DHCP works only in simple zones.

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

**Built so far** (exact and wildcard names in `winlab.tw`): `domain_request` takes `name`, `kind`
and `reason` and stores a request of kind `domain`; `request_approve` checks the rules again and,
with `adopt`, may replace existing A, AAAA or CNAME records at the name. An approval stores a
`domain_grants` row. `domain_add` with `name` instead of `sub` publishes the granted name, or for
a wildcard its catch-all `*.<base>` or one label under it, as a domain row that carries the
grant's id; quota counts it like any domain. Each grant has its own certificate lineage
`_grant-<id>` (DNS-01, the same 7-day budget as tenant wildcards) and its own site block at the
gateway. Its A record, comment `carrel:b09:grant:<id>`, is written or moved only once the gateway
holds that certificate, so an adopted name keeps answering where it did until carrel serves it;
a lone foreign A record changes in place. Removing a grant's last domain keeps the grant and its
record; the maintenance pass releases a grant unused for 30 days (record, gateway site,
certificate, grant; the request reads `released`). An adopted name is not restored on release:
the old records were replaced on purpose, and only the log keeps them. Labels of grants are
reserved against new tenant slugs; a pending request reserves nothing, and a tenant has at most
3 pending domain requests. `domain_add` prefers an exact grant of the name over a wildcard that
covers it.

Special ports and SRV records are built too. `port_request` takes `public_port`, `proto` and
`reason`; an approval stores a `port_grants` row, and `port_open` with `public_port` forwards that
port instead of one from the tenant's block (the grant row carries `special`, and the exit node
accepts such a port only outside the never-granted list below). A port grant that forwards nothing
is released after 30 days. `domain_request` with `kind: srv` asks for `_service._tcp.<name>` or
`_service._udp.<name>`; `domain_add` under that grant needs an open public port to the target with
the grant's protocol and writes an SRV record that names `carrel.winlab.tw` and that public port.
The maintenance pass follows the port and removes the record once no port forwards there; SRV
grants have no certificate and no gateway site.

Delegated names are built too. `domain_request` with `kind: delegated` asks for `*.<base>` in a
zone open to the tenant alone; `domain_add` publishes its catch-all. The grant's wildcard A record
is written at once, and the gateway serves `*.<base>` and `*.*.<base>` with `tls { on_demand }`;
the global `on_demand_tls` asks `http://10.200.0.3:8080/gateway/ask`, a path the public origin does
not forward, answered only to the gateway's address. carrel agrees to a name once its route is
ready, the tenant is active, the grant has issued fewer than 20 new names in 7 days, and the
route's target answers `GET /.well-known/carrel/ask?domain=<name>` with 200 (the control plane
reaches it: the guest firewall admits `10.200.0.3` to a delegated route's port). A name agreed to
once is answered from its record, so renewals spend no budget.

The Cloudflare proxy switch is built too: admin `domain_proxy` with `name` and `proxied` turns it on
or off for an exact grant one label under its zone (the record gets Cloudflare's automatic TTL).
The DNS tokens cannot read a zone's SSL mode, so after turning it on carrel resolves the name
through 1.1.1.1 until Cloudflare answers for it and asks `https://<name>/` there; a 52x, no answer,
or the gateway's redirect back to the same URL (Flexible mode) turns the proxy off again. With all
of this, section 6.10 is built.

**Zones**: admins add DNS zones with `zone_add`: the Cloudflare token, kept as a server secret, and
the tenants the zone is open to. Built: `zone_add` checks that the token sees exactly that zone
and can write (a TXT probe it removes at once), keeps the token in `zone_dir/<zone>.token` (0600,
never in the database, a result or the audit log) and the zone in the site table; calling it again
replaces the token and tenant list. `zone_list` shows the site's zone and the added ones;
`zone_remove` refuses while a name in the zone is granted or requested. A name belongs to the
longest managed zone it sits in, and its ACME challenge and grant record go to that zone. Outside
`winlab.tw` the slug and platform-label rules do not apply; the zone's own wildcard is never
granted, and its apex only outside `winlab.tw`. A zone may not overlap `winlab.tw` or another
added zone. `winlab.tw` is open to every tenant; a personal zone such as
`zyx.tw` can be open to one tenant only. Records are DNS only by default. An admin may turn on the
Cloudflare proxy for an HTTP special domain one label under its zone; Cloudflare's free certificate
covers only one label, so a proxied `x.afc.winlab.tw` would fail.

**Ports that are never granted**: 22, 25, 53, 80, 443, 111, 3128, 8006, the tenant blocks (`20000`
to `22549`: 10 ports for each of 254 tenants), the client VPN ports (`31000` to `31254`), and any
port the nodes themselves use. A protocol that supports SRV records gets an
`srv` domain on its normal tenant port instead of a scarce well-known port.

**Certificate budget**: `delegated` names mint certificates on demand, so each such grant carries a
weekly cap. They exist only in single-tenant zones, so they never spend the `winlab.tw` budget of
section 6.4.

### 6.11 Network model in AWS terms (issue #103, design only)

carrel names its network objects after their AWS counterparts where one exists, and each tool
description says what differs. Members and agents already know the AWS model, so a request such
as "connect my machines to the lab network and route between my projects" needs no carrel
vocabulary. carrel stays a lab platform on one cluster: no accounts, IAM, regions or zones.

| AWS | carrel | Differs from AWS |
|---|---|---|
| VPC | a tenant's primary network, `10.200.N.0/24`, one EVPN VNet | one fixed CIDR per tenant, no secondary CIDRs |
| Subnet | the primary network; `network_create` segments (6.8) | private segments are layer 2 only: no gateway, no routes |
| Security group | `network_access` plus declared `connections` (6.3) | rules belong to the machine, not to a named group |
| VPC peering | `peer_allow` | one port per grant, TCP or UDP, one direction |
| Internet gateway and NAT gateway | the exit node: SNAT to the site address | shared by every tenant |
| Elastic IP | public IP per machine (#91) | admin approval, from a site pool |
| Load balancer | `domain_add` (HTTPS), `vip_add` (6.3) | no health checks, no L4 balancing |
| Route table | none today | see below |
| Transit gateway | planned | see below |
| Site-to-site VPN, customer gateway | planned | WireGuard first |
| Direct Connect | planned | a VLAN on a spare node port, admin provisioned |
| Client VPN | planned | WireGuard, one endpoint per tenant |

**Routing domains.** All tenants share one VRF (`vrf_tenants`, table 1001), and isolation comes
from the guest firewall, not from routes (6.3). Every tenant prefix is unique inside
`10.200.0.0/16`, so a shared table can carry them all. A VRF per tenant would mean one EVPN zone
per tenant; Proxmox binds a VNet to its zone, so every tenant VNet would be recreated and every
machine NIC moved. carrel keeps the shared VRF and models route tables as reachability: a route
table lists which attachments may reach which, and carrel compiles that into firewall rules on the
exit node and the guests, the way `peer_allow` already works. A real VRF becomes necessary only
when a tenant must use addresses that overlap another tenant's, which carrel does not offer. If it
ever does, the migration is one tenant at a time: create the tenant's zone and VNet, attach a
second NIC on the new VNet to each machine, move the address, detach the old NIC. Each machine
loses its connections once, for seconds.

**Attachments.** A transit gateway is a tenant-owned object with attachments and one route table
per attachment. Attachment kinds: a tenant network (the tenant's own, or another tenant's with
that tenant's acceptance, like `peer_allow`), a client VPN, a site-to-site VPN, a dedicated link.
A route table entry says "this attachment may reach that prefix through that attachment"; carrel
refuses an entry whose prefix overlaps a tenant network it does not belong to. Traffic from every
attachment still passes the destination machine's guest firewall: a VPN client is one more source
the machine must accept, never a way around `restricted`.

**Client VPN** (first attachment to build, issue #103). WireGuard on the first exit node, one
interface per tenant (`wg-tNNN`) in `vrf_tenants`, listening on UDP `31000 + N` of the public
address (below the ephemeral range), with client addresses from `10.201.N.0/24`. The member or
agent generates the key pair and sends only the public key (`vpn_client_add`), so carrel never
holds a client private key; the server keys stay on the exit node. A client reaches only its
tenant's `/24`: `inet carrel_vpn` on the exit node passes `10.201.N.0/24 <-> 10.200.N.0/24` and drops
every other packet of a `wg-t*` interface, the node itself included, and tenant machines with
`network_access` `tenant` accept `10.201.N.0/24` as they accept their own network. Other nodes
reach the clients through the VRF default route to the exit node; `wg-t*` joins conntrack zone 1
like the other VRF ports.

Agents use it on their own. The skill tells an agent to try the SSH jump host first (`ssh -L` for
one or two TCP ports) and to open a client only for UDP, many ports or a browser on internal
services. The agent runs `wg genkey`, calls `vpn_client_add` with the public key and a name for the
session, writes the private key into the returned `config`, and brings it up: `wg-quick` when it may
use root, or a userspace client such as wireproxy (WireGuard as a local SOCKS5 proxy) when it may
not, which needs no prompt at all. A client expires after `hours` (default 8, at most 168), so a
session an agent forgot ends by itself; adding the same name again renews it. A tenant keeps at
most 8 clients. The lab's
NetBird mesh uses `100.64.0.0/10`, which tenants drop as the tailnet range (6.3); it can be added
later as a routing peer per tenant, mapped to the same attachment.

**Site-to-site VPN.** A customer gateway (remote public address, public key, the remote prefixes)
and a connection to a tenant network or a transit gateway, WireGuard with static routes first,
BGP over it later with FRR. Remote prefixes that overlap `10.200.0.0/16` or another attachment
are refused; a lab network that does overlap needs 1:1 NAT (`netmap`) on the connection, which
the connection object declares.

**Dedicated links.** An admin connects a lab or campus network to a spare node port (the X540 and
X710 ports are unused, 15.15) as a tagged VLAN with a BGP session, then offers it to tenants as an
attachment. Members request it and admins approve it, like special domains (6.10). Cabling and
which node holds it are open (13.14).

**Order.** 1. This section. 2. Client VPN for one tenant, with a test that a client cannot reach
another tenant. 3. Site-to-site VPN to a tenant network. 4. Transit gateway between tenant
networks and VPNs. 5. Dedicated links. Steps 2 to 4 add quota dimensions (`vpn_clients`,
`vpn_connections`, `transit_gateways`) and audit entries; every new endpoint lives on the exit
node, so they follow the exit node failover of #89.

**Open for decision**: whether VPN endpoints may live on a tenant gateway machine instead of the
exit node (more isolation, one more machine per tenant); whether project tenants may attach other
projects without an admin; whether the lab's NetBird gets a routing peer at all.

### 6.12 Public IP per machine (issue #91, design only)

The Elastic IP of 6.11. A member requests a dedicated public IPv4 address for one machine; once
approved, the machine is reachable on any port of that address and its outbound traffic leaves
from it. Other machines keep the shared address.

**1:1 NAT, as in AWS.** An AWS instance never holds its Elastic IP: the instance keeps its private
address and the internet gateway translates one to the other. carrel does the same on the exit
node: DNAT of inbound traffic for the bound address to the machine's primary address, and SNAT of
the machine's outbound traffic to the bound address. The guest needs no change, the shared VRF
stays (6.11), and no anti-spoofing rules are needed. Routing the public address into the guest
(a second NIC or an extra address on `net0`) is not offered.

**Address pool.** The pool is site configuration (`config.json`), not a constant in the code: a
list of addresses or prefixes the lab network team has assigned to carrel. A site with no pool
offers no public IPs. The control plane takes a free address from the pool, never one of the
exit node's own addresses or the shared address.

**Objects and tools.** A binding belongs to one machine and one tenant. `public_ip_request`
(machine, reason) creates a request like `quota_request`; an administrator answers it with
`request_approve` or `request_reject`. `public_ip_release` and machine deletion return the address.
A new quota dimension `public_ips` (default 0) counts what a tenant holds. `machine_get` shows the
bound address; `catalog_get` shows whether the site has a pool and how many addresses are free. A
rejected or pending request changes nothing on the network. A binding survives restarts, resizes
and snapshots.

**Filtering.** Traffic to a bound address still passes the guest firewall. It follows the
machine's `network_access` plus an explicit list of allowed ports or "all", chosen by the member;
the default is SSH only. Egress limits and abuse handling of 6.6 apply to the bound address too.

**Exit node.** The NAT rules live on the exit node, so each bound address follows the exit node
failover of #89: the address moves with the active node.

**Order.** Independent of the attachments in 6.11: it needs neither a route table nor a
VRF, so it can be built beside the client VPN once a pool is configured.

**Left open**: who approves and for how long (`until`, automatic removal of expired bindings), and
whether carrel creates a DNS name for a bound address.

## 7. Machines

### 7.1 Images

Only LTS or stable releases still under vendor security support, at most 3 per distribution, the
newest is the default. Interim releases (Ubuntu 25.04, 25.10) are never offered.

| Distribution | Offered on 2026-09-24 | Not offered |
|---|---|---|
| Ubuntu | 22.04 (standard support ends 2027-04), 24.04, 26.04 | interim releases |
| Debian | 12 (LTS until 2028-06), 13 | 11 (support ended 2026-08-31) |

`catalog_get` returns the end of support date. `machine_get` warns when a machine runs an image
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
- `carrel-deployd` (section 7.9) runs whatever release carrel hands it, so installing it is the
  owner's choice, made over the owner's own SSH. It cannot change the start command, and removing
  it ends the delivery.
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
| ISO | `iso_import` with `url` and `sha256`, through carrel's fetcher | no | an empty disk with the ISO attached, a browser console for the installer, and the machine's reserved address to enter in the installer |

- **Where files live** (issue #92, decided 2026-10-21): the site file's `content_storage` names one
  storage for each file kind: `vztmpl` (the platform CT templates), `iso` and `import`. Each
  defaults to `local`. B09 uses `rs822rp1`, an NFS export of the lab NAS that every node mounts
  and Proxmox marks `shared`, so each file exists once per site. Tenant imports are offered only
  where the `iso` and `import` storages are shared, or the site has one node; carrel never copies
  an image between nodes. VM base templates stay per node on the guest storage (7.2), and
  cloud-init files stay on each node's `local` storage (7.10).
- **Fetcher**: imports are downloaded by carrel, not by Proxmox's `download-url`, which runs from
  the node's own network (Proxmox guards it with the `Sys.AccessNetwork` privilege for that
  reason). `carrel-fetch` (Go) runs in CT 103, an unprivileged container on the first exit node,
  as the user `carrel-fetch`, one transient unit per job with a memory cap. The container sits on
  the fetch network (`t255`, `10.200.255.10`, section 6.1), which tenants drop like any other
  tenant's network, and it has no view of the shared storage: NFS is mounted only on the hosts.
  `carrel-fetch` resolves the name once and dials the address it checked; refuses private,
  loopback, link-local, `100.64.0.0/10`, documentation and the site's own addresses; allows only
  `http` and `https` on ports 80 and 443, no credentials in the URL; follows at most 3 redirects
  and checks each one the same way; stops at the smaller of 20 GB and the tenant's remaining
  `images_gb`; and verifies the checksum. Its staging space is the container's 64 GB disk, so a
  server that lies about size cannot fill a node. (Decided 2026-10-21 instead of a network
  namespace per node: with the files on shared storage one fetch point is enough, and an
  unprivileged container gives the same isolation with no plumbing of its own.)
- **Rules on the host side**: the container's Proxmox firewall, written by node-agent, drops
  everything inbound and, outbound, allows only DNS to the infra resolver and TCP 80 and 443 to
  addresses outside the private ranges and the site's own; its NIC is capped at 25 MB/s. The
  rules sit outside the container, out of the fetcher's reach.
- **Limits**: one import per tenant and one per member, 3 per site at a time, so a member of
  several projects cannot take every slot; more return `queued` (section 4.2). A download that
  stays under 2 MB/s for 60 seconds, or runs longer than 3 hours, is aborted, so a slow server
  cannot hold a slot; at 2 MB/s a 20 GB file still finishes inside 3 hours.
- **Format checks**: `qemu-img info` runs as the fetcher user, under CPU and memory limits, on
  every staged cloud image. The image is refused if the probed format differs from the `format`
  argument (a `raw` file that probes as anything else included), or if it names a backing file or
  a qcow2 data file, is encrypted, or has a virtual size above 1000 GB. A backing file that points
  at another tenant's disk would otherwise copy that disk into the attacker's machine.
- **Storing**: a root step on the node (node-agent `fetch_store`), not the fetcher, checks the
  staged file against the checksum in the database. It pulls the file out with `pct pull`, which
  resolves the path inside the container, so a symlink the fetcher plants cannot point at a host
  file. It writes to a temporary name on the shared storage that Proxmox does not list, hashes it
  again, makes it read-only (`0444`), renames it to its final name and removes the staged copy.
  Nothing goes through the upload API, which spools to `/var/tmp` on the root file system first.
- **Layout**: files use Proxmox's own directories: ISOs in `template/iso/` as `iso` content, cloud
  images in `import/` as `import` content, never `images`, because Proxmox applies its
  untrusted-image checks only to `import` volumes. Those checks still hold if a compromised
  fetcher lies about an image. Proxmox volume names are flat, so the name carries the tenant:
  `carrel-t<NNN>-<name>-<first 12 hex of sha256>.<iso|qcow2|raw>`, for example
  `carrel-t017-alpine-1a2b3c4d5e6f.qcow2`. The prefix marks carrel's files among others on the
  export, and a new import under the same name is a new file. node-agent refuses a volume whose
  tenant number is not the machine's. The reconciler reports carrel files without a database
  record, and records without a file; it deletes neither.
- **Checks before use**: before every `import-from` and every ISO attach, node-agent checks the
  file's size and SHA-256 against the database. A match means these are the bytes the format
  checks accepted, so those checks need not run again; Proxmox's own `import` checks run anyway.
  Starting a machine whose ISO is already attached does not read the file again. A cloud image's
  virtual size counts against `disk_gb` and may not exceed the requested disk. CT templates are
  pinned to the sha512 of Proxmox's signed index and checked before every `pct create` (#100),
  since one rewritten template on shared storage would reach every new CT on every node. These
  reads, the copies of the storing step and migrations share the nodes' one link with corosync
  (13.14), so they are rate-limited.
- **Quota**: files count their size against `images_gb`, together with app releases (7.9), at
  most 20 GB per file; a download in flight reserves its limit. A checksum is mandatory, and
  imports stay private to the tenant: two tenants who import the same file store it twice, so
  neither learns what the other imported. A machine created from a cloud image gets its own copy
  on the guest storage, so `image_delete` frees the file at once. An ISO stays while a machine
  has it attached; `image_delete` refuses it until `machine_media` ejects it.
- **When the shared storage is down**: the NAS is a network service outside the cluster, and the
  mount is `hard`, so a read waits for the server forever. Before any action that reads the
  storage (CT creation from a template, `import-from`, ISO attach, starting or migrating a machine
  with an ISO attached), node-agent reads it in a child process with a deadline. If that fails,
  the action returns `storage_unavailable` and nothing is created. A creation that fails after the
  check removes the machine it started, under the existing creation manifest. Running machines do
  not depend on the storage, except that reads from an attached ISO wait until the server
  returns. A machine with an ISO can always start once `machine_media` ejects it.
- **Who can read the files**: the export accepts only the site's node addresses, and its
  directories are `0755 root` (they were `0777` until 2026-10-21; the export does not squash
  root). Tenant machines, the infra CTs and the fetcher cannot reach the NAS (section 6.3). The NAS
  administrators can read every imported file, and the README says so next to the note on
  hypervisor root (7.7).
- **Migration**: an ISO on shared storage needs no copy, and Proxmox migrates a machine with one
  attached. Moving machines is section 7.10.
- **Unmanaged machines**: `machine_create` returns in state `installing`, without an SSH line.
  The member installs through `machine_console_url` and ejects the ISO with `machine_media`, which
  marks the machine ready. The SSH check is only a hint for these machines, because systems such as
  Windows may never run SSH. `machine_reset_access` is not available, snapshots are
  crash-consistent (no guest agent to freeze the file system), and shutdown uses ACPI.
- **Firmware**: `firmware: bios | uefi` and `tpm: true` for systems that need them, such as
  Windows 11. The virtio driver ISO can be attached as a second drive. Licences are the tenant's
  responsibility.
- **Browser console**: `machine_console_url` returns a single-use link, valid for 15 minutes.
  Opening it sends the browser through a WinLab login (Keycloak, through carrel's own
  `/oauth/callback`, so no new redirect URI), and any login spends the link; only the member who
  asked for it gets the console, in a session cookie for `/console` only (`HttpOnly`, `Secure`,
  `SameSite=Strict`, one hour). The page is noVNC, loaded from jsdelivr pinned to the commit of
  v1.6.0; its WebSocket is accepted only from carrel's origin, and the control plane bridges it to
  `qm vncproxy` on the machine's node through the node adapter, which answers one line and then
  hands its standard input and output to `qm`. Every link and every opening, refused ones
  included, is in `audit_log`. Links are not emailed (decided 2026-10-21): in a personal tenant the
  member is the owner, project members share their machines anyway, and the audit log answers
  "who opened it". This page is the one exception to 1.4.
- **Images without SSH**: `image_import` takes `ports` (1 to 4 TCP ports, not 22) for an image
  that runs no cloud-config and no SSH, as Talos does (issue #94; `[50000, 6443]`). A VM from it
  is unmanaged: no keys, no swap, no public SSH port, small by default (Talos needs 2 GiB for a
  control plane). carrel still writes the network file (Talos' nocloud platform reads the same
  version 2 document) and passes the member's `user_data` unchanged as user-data, which Talos
  reads as its machine config; without it, an empty cloud-config, which Talos skips and boots
  into maintenance mode for `talosctl apply-config --insecure`. `user_data` is stored like
  `runcmd`: never shown, audited or sent to other nodes. Readiness is a TCP connection from the
  control plane to the first port, checked by `machine_get`. Each guest firewall admits the
  control plane and the jump host on the declared ports instead of 22, the jump host's key lines
  permit those ports, and `machine_get` returns a `tunnel` line (`ssh -N -L ...`) for
  `talosctl` and `kubectl`. `port_open` still publishes a port when a member wants one.
- **CTs** keep to the platform images in version 1.

**Order of work** (planned 2026-10-21; each line one PR, `R` = independent review):

1. Content storage per kind, CT templates on it (#92, done in #100).
2. Cloud-init bytes in the database (#93, 7.10). R
3. `machine_migrate`, admin (7.10). R
4. `node_drain`, admin. R
5. Fetcher infrastructure without a member tool: namespace, user, mount sandbox, host rules,
   staging dataset, `qemu-img` sandbox. R
6. `iso_import`, `image_delete`, `images_gb` in `quota_get` and `quota_request`, the storing step,
   queue limits, drift report. R
7. ISO machines: `iso` on `machine_create`, `machine_media`, firmware, `installing`.
8. `machine_console_url`. R
9. `image_import` and `tenant:<name>` creation through `import-from`. R
10. Talos (#94).

### 7.9 Apps: deploy on push

An app binds one GitHub repository branch to one tenant machine. Every push builds in GitHub
Actions and lands on the machine as a new release, with the old one kept for rollback. The machine
stays a pet machine: the member can still SSH in and change anything, and carrel never enters it.

**Flow**

1. The member's agent calls `app_link` with the machine, repository, branch, start command and
   port. carrel returns an install line, the app's agent token and a workflow snippet. A public
   name is a separate `domain_add` to the same port.
2. The agent runs the install line on the machine over its own SSH, with the token piped into it
   from the client, so no command line on the machine carries the token (issue #33). It installs `carrel-deployd`
   (a small static binary run by systemd) with a token scoped to this one app, and writes the start
   command into a local file that carrel cannot change. carrel has no other way into the machine
   (section 7.7).
3. The agent commits the workflow to the repository. The workflow builds, then calls the reusable
   action `NYCU-WinLab/carrel-deploy@v1`:

   ```yaml
   permissions:
     id-token: write
   steps:
     - uses: actions/checkout@v4
     - run: npm ci && npm run build && tar czf app.tar.gz .next/standalone
     - uses: NYCU-WinLab/carrel-deploy@v1
       with:
         app: my-site
         artifact: app.tar.gz
   ```

4. The action uploads the artifact to carrel with a GitHub OIDC token (a short-lived token GitHub
   signs for each job). The repository holds no carrel secret.
5. carrel checks the token, stores the artifact as a release and marks it pending.
6. `carrel-deployd` long-polls carrel over outbound HTTPS, downloads the release, unpacks it to
   `/srv/apps/<app>/releases/<id>`, switches the `current` link, restarts `carrel-app-<app>` and
   checks the port: any HTTP answer below 500 on `127.0.0.1:<port>` within 60 seconds. A failed
   check switches back to the previous release and reports `failed` with the last 50 log lines.
7. The action polls the release until it is `live` or `failed`, so the workflow run fails when the
   deploy fails.

**OIDC checks**: issuer `https://token.actions.githubusercontent.com`, audience
`carrel.winlab.tw`, `repository` equal to the linked repository, `ref` equal to the linked branch,
and `event_name` of `push` or `workflow_dispatch`. The first accepted deploy pins `repository_id`,
so a deleted and recreated repository with the same name cannot deploy afterwards. Pull requests
from forks get no OIDC token, so they cannot deploy.

**Why the build runs in GitHub Actions**: the default machine has 1 GiB of memory and cannot run
`next build`. GitHub runners have 7 GB, cost carrel nothing to operate, and keep build tools and
caches off tenant disks. NYCU-WinLab is on the GitHub Team plan: public repositories build free,
private ones share 3,000 minutes per month.

**What stays inside the machine**

- Runtime secrets live in `/srv/apps/<app>/env` (mode `0600`), written by the member's agent over
  SSH. They never pass through carrel or GitHub.
- Application logs stay in the machine's journal. `carrel-deployd` reports only release state, the
  health check result and, on failure, the last 50 lines of `carrel-app-<app>`.
- The member may stop or remove `carrel-deployd` at any time. The app then shows `agent_offline`.

**Artifacts**: at most 500 MB per release, the last 3 releases kept per app, counted against
`images_gb`. Releases older than the last 3 are deleted when a new one is stored.

**Observability**: each release is a span in sensorium with app, commit SHA, duration and result,
so an admin agent can answer which commit runs where (section 9.1).

**Version 1 limits**: GitHub only. GitLab CI also issues OIDC tokens (`id_tokens`), so the same
design extends to it later. One app per machine port; one machine per app.

### 7.10 Cloud-init files and moving machines

Proxmox derives a VM's cloud-init instance id from the SHA-1 of its user-data and network files,
so any change to their bytes makes cloud-init run again (new SSH host keys, `runcmd` again).
Regenerating the files on another node is therefore never safe. At creation the control plane
stores the exact bytes of both files and their SHA-256 in its database, and node-agent writes them
back, mode `0600`, on the node that starts or receives the machine, before every start and every
migration. The files stay on each node's `local` storage, never on shared storage, because they
hold keys, member commands and the readiness token. Deletion removes them on every node.
`machine_reset_access` is the one action that stores new bytes.

Machines are linked clones of their node's base template (7.2), and Proxmox refuses to migrate a
linked clone on local storage. `machine_migrate` (admin) therefore moves a machine in three steps,
online when it runs: move its disks to the shared storage (`qm disk move`), migrate it (the disks
are shared, so only memory moves), and move the disks to the target node's guest storage. The
first move also detaches the disk from the template. Each step is bandwidth-limited, because the
nodes reach the NAS over the link corosync uses (13.14). The record's `node` changes only after
Proxmox reports the machine on the target, and the source's cloud-init files go last.
`node_drain` marks a node unschedulable (kept in the database's `site` table, outside any
tenant) and queues a `machine_migrate` for each of its machines; `machine_migrate` without a node
picks the node with the most free memory that is not drained. Moves run one at a time across the
site, since they share the nodes' one link with corosync; a move that finds another in progress
waits for its slot. `node_undrain` reopens placement and leaves moved machines where they are.

## 8. Hosts and sites

### 8.1 The installer

The installer is a short ordered list of idempotent scripts, each run where it acts (README,
"Install a site"); running one again repairs, never assumes a blank slate. Planned: one
`install.sh` that runs them in order, with `--join <existing node>` to add a node that holds no
guests.

- Every node: the site file, `storage` in `node.json`, then `install-network.py`.
- First exit node: `bootstrap-platform.py` creates CT 100 and CT 101.
- Every node: `build-templates.py` imports the prepared images at that node's VMIDs.
- CT 100: `config.json`, written by an administrator from `sites/<site>/config.example.json`.
- Workstation: `deploy-go.py --host <first exit node>` stages the release and runs
  `install-control.py`, which installs the reader token, the node programs on every node, the
  control plane service and its backup timer. The same command upgrades.

### 8.2 Decided on the first host, because they cannot change later

| Item | Decision |
|---|---|
| Node names and management addresses | stable names `carrel01` to `carrel04`; fixed management addresses `192.168.19.101` to `.104`; site `b09` identifies the room |
| Storage | One storage id on every node of a site, read from site configuration, never hardcoded. B09: ZFS `local-zfs` on a two-disk stripe per node (2026-10-19; the R640 node used LVM-thin `local-lvm`). Migrations copy local disks. No ZFS replication; recovery uses independent backups |
| Tenant networks | EVPN zone for primary networks, VXLAN zone for private networks (section 6.2) |
| VMIDs and templates | site-unique ranges (section 6.1) |
| Data model | site then node from day one (section 2) |

### 8.3 Adding nodes

1. Same room, under 5 ms between nodes. A dedicated corosync link plus a second link for
   redundancy. VXLAN and BGP between nodes use the second link or a NIC of their own, never the
   dedicated corosync link, because tenants control that traffic (section 6.3).
2. Same Proxmox VE version on every node.
3. Two nodes need a QDevice outside the cluster. Three or more nodes can provide quorum for
   HA, but local ZFS alone cannot restart a failed node's guests elsewhere: their disks are
   still on that failed node. Planned migrations copy disks while the source is healthy; host
   failure recovery uses independent backups until shared storage is supplied and tested.
   B09 runs four nodes without a QDevice: 4 votes, quorum 3. Only one node may be down at a time,
   so drain and upgrade one node at a time.
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

A loop compares the database with Proxmox, firewall, NAT, private DHCP, DNS and Caddy every 5 minutes and
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

### 9.4 NetBox inventory sync

Opt-in (issue #141). With `netbox.enabled` carrel pushes what it already knows to a NetBox instance,
so the inventory and IP allocation there do not go stale. The database stays the only source of
truth and NetBox is a derived copy, like the firewall or the DNS records: nobody edits what carrel
created.

Configuration, in `config.json` (omitted or `enabled` false means no sync, no goroutine, no
`netbox` field in `machine_get`):

| Key | Meaning |
|---|---|
| `url` | NetBox base URL |
| `token` or `token_file` | API token. `token_file` is read again on every pass, so rotation needs no restart. Never logged or put in an error; a value with a space is sent as the header as is, `nbt_` gets `Bearer`, anything else `Token` |
| `cluster` | NetBox cluster (name) that holds the virtual machines. It must exist; the NetBox operator owns it |
| `owner` | name of the NetBox owner (NetBox 4.5+) every created object carries. It must exist; the NetBox operator creates it, since an owner needs a group. Use a different owner for each carrel installation that shares a NetBox |
| `vmid_field` | integer custom field on the NetBox VM for the Proxmox VMID, default `vmid`. The NetBox operator creates it |
| `device_field` | custom field of a NetBox device that holds the Proxmox node name, for devices named differently from their node (`serverQ10` for `carrel01`). Empty, the default, matches the device name |
| `vrf` | name of the shared VRF, default `Carrel`; a private network's VRF is `<vrf> <Tenant> <network name>` (`Carrel Alice back`). A VRF that carrel created under the old form (`carrel-alice-back`) is found by that exact name and renamed in place |

Mapping:

| carrel | NetBox |
|---|---|
| machine (VM and CT) | virtual machine `<machine>.<tenant>` in the cluster; vCPU and memory (MiB) from the spec; `active` when running, `planned` while provisioning, otherwise `offline`; `start_on_boot` follows Proxmox `onboot`, which is set by the owner's last power action (`on` after a start, `off` after a stop, pause or tenant suspension), so a guest that shuts itself down stays `on`; a machine with no recorded action is `on` when running; the description says VM or CT; the VMID goes into `vmid_field`; the device is the cluster device whose name, or `device_field`, matches the Proxmox node, none when there is no such device |
| image | platform created and deleted by carrel. The name starts with `Carrel: `: `Carrel: Debian 13` for a platform image (shared by all tenants) and `Carrel: Alice/base` for a tenant image or ISO (one per tenant; the two share one name space in a tenant). The slug keeps them apart and starts with `carrel-` so it cannot meet a platform made by hand: `carrel-catalog-debian-13`, `carrel-alice-tenant-base`, `carrel-alice-iso-win11` (the label in lower case with other characters as `-`); a platform with that slug that carrel did not create is an error. A platform from before the prefix is found by its old slug and renamed in place. NetBox keeps platform names unique, so a platform made by hand with the same name, which the prefix makes unlikely, fails the machines of that image until it is renamed; the error shows in `machine_get` |
| machine disk | virtual disk `scsi0` (VM) or `rootfs` (CT) in MiB; NetBox sums it into the machine's disk |
| NIC MAC | MAC address object assigned to the interface and set as its primary MAC |
| primary NIC and each extra NIC | VM interface `eth0`, `eth<index>` |
| machine address, managed NIC address | IP address on its interface, in the shared VRF (a private network's address in that network's VRF); the machine address is the primary IPv4, with DNS name `<machine>.<tenant>.internal` as the infra resolver answers it |
| tenant segment `10.200.N.0/24` | prefix in the shared VRF |
| managed private network CIDR | prefix in that network's own VRF |
| `raw_l2` private network | nothing but the attachment: the NIC's interface description names the network and its mode; no prefix, VRF or address |
| published port, HTTPS route | service on the VM, or on the FHRP group when it targets a virtual address, with `port_mappings` `<proto>/<target port>` (`public-<proto>-<public port>`, or the domain URL as the name) |
| virtual address | IP address with role `vip` on an FHRP group (protocol `other`) named `<name>.<tenant>`, with the primary interface of every allowed machine as a member |

The tenant segment `10.200.N.0/24`, machine addresses and virtual addresses are allocated by the
platform and unique across tenants, so they share one VRF. Only a private network can overlap
another tenant's CIDR (a member may choose it, and only managed networks are checked, and only
within the tenant), so each managed private network gets a VRF of its own. A `raw_l2` network has no addressing carrel manages, so it gets no prefix, VRF or address, only the interface that attaches to it. Carrel creates every
VRF with the owner and deletes it when nothing needs it. A VRF of the same name that carrel did not
create is an error, not something to adopt. Dedicated public IPs are not mapped yet
(the feature does not exist); they would add an IP from the public pool with `nat_inside`.

Behavior:

1. A pass derives the wanted objects from the database, lists the objects that carry the owner,
   and creates, patches (only fields that differ) or deletes the difference. A pass over an
   unchanged database sends no write. Passes run every 5 minutes (drift repair, backfill of
   machines that existed before the feature was enabled) and 2 seconds after any operation
   changes, merged into one. There is no dry run.
2. Deletion goes dependents first: services, memberships, IPs, interfaces, VMs, groups, prefixes,
   VRFs, because NetBox refuses to delete a referenced object.
3. The pass takes no part in `writer` and no machine operation waits for it. Failures retry with
   backoff (15 seconds up to 5 minutes) and the next pass catches up.
4. A machine that fails (a foreign VM with its name, a missing custom field, a rejected value)
   keeps every object it already has in NetBox, the other machines still sync, and the error shows
   in `machine_get` as `netbox: {last_synced, last_error}` and once in the audit log (tool
   `netbox_sync`). A pass-level failure is in the site status and the audit log.
5. A machine rename (`machine_rename`) changes the VM's name, matched by VMID, on the next pass.

Names and descriptions start with a capital letter and may have spaces; only slugs are lower case with dashes.

Least privilege. Every object carries the owner from its creation request, and only objects with that owner
are listed, patched or deleted. NetBox cannot constrain what a binding points at, so carrel only
binds to objects it created in the same pass or earlier (the VM, interface, group and IP), plus the
configured cluster. FHRP memberships cannot carry an owner; they are deleted only when their group
is carrel's. The owner belongs to the sync alone: a pass deletes every object with that owner it does
not want, so nobody gives the owner to an object by hand, and the owner's object count is 0 before
the first pass. Permissions the token needs, each constrained to the owner where NetBox allows:

| Object | view | add | change | delete |
|---|---|---|---|---|
| virtualization.virtualmachine, vminterface | yes | yes | yes | yes |
| ipam.ipaddress, prefix, vrf, service | yes | yes | yes | yes |
| ipam.fhrpgroup | yes | yes | yes | yes |
| dcim.platform | yes | yes | yes | yes |
| dcim.macaddress | yes | yes | yes | yes |
| virtualization.virtualdisk | yes | yes | yes | yes |
| dcim.device | yes | no | no | no |
| ipam.fhrpgroupassignment | yes | yes | no | yes |
| virtualization.cluster | yes | no | no | no |
| users.owner | yes | no | no | no |

## 10. Maintenance

### 10.1 Backups

Proxmox Backup Server on a separate machine. Priority: the carrel database and Keycloak client
configuration, then infra machines, then tenant machines (opt-in, counted against quota).

Until then, the control plane sends one archive each night (database, configuration,
certificates and each node's files) to the SSH target `carrel-backup`: `scripts/backup-target.py`,
a forced command on a host outside the cluster (spawner, the old PVE), keeps 14 of them.

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

Planned: a nested Proxmox VE inside a VM on a site node. CI installs carrel into it from scratch on
every release candidate and runs the acceptance sentences of section 11.3 against it, with two
differences from production: staging has its own DNS zone (open decision 13.11) and uses the
Let's Encrypt staging CA, so a run never issues real certificates or touches `winlab.tw` records.
M9 (import) is production only and is checked once, by hand, against its sentence.

The nested staging VM on the R640 node retired with that node (2026-10-20). Until the planned
one exists, changes are checked on disposable tenant machines.

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
- VPN access into tenant networks (public SSH ports and the jump host are the path; design in 6.11).
- IPv6 (open decision 13.6).
- Machines spanning sites, live migration across sites.
- A web UI, apart from the machine console page (section 7.8).
- Builds inside carrel. Apps build in GitHub Actions and carrel only stores and hands out releases
  (section 7.9).
- Apps from GitLab (section 7.9).

### 11.3 Milestones

| Milestone | Done when |
|---|---|
| M0 Staging | CI installs a nested node from scratch and the install is idempotent: a second run changes nothing |
| M1 Host baseline | A bare host after `install.sh` has the configured storage, both SDN zones, the infra network, the firewall, the gateway and all templates; a tenant address cannot reach host port 8006, and a VXLAN or BGP packet is dropped when it comes from an address that is not a node or carries a forged node address on the public interface |
| M2 Control plane | A clean agent with only the MCP connector, given "Open a VM on winlab for my SDN homework", signs in through Keycloak and ends with a working SSH session |
| M3 Access | The same agent opens a port and a domain under the tenant's wildcard certificate, a second tenant cannot reach the machine until `peer_allow`, and `machine_reset_access` recovers a machine whose keys were deleted |
| M4 Quotas and requests | A project tenant runs out of quota, files `quota_request`, an admin approves it, and the retry succeeds; a temporary grant expires on its date; the project requests a name that already exists, such as `afc.winlab.tw` (its twin in the staging zone on staging), an admin approves it with `adopt: true`, and the site answers over HTTPS on that name |
| M5 Private networks | Two host VMs on two private networks reach each other only through a router VM, a machine of another tenant on the same node captures no frame from those networks, a frame sent from outside with a guessed VNI never arrives, and 1450 byte packets pass end to end |
| M6 Custom images | A tenant imports a cloud image by URL and checksum and gets a managed machine with an SSH line; another installs Debian from an ISO through `machine_console_url`, gets its reserved address by DHCP, and both files show in `quota_get`; an import URL that points at an internal address such as `10.0.0.0/8` is refused, and so is a qcow2 image with a backing file; a second import by the same tenant waits in `queued` until the first ends |
| M7 Skills | Every skill in 4.5.1 has evaluation cases, passes the release gate of 4.5.3 on staging for both Claude Code and Codex, `usage_report` shows reads per skill version, and an agent that hits a known problem finds its issue with `issue_search` instead of filing a duplicate |
| M8 Operations | Killing the metric pipeline raises the freshness alert, a restore from Proxmox Backup Server brings back a deleted infra machine, and an alumni member's machines stop on schedule |
| M9 Import (production only) | Every guest chosen under section 10.7 runs on the new site under its owner, its names answer from outside the campus, every check of 10.7 that applies to it passes, and its source stays stopped on the old host for 14 days |
| M10 Second node | `install.sh --join` adds a node, `node_drain` empties the first one with no tenant noticing (a machine with an ISO attached included), and machines land on both nodes; with real peers now, a VXLAN or BGP packet carrying a forged node address on the public interface and a frame with a guessed VNI never arrive (the cases of M1 and M5); a machine created on the new node from an image fetched on the first gets a verified copy |
| M11 Apps | A clean agent given "Deploy this Next.js repo to my machine on every push" ends with the site answering on its domain; the next push serves the new commit; a push that fails its health check leaves the previous release serving; a workflow in another repository, or on another branch, is refused |

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
    Real OAuth, public SSH and tenant HTTPS were verified; see 15.4. Superseded 2026-10-19: the
    four-node cluster takes ingress on `140.113.60.184` (section 15.15).
14. B09 links and backups. Resolved 2026-10-19: four nodes, no QDevice. Open: every node has one
    connected 1 Gbit/s port, so corosync, the VXLAN underlay, management and VLAN 60 share it.
    A second link (the X540 and X710 ports have no cable) and backup storage outside the cluster
    are still needed. The striped pools make backups the only recovery from a disk failure.
15. App artifact limits (section 7.9): 500 MB per release and 3 kept releases are first guesses.
    Revisit after real apps.

## 14. Vocabulary

| Term | Meaning |
|---|---|
| admission | the physical capacity check at create or start, separate from quota |
| `carrel-deployd` | the agent a member installs in a machine to receive app releases (section 7.9) |
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
Explicit restricted ingress enforces exact source/protocol/port rules and prevents unfiltered NIC bypass
(superseded 2026-10-20, issue #75: restricted filters the primary NIC only).
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
- The current Go contract is maintained directly. No new scheduler, cache or warm pool is
  introduced by this release.

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
reconciles. Experiment NICs no longer prevent restricted ingress (superseded 2026-10-20, issue #75):
restricted filters the primary NIC only, and private NICs stay unfiltered.
SSH, publications and old peer grants remain. Rollback restores a prior policy only if the operation
still owns it on the same allocation. Results include affected existing machines.

Resize separates allocated block capacity from unverified guest filesystem growth, with owner SSH
follow-up and no implicit reboot or guest execution API. HTTPS preparation persists reserved domains
before DNS/ACME work outside the writer; issuers serialize separately from it.
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

### 15.15 Four-node cluster (2026-10-19)

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
