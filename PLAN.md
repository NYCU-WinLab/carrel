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
  Functions (section 7.11) are the one planned exception: a single container image that carrel
  runs while it has work. They add no manifest language and no orchestration.
- Not a public cloud. One installation serves one organization, and tenants are lab members and
  lab projects. A member may pair a Proxmox host of their own as a private site (section 8.4),
  which only their own tenants use; carrel never places another tenant's machine on it.
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
| 2026-09-27 | Admin notifications and alerts go by email (alerts superseded 2026-11-17: an alerting service reads the telemetry collector, section 9.3) |
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
| 2026-10-24 | The lab website moves onto a tenant: `winlab.tw` and `www.winlab.tw` may be granted as exact special names. `www` stays reserved as a tenant slug, and the zone's wildcard is never granted (section 6.10) |
| 2026-11-25 | One control plane manages several sites. Each site runs a site agent that connects out to the control plane, pulls the desired state and reports the actual state (section 8.4) |
| 2026-11-25 | A member may pair their own Proxmox host as a private site. Its owner has root on it, so carrel treats it as untrusted: only the owner's tenants use it, and its quota counts only there (section 8.4) |
| 2026-11-25 | Features outside the core become plugins that run next to the site agent, and each site reports which it supports. Snapshot and freeze are the first two (section 8.5) |
| 2026-11-12 | Functions: a container image that sleeps without memory and wakes from a microVM snapshot on a request. The contract is an OCI image that serves HTTP, so the same image runs on AWS Lambda. Pet machines stay the default. Built since: the host agent and the control plane side (section 7.11) |

### 1.6 Current core and deferred work

The first release is accepted around three member outcomes: create one VM/CT and SSH into it;
publish an application on an existing machine; create an app/database pair with only the declared
connection allowed. Agents provide machine, connection and publication intent through the existing
`deployment_plan` / `deployment_apply` tools. Physical nodes, bridges and ingress hops are operator
implementation details. Advanced L2 tools remain available for network experiments.

Reliability, tenant isolation, ownership-safe retries, quota accounting and cleanup are core work.
The longer catalog below is a roadmap, not a claim that every tool exists or a requirement to ship
all of it before the core is useful. Custom ISO/image import, special names and ports (6.10) and
the client VPN (6.11) are built. Legacy workload migration, a full skill catalog, issue workflow and
alumni scheduling are deferred until there is a concrete need. Multiple nodes became core work on
2026-10-19 (section 15.15). This change adds no scheduler, workflow language or separate intent
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
| Function | A container image owned by one tenant that runs only while it has work (section 7.11, planned) | tenant, name |
| Version | One image digest of a function, with its root file system and snapshot | function, digest |
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

Tool annotations follow one rule, and `TestContractAnnotations` checks it over the whole contract.
`readOnlyHint` is true exactly for the tools that are not in `mutations`, except `whoami`, which
registers an eligible tenant. `destructiveHint` is true when the call removes something the member
cannot get back with one call: deleted data (`machine_delete`, `snapshot_delete`, `image_delete`,
`function_remove`, `app_unlink`), state that is overwritten (`snapshot_rollback`), a resource
returned to a pool (`vip_remove`, `public_ip_release`) and a secret replaced (`app_webhook_rotate`).
Removing a grant, key, route or client that one add call restores is not destructive.
`idempotentHint` is true on a write whose repeat with the same arguments changes nothing more.

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
  `invalid`, `pending_approval`, `internal`. `internal` is a panic that is not a refusal, a bug;
  it is logged at error level with its stack and never reads as a member conflict.
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
| Machines | `machine_create` | `kind`, `name`, `image` (platform, `tenant:image:<name>`) or `iso`, `size` or `cpu` + `memory_mb` + `disk_gb`, `networks[]`, `ssh_keys[]`, `packages[]`, `runcmd[]`, `nested_virt`, `swap_mb`, `firmware`, `tpm`, `tags[]` |
| | `machine_get`, `machine_list` | state, primary address, SSH line, image support status |
| | `machine_resize` | CPU/RAM may shrink while stopped; disk only grows |
| | `machine_power` | `start \| stop \| shutdown \| reboot` |
| | `machine_rebuild` | new `image`; keeps address, ports and domains |
| | `machine_delete` | `confirm: <name>`; if the post-delete reconcile fails the result still reports `deleted` and adds `warnings: [{code: "reconcile_failed", message}]`, absent otherwise |
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
| | `public_ip_request` | `reason`; an approval gives the tenant an address of the pool (section 6.12) |
| | `public_ip_bind`, `public_ip_release`, `public_ip_list` | `machine`, `address`, `ports: ["all"] \| ["tcp/N", "udp/N"]`; 1:1 NAT |
| Apps | `app_link` | `machine`, `name`, `repo` (GitHub owner/name or a GitHub or GitLab URL), `branch`, `start`, `port`; returns the install line and the workflow snippet (section 7.9) |
| | `app_get`, `app_list` | linked repository, agent state, current and previous release, last result |
| | `app_deploy` | `app`, `release`; deploys a stored release again |
| | `app_rollback` | `app`; switches back to the previous release |
| | `app_unlink` | `confirm: <name>`; deletes stored releases and revokes the agent token, leaves the machine as it is |
| Runners | `runner_add` | `machine`, `provider: github \| gitlab`, `url`, `name`, `labels`, `allow_public`; returns the install line and `token_command` (section 7.9) |
| | `runner_list` | Runners with machine, provider, URL and labels |
| | `runner_remove` | `runner`, `confirm: <name>`; returns the commands that stop and unregister it |
| Functions (planned) | `function_deploy` | `name`, `image`, `port`, `memory_mb`, `instance: reuse \| fresh`, `idle_seconds`, `timeout_seconds`, `schedule`, `wake_path`; returns the URL (section 7.11) |
| | `function_env` | `function`, `clear`; a single-use link for the environment file (section 7.11) |
| | `function_registry` | `function`, `registry`, `clear`; a single-use link for a private registry's credentials (section 7.11) |
| | `function_link` | `function`, `repo`, `branch`, `clear`; deploy on every push with GitHub OIDC (section 7.11) |
| | `function_get`, `function_list` | state, URL, current and previous version, wake times of the last 24 hours |
| | `function_logs` | `function`, `since`; the output the platform captured |
| | `function_rollback` | `function`; switches back to the previous version |
| | `function_remove` | `confirm: <name>`; deletes every version and snapshot |
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
`tenant_suspend`, `usage_report`, `node_list`, `node_drain`, `node_undrain`, `machine_migrate`, `reconcile_run`, `platform_power` (section 7.5), `image_build`,
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
`snapshot_gb`, `frozen_gb`, `networks`. Member and project tenants use the same dimensions. `images_gb` is
reserved for deferred image support and hidden from the current API. `snapshot_gb` counts the space
that only a tenant's snapshots hold, as the nodes last measured it (2026-11-17; before that each
snapshot counted at the size of its disk). The rule is in section 5.2.
A frozen machine (section 10.1) holds its configured disk size in `frozen_gb` (default: the `disk_gb`
default) and its address in `ips`, and nothing else.
Special domains and ports are not a dimension: each one needs an admin's approval (section 6.10).
Functions will add `functions` and `function_gb` (section 7.11).

### 5.2 Quota versus admission

Quota is a ceiling, not a guarantee of unused physical capacity. Admission is checked separately.

Personal and project defaults are 8 machines, 8 IPs, 16 vCPU, 32768 MiB RAM and 200 GiB disk.
Eight default 1 vCPU / 1024 MiB / 10 GiB machines consume 8 vCPU / 8 GiB / 80 GiB. CPU growth
then requires quota headroom or approval; stopping does not release reservations. Every machine
uses one of the tenant's 10 public ports for SSH, leaving two for extra TCP/UDP publications.
HTTPS domains do not consume this port block. Domains (10), networks (4), snapshots (4) and
snapshot space (200 GiB) retain their existing defaults. A machine created with
`public_ssh: false` takes no public port and is reached through the platform SSH jump host
(CT 102, issue #98), so the machine quota, not the port block, bounds how many a tenant runs.

| Layer | Rule (initial values, tuned after the hardware inventory) |
|---|---|
| Quota | The sum of all quotas may exceed capacity, because most tenants are idle most of the time |
| CPU admission | All allocated Carrel machines, including stopped ones, reserve vCPU; shared vCPU at most 4 times host threads |
| Memory admission | All allocated Carrel machines, including stopped ones, reserve RAM; unmanaged running infrastructure also counts |
| Memory ratio | The ratio stays at 1 (owner decision on #290): admission reserves all assigned memory and no ratio above 1 is set. Resident memory is about 75 percent of assigned, a node has no swap, and a balloon target below the guest's working set kills processes. So there are no burstable or guaranteed classes, no floor-based admission and no reclaim loop; the experiment is in #290 |
| Memory measurement | VMs keep the balloon device (2026-11-17): the guest reports what it needs, and returns freed pages to the node. Nothing shrinks a machine, and admission still reserves all assigned RAM. Each node's sum of assigned and needed memory is recorded (section 9.1); a memory ratio is set only from that record. Machines created earlier get the device at their next cold boot or reboot through `machine_power`, and a machine thawed from an older backup gets it at the restore |
| Disk admission | Allocated disk at most 1.5 times the pool: volumes at their declared size, snapshots at the bytes they hold (2026-11-17; a node that does not measure them counts each at the size of its disk). A snapshot whose disk would not fit in the node's physical headroom is refused |
| Snapshot quota | `snapshot_gb` is the space only the tenant's snapshots hold (ZFS `usedbysnapshots` of its volumes, sampled every 300 seconds and after each snapshot operation). A new snapshot holds nothing, so it is refused only while the tenant is already over the limit; `snapshots` bounds how many there are. The limit is a line where growth stops, not a cap: snapshots keep growing as the disk changes, up to the size of the disk each. Being over it refuses new snapshots and nothing else. In every dimension only growth is refused; a request that adds nothing passes. Without a sample from the last 15 minutes each snapshot counts at the size of its disk, as it did before. The control plane's clock dates a sample, so a node whose clock is wrong cannot keep an old one in use |
| Disk watermark | Real use of a node's pool: `warning` above 70 percent, `blocked` above 80 (nothing on the node grows), `critical` above 85. `capacity_get` and `node_list` report it; alerts are in section 9.3. Snapshots and thin disks grow after admission, so the watermark, not admission, is what guards a pool |
| Addresses, ports, domains | Fixed allocations, never oversubscribed |

When admission fails the tool returns `capacity_exhausted` and lists the tenant's idle machines.

### 5.3 Requests

Four kinds share one flow: `quota_request` (more of a dimension), `domain_request` and
`port_request` (special names and ports, section 6.10) and `public_ip_request` (a public address,
section 6.12).

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
- No bandwidth limits: tenant machines may use the full uplink (open decision 13.4).
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
   - the zone is managed and open to this tenant, and the name is not reserved (the site's own
     `winlab.tw` and `www.winlab.tw` may be requested as exact names; their certificates cover
     only themselves);
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
the global `on_demand_tls` asks the gateway's own `http://127.0.0.1:2020/gateway/ask`. It answers
names carrel agreed to at the last reconcile itself, since Caddy asks again when it loads a
certificate it holds, so a gateway restart while the control plane is down keeps delegated sites
up; it passes any other name to `http://10.200.0.3:8080/gateway/ask`, a path the public origin does
not forward, answered only to the gateway's address. A second ask for a name whose tenant is being
asked waits for that answer. carrel agrees to a name once its route is
ready, the tenant is active, the grant has issued fewer than 20 new names in 7 days, and the
route's target answers `GET /.well-known/carrel/ask?domain=<name>` with 200 (the control plane
reaches it: the guest firewall admits `10.200.0.3` to a delegated route's port). A name agreed to
once is answered from its record, so renewals spend no budget.

The Cloudflare proxy switch is built too: admin `domain_proxy` with `name` and `proxied` turns it on
or off for an exact grant one label under its zone (the record gets Cloudflare's automatic TTL).
The DNS tokens cannot read a zone's SSL mode, so after turning it on carrel resolves the name
through 1.1.1.1 until Cloudflare answers for it and asks `https://<name>/.well-known/carrel/probe`
there, a path every exact grant's site answers with its grant id; a 52x, no answer, a redirect
(Flexible mode) or any body but the id turns the proxy off again. The check runs outside the writer
lock. The gateway's servers run with `strict_sni_host`, so a request's Host must be the name its
TLS handshake was for. With all of this, section 6.10 is built.

A grant can change tenants: admin `domain_transfer` with `name` and `tenant` moves it, for a name
filed in a personal tenant that belongs to a project. The grant keeps its id, so its certificate
lineage and DNS record stay and the name keeps resolving. Its request moves with it; the delegated
names the old tenant agreed to are dropped, so the new tenant's target is asked again, and an SRV
record goes at once, since it names the old tenant's port. The unused period starts over. It is refused while the grant has domains (the old tenant removes them first), and the new
tenant passes the same checks a request would, the grant itself aside.

**Zones**: admins add DNS zones with `zone_add`: the Cloudflare token, kept as a server secret, and
the tenants the zone is open to. Built: `zone_add` checks that the token sees exactly that zone
and can write (a TXT probe it removes at once), keeps the token in `zone_dir/<zone>.token` (0600,
never in the database, a result or the audit log) and the zone in the site table; calling it again
replaces the token and tenant list. `zone_list` shows the site's zone and the added ones;
`zone_remove` refuses while a name in the zone is granted or requested. A name belongs to the
longest managed zone it sits in, and its ACME challenge and grant record go to that zone. Outside
`winlab.tw` the slug and platform-label rules do not apply; the zone's own wildcard is never
granted, and its apex only as an exact name (in `winlab.tw` too, for the lab website). A zone may not overlap `winlab.tw` or another
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

### 6.11 Network model in AWS terms (issue #103, client VPN built)

carrel names its network objects after their AWS counterparts where one exists, and each tool
description says what differs. Members and agents already know the AWS model, so a request such
as "connect my machines to the lab network and route between my projects" needs no carrel
vocabulary. carrel stays a lab platform: no accounts or IAM, and no regions. Several clusters
become sites (section 8.4), carrel's counterpart of availability zones.

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
| Client VPN | built (`vpn_client_add`) | WireGuard, one endpoint per tenant |

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

**Client VPN** (built, issue #103; the rest of this section is design only). WireGuard on the first exit node, one
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
most 8 clients. This is the constant `vpnClientLimit` in `vpn.go`, not a quota dimension; the
`vpn_clients` dimension below is still planned. The lab's
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

### 6.12 Public IP per machine (issue #91)

The Elastic IP of 6.11. A member requests a dedicated public IPv4 address; once approved, the
tenant holds it and binds it to one machine, which is then reachable on the chosen ports of that
address and whose outbound traffic leaves from it. Other machines keep the shared address.

**1:1 NAT, as in AWS.** An AWS instance never holds its Elastic IP: the instance keeps its private
address and the internet gateway translates one to the other. carrel does the same on the first
exit node: in `carrel_ports`, DNAT of traffic arriving on the public interface for the bound
address to the machine's primary address, and SNAT of the machine's traffic leaving the public
interface to the bound address (that chain runs before `carrel_public`, whose rule SNATs every
other tenant to the shared address). The exit node holds each bound address on its public
interface as a deprecated /32 of scope link, so it answers ARP but never picks it as the source of its
own connections, and the ifreload of every SDN apply (which purges global addresses its files do
not list) keeps it; it records the addresses it added, and each one's machine, in
`/etc/carrel/public-ips.json` before it adds them and removes only those, checking that the
interface no longer holds one. An address that leaves or moves to another machine loses its
tracked connections (`conntrack -D`, every zone), since a NAT mapping outlives its rule.
`carrel-ports.service` puts the addresses back at boot. A node that is not the first exit node
drops every address its file records on reconcile, with their connections, so a change in the
order of `exit_nodes` leaves no second node answering ARP for them. The guest needs no change, the shared
VRF stays (6.11), and no anti-spoofing rules are needed. Routing the public address into the
guest (a second NIC or an extra address on `net0`) is not offered. carrel's own machines cannot
reach a bound address (the DNAT matches only the uplink), as there is no hairpin for it.

**Address pool.** NetBox holds the pool, not `config.json` or the code: the lab network team
assigns addresses to carrel there, and NetBox is where they track the range. The pool is every
active IP range in NetBox, in the global table, whose tenant is `netbox.public_tenant` and whose
role is `netbox.public_role` (defaults `Carrel` and `User`), less the shared address. Addresses of
that tenant outside such a range, such as the exit nodes' own addresses and the shared address,
are never handed out. An address that does not answer ARP is not free unless NetBox assigns it to
carrel. A site without NetBox sync, or with no such range, offers no public IPs. carrel reads the
ranges on each NetBox pass (a failed read keeps the last pool) and records each bound address as
an IP address it owns, with the length of its range, whose `nat_inside` is the machine's primary
address, so NetBox shows which machine holds it. A range that shrinks under a held address keeps
its binding working, but the address cannot be bound again and is not handed out once released. On B09 the range is `140.113.60.163` to `.165`
(2026-10-23).

**Objects and tools.** Like special ports, approval grants and the member applies.
`public_ip_request` (reason) creates a request; an administrator answers it with
`request_approve`, which takes the first free address of the pool for the tenant (an address at
which NetBox holds an object carrel does not own is not free: the approval names it), or
`request_reject`. `public_ip_bind` (machine, optional address, ports) points a held address at a
machine of the tenant; binding again moves it or changes its ports. A machine holds at most one.
`public_ip_release` returns the address to the pool; a release whose
reconcile failed is finished by releasing again. `public_ip_list` shows the tenant's
addresses and the free count, `machine_get` shows a machine's bound address, and `catalog_get`
shows whether the site offers them and how many are free. Deleting a machine unbinds its address
and the tenant keeps it, so a later machine with the same VMID inherits nothing. A suspended
tenant's addresses stop answering until it is active again. A pending or rejected request changes
nothing on the network. A binding survives restarts, resizes and snapshots. Approval is the
control on a scarce resource, so there is no quota dimension, no expiry and no automatic DNS
name (Loki, 2026-10-23); the member points a name at the address with `domain_request` or a zone
of its own.

**Filtering.** Traffic to a bound address still passes the guest firewall: a bound machine's
firewall gets an `internet` ipset (every IPv4 source except 10/8, 172.16/12, 192.168/16 and
100.64/10) and accepts it on the chosen ports (`tcp/N`, `udp/N`, at most 32) or on all of them;
the default is `tcp/22`. Its `network_access` toward other machines is unchanged. Egress limits
and abuse handling of 6.6 apply to the bound address too.

**Exit node.** The NAT rules live on the exit node, so each bound address follows the exit node
failover of #89: the address moves with the active node.

### 6.13 Site IPv6 (issue #142)

The lab and the campus have no IPv6. A lab member (N0Ball, AS214821) routes a /44 from his
own allocation; carrel routes it in over one WireGuard tunnel and gives each machine that asks a
public IPv6 address. This is site IPv6, not per-member "bring your own prefix": one site block,
one peer, no customer gateway objects. The block is configuration, so the site can be renumbered.

**Off by default, byte for byte.** A site file without an `ipv6` block produces exactly the files it
did before (tests/test_ipv6_off_golden.py): guest firewalls, host nft, sysctl, cloud-init. A site
with the block changes nothing for a machine that did not opt in.

```json
"ipv6": {"prefix": "2a14:7581:880::/44", "tenants": "2a14:7581:880::/48",
         "peer": {"endpoint": "<IPv4>:<port>", "public_key": "<WireGuard key>"}, "mtu": 1370}
```

`prefix` is the routed site block, a /32 to a /48. `tenants` is the tenant pool inside it, a /52 or
shorter, by default the block's first /48; the rest of the block (for the b09 /44: `881::/48`
infrastructure, `882::/48` VPN clients) is reserved. The control plane's `/etc/carrel/config.json`
gets the tenant pool as `ipv6_prefix`; with it,
`catalog_get` reports `capabilities.ipv6: true` and `machine_create` accepts `ipv6: true`.

**Addresses.** Tenant N has the block 12 bits longer than the pool whose 12 bits spell N in
decimal digits (a /60 from a /48 pool), and its network is the first /64 of that block; the rest
is room for more networks. A machine's address mirrors its IPv4 one: with a /48 pool,
`10.200.17.11` is `<pool>:170::11`, gateway `<pool>:170::1` (the EVPN anycast gateway, as for
IPv4). Static, from cloud-init (`accept-ra: false`) or `pct`
(`ip6`, `gw6`); the gateway sends no router advertisements. Each tenant VNet gets a second PVE
subnet with `snat 0`: the addresses are routed, never translated.

**Path.** The first exit node holds `wg-v6`, enslaved to `vrf_tenants`, with `AllowedIPs ::/0`
and the VRF's IPv6 default route through it. The whole site block is `unreachable` in the VRF
(route protocol 96), so traffic to unused addresses stops there instead of going back into the
tunnel. The VRF keeps the tunnel to tenant traffic: the hosts' own IPv6 never uses it. Its UDP leaves from the public address (fwmark
`0x60`, table 160) on port 31000, which no tenant VPN uses, and keeps the path open with a 25 s
keepalive, so `carrel_public` needs no new input rule. The tunnel's MTU is 1420 at most (1370 for b09); `carrel_tenant_host`
clamps IPv6 TCP MSS to the tunnel MTU minus 60, and the base guest chains let ICMPv6 Packet Too Big through.

**Filters.**
- `inet carrel_v6` on the exit node: from the tunnel, sources inside the site block are dropped (spoofing)
  and only opted-in machine addresses are reachable; into the tunnel, only those addresses leave.
- `inet carrel_tenant_host` on every node: IPv6 forwarding is global in Linux, so forwarded IPv6
  that enters or leaves anything but the tenant VRF and its links is dropped (management,
  `tailscale0`, other bridges). Neighbour discovery from guests to the gateway is accepted before
  the tenant input drop. The file is loaded before the forwarding sysctl is set.
- Guest firewall of an opted-in machine: `ndp: 1` (`radv: 0` stays), the machine's /128,
  `fe80::/64` and `::` in its ipfilter set (the nftables firewall adds no link-local to an explicit
  set), the two `::/0` drops removed, and IPv6 twins of the tenant rules: its own /64 out (not the
  gateway), its tenant's /64 in when `network_access` is `tenant`, the rest of the site block, ULA,
  link-local, multicast and loopback dropped out, and nothing in from the rest of the site block. Rules
  without an address already apply to both families (SMTP drop, port grants), so from the
  internet a machine takes SSH (unless `public_ssh` is false) and its open ports.
- `bridge carrel_nd` on every node: a guest's neighbour advertisements may name only its own
  address and its EUI-64 link-local. `ndp: 1` checks the source, not the target; without this a
  guest could answer for the gateway or a neighbour (the IPv6 form of ARP spoofing, which
  ipfilter stops for IPv4).

**Removal.** Dropping the `ipv6` block removes the tunnel, `carrel_v6`, the IPv6 subnets (one SDN
reload) and the forwarding sysctl; a node that stops being the first exit node removes its tunnel.

**Not yet.** Turning IPv6 on for an existing machine (its guest needs the address configured by
hand), more inbound ports than SSH, and a watchdog that withdraws the IPv6 default when the
tunnel is down (until then a dead tunnel is a black hole for IPv6, and clients fall back to IPv4
after their own timeout).

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
| CPU type `x86-64-v3` (AVX2, FMA; every node is an E5-2630 v4); `host` only with `nested_virt` | Machines can migrate between nodes |
| Balloon device on, with free page reporting; no target below the assigned memory | Memory the guest frees returns to the node, and the node learns what the guest needs (section 5.2); KSM stays off (`ksmtuned` is disabled in the node setup) |
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

`platform_power` (admin) turns the whole platform off and on for a planned outage: `shutdown`
stops every tenant machine gracefully and records which ones were running, `start` brings back
exactly those, and `check` repairs what a node boot can lose (path MTU cache, the tenant MSS
clamp, the infra CTs' MTU 1450; 2026-10-27 outage). A paused VM is shut down too, but a start
leaves it stopped and says so: its memory is gone. The restore list holds only what the
shutdown stopped (a failed shutdown is not listed), expires after 7 days, and a start keeps only
what it failed to start. While a platform job waits for a machine job, the operation names it
(`waiting_for`). Nodes and infra CTs stay up, so the tool keeps
answering. Both power actions need two calls: a dry run returns a confirm code that the real call
repeats, and the code changes when the machine list does.

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
- carrel-keys (issue #209) is the same kind of choice. The guest pulls its tenant's saved keys from
  `/internal/guest-keys` with its readiness token, so group members reach existing machines without
  the guest agent writing files. Each line is type, key and a `carrel:<member>` comment, never
  options. Installing it gives up this section's promise for that machine: whoever can save a key
  in the tenant gets in.
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
- **Names** (issue #182): a machine's `image` has two axes, scope and kind. A catalog image is
  bare (`debian-13`); a tenant's is `tenant:image:<name>` (a cloud image, `image_import`) or
  `tenant:iso:<name>` (an ISO, `iso_import`, which a machine gets through `iso`, never through
  `image`). The platform keeps no shared ISOs, so the catalog has one kind. The spelling from
  before, `tenant:<name>`, is still accepted and means `tenant:image:<name>`; stored machines
  are read either way and never migrated.
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

**GitLab (issue #265)**: `app_link` also takes a project URL, such as
`https://gitlab.com/group/subgroup/project`, on gitlab.com or on an instance listed in the operator's
`gitlab_issuers` (default: gitlab.com only). With overlapping issuers, such as `https://x.org` and `https://x.org/gitlab`, the longest that prefixes the URL wins. `protected_only` on a GitLab app accepts only tokens whose `ref_protected` is true, so pushing to an unprotected branch of the same name does not deploy; GitHub's token has no such claim, so the option is refused there. The app stores the issuer with the path, and a token
deploys only when its issuer is that issuer: anyone can run a GitLab instance and mint a token for
any `project_path`, so the path alone proves nothing. The verifier reads the instance's keys from
`<issuer>/oauth/discovery/keys` and maps `project_path` to the repository, `project_id` to the
pinned id, `ref_path` to the ref and `pipeline_source` (`push` or `web`) to the event. The returned
`workflow` is a `.gitlab-ci.yml` job with an ID token for carrel's audience that runs
`/apps/v1/deploy.sh`, the counterpart of `carrel-deploy`. `function_link` stays GitHub only.

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

**Pull mode (issue #266)**: `app_link` with `mode: pull` takes any clone URL (https, ssh or
`user@host:path`) and an optional `build` command, for Gitea, Bitbucket, a bare repository over SSH
or a repository without CI. carrel-deployd watches the branch with `git ls-remote` every minute, or
at once when the app's `webhook_url` is called. A new commit is fetched into
`/srv/apps/<app>/.carrel/build`, built and packed there by the app user, never by root, since git
and the build run code the repository controls. The build has the app user's rights, as the
running app does; install with `--user` of an account without sudo to keep both away from root. The agent uploads the result with its agent token
to `/apps/v1/agent/upload`, and from there it is an ordinary release: stored, switched, health
checked, `app_deploy` and `app_rollback` work as in push mode. A failed fetch or build is a
`failed` release with the last 8 KiB of its log and no artifact, and is not retried until the
branch moves or the webhook is called. Builds run beside the agent's poll loop, so a long build
does not hold up `app_deploy` or `app_rollback`. When carrel does not take an upload (429 or 5xx),
the agent builds the commit again after 1 minute, doubling up to 30. `app_webhook_rotate`
replaces a leaked `webhook_url`. In both modes the health check passes only when the app's unit
stays up with no restart for 3 seconds after a good answer, so another program on the same port
cannot pass it while the app crash-loops. The webhook carries no payload carrel reads: it only makes the agent check, and only
the linked branch of the linked URL is ever built. carrel never clones, so the control plane never
fetches a URL a member names. For a private repository the agent makes an ed25519 deploy key as
the app user and reports its public half, which `app_get` shows for the member to add as a
read-only deploy key. Push mode stays the default for GitHub and GitLab: it builds off the machine
and proves the source with OIDC.

**Version 1 limits**: one app per machine port; one machine per app.

**Self-hosted runners (issue #267)**: `runner_add` starts a GitHub Actions or GitLab runner on a
member's machine, so jobs build there with the machine's tools and quota instead of on hosted
runners. A job on it deploys an app unchanged: GitHub gives self-hosted jobs OIDC tokens with
`runner_environment: self-hosted`, and GitLab issues ID tokens from the server, not the runner.
carrel never holds a runner token. The result's `token_command` asks the forge for one with the
member's own `gh` or `glab` login and pipes it into the install line over SSH, so the token appears
in no tool call, no output and no command line on the machine (the script hands it to the runner
in an environment variable). Jobs run as the unprivileged user `carrel-runner`; GitLab uses the
shell executor, so the machine needs no Docker. A public GitHub repository is refused unless
`allow_public` is set, because a pull request from any fork could run code on the machine.
`runner_remove` returns the commands that stop the runner and delete it on the forge; a GitLab
runner made with a runner authentication token stays on GitLab after `gitlab-runner unregister`,
so the client deletes it by name.

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

### 7.11 Functions: wake on request

A function is a container image that carrel runs only while it has work. A sleeping function has
no process and uses no memory. A request wakes it from a snapshot in about 100 ms, and it goes
back to sleep when it is idle. The measurements behind the design are in
`docs/evaluations/2026-11-12-function-wake.md`.

Built so far (2026-11-12): `carrel-fnd` and `carrel-fn-init`, which are the router, the snapshot
build from a local Docker image, both instance modes, the idle stop, the clock on wake and the
writable overlay, and the jailer around every Firecracker process. They run by hand on one test
host. A function has a route to the internet behind the egress filter. Images come from a
registry without credentials, or from a `docker save` tarball, with no Docker daemon. The control
plane and the MCP tools are connected since (below). The three
limits required before tenant code runs on a function host are built: disk use (issue #225),
traffic (issue #229) and a guard that keeps the rules loaded (issue #230).

**Why carrel offers it**

- A webhook, a scheduled script or a small API no longer needs a machine that is patched,
  monitored and mostly idle.
- Each instance is a microVM, a small virtual machine with its own kernel. That boundary is
  strong enough for code the tenant does not trust, such as code an agent wrote a minute ago.
- An agent deploys with one tool call and gets a URL back.
- A function can run for an hour and can call the lab's own services by their public names. AWS
  Lambda stops at 15 minutes and cannot reach the lab.

**Contract**

- An OCI image for `linux/amd64` that serves HTTP on `$PORT` (default 8080). carrel honours the
  image's entrypoint, command, environment and working directory, and does not change the image.
- A function keeps no state. Every instance starts from the snapshot made at deploy time. The root
  file system is read-only under a memory-backed overlay, so writes work and are gone when the
  instance stops.
- This is the contract of Cloud Run and Knative. The same image runs on AWS Lambda with the AWS
  Lambda Web Adapter. carrel does not implement the Lambda Invoke API or Runtime API, so a move
  to AWS changes where the image runs and nothing inside it.

**Deploy**

1. The member's agent calls `function_deploy` with a name and an image reference. A repository can
   also deploy on every push through `NYCU-WinLab/carrel-deploy@v1` with the same OIDC checks as
   apps (section 7.9).
2. A function host pulls the image without a Docker daemon and flattens it into an ext4 root file
   system. It adds `fn-init`, a small static program that becomes process 1, prepares mounts and
   the network, and starts the image's command as the image's user. The image is the tenant's
   and may be hostile, so its files are never unpacked on the host: the flattened tar stream goes
   straight into the file system image (`mkfs.ext4 -d`, which needs libarchive). Paths that leave
   the root fail the build, devices are dropped, and the image cannot bring its own `/.fn`.
3. The host boots the microVM and waits for readiness: any HTTP answer below 500 on the port
   within 60 seconds, the rule apps use.
4. It pauses the microVM, writes the snapshot and stops it. The function is now `asleep`.
5. A version is one image digest. carrel keeps the last 3. `function_rollback` switches to the
   previous one without a new build.

Measured from image to `asleep`: 10.4 seconds for a 118 MB image, 33.5 seconds for a 945 MB image.

**Wake**

1. The gateway sends a request for the function's name to the router on a function host.
2. If no instance is awake, the router restores the snapshot into a new network namespace. The
   tap device there carries the MAC address the snapshot expects.
3. The router hands the current time to `fn-init`, which sets the guest clock. A restored guest
   otherwise reads the time of the snapshot.
4. If the function declared a `wake_path`, the router calls it once. This is where a function
   reseeds random state it keeps in user space, which is identical in every restore.
5. The router forwards the request and holds the instance awake while requests arrive.
6. After `idle_seconds` (default 300) without a request, the router stops the instance.

**Instance modes**

- `reuse` (default): one instance serves concurrent requests until it is idle. For web services
  and APIs.
- `fresh`: every request gets its own instance, which is destroyed after the answer. For untrusted
  code and job runners, where one request must never see the memory or files of another.
  At most 10 instances per function run at once in version 1.

**Triggers**

- HTTP: `domain_add` accepts `function` in place of `machine` and `target_port`. Webhooks are
  HTTP.
- Schedule: `schedule` is a cron expression in the site's time zone. The control plane sends a
  POST to the function. A missed run is not repeated.
- Queues and platform events are not in version 1.

**Isolation**

- Instances are Firecracker microVMs started through its jailer (a private root directory, a
  system call filter, a cgroup and an unprivileged user). Each slot has its own user ID, so one
  Firecracker process cannot signal or read another.
- They run on function hosts: platform-owned VMs with nested virtualization in the infra range.
  An escape from a microVM lands in a function host, not on a node. A function host holds one
  token that reads function versions and nothing else.
- Each instance has its own network namespace. It may reach the internet and public names. Private
  ranges and platform addresses are dropped, so a function reaches a tenant machine through that
  machine's public name or port (open decision 18). IPv6 is dropped. A function host needs
  `nftables`, and no other firewall on it may drop forwarded packets by default. It is a
  dedicated machine: the daemon turns on IPv4 forwarding for the whole host.
- The promise of section 7.7 does not cover functions. carrel runs the code, so the platform
  holds the image, the environment and the snapshot, and a snapshot contains the memory of the
  process. Admin reads of them are audited and visible to the tenant in `audit_log`.

**Environment and secrets**

`function_env` returns a single-use upload link, valid for 15 minutes. The agent pipes an
environment file to it (`PUT /functions/v1/env/<link>`), so values never appear in tool
arguments, in the audit log or in a transcript. The control plane stores them encrypted with
AES-256-GCM under `function_env_key` of the configuration, bound to the function. A change of
environment builds a new version from the current one, because the values are part of its
snapshot; each version keeps the environment it was built with, so a rollback brings back its
values, and a deploy keeps the function's environment. `clear` builds a version without one.
The desired state only marks a version that has an environment (`has_env`); the host
fetches its values from `GET /functions/v1/agent/env` when it builds that version, and writes
them into the version's root file system, never into `function.json`. `function_get` shows the names only. Snapshots stay on
function hosts and are deleted with their version. `function_env_old_keys` lists earlier keys that
still open values; new values are sealed with `function_env_key` only. A value no key opens
answers 409, and the host fails that version instead of asking again.

**Limits and quota**

- Per function: 128 to 2,048 MiB of memory (default 512), 1 vCPU, `timeout_seconds` default 300
  and at most 3,600, image at most 2 GB.
- Per tenant: `functions` (default 20) and `function_gb` (default 20), which counts the root file
  systems and snapshots of kept versions.
- Awake instances are not charged to a tenant. They share the memory of the function hosts. When
  a host runs short, the router first stops the idle instances used least recently, then answers
  503 with `Retry-After`.

**Observability**

- Each wake is a span in sensorium with function, version, mode, restore time and whether the
  snapshot came from the page cache.
- The platform captures standard output and standard error, keeps the last 10 MB per function
  and returns it through `function_logs`. Apps keep their logs inside the machine; functions have
  no machine to keep them in.
- `function_get` reports state, the URL, versions and the p50 and p95 wake time of the last
  24 hours.

**Measured on 2026-11-12** (nested virtualization, 1 vCPU, from process start to the first HTTP 200)

| Workload | Snapshot restore p95 | `docker start` p95 | Cold boot p95 |
|---|---:|---:|---:|
| Python function, 512 MiB | 104 ms (223 ms from disk) | 1,611 ms | 3,026 ms |
| Headless browser, 1,024 MiB | 913 ms (2,178 ms from disk) | 1,811 ms | 6,421 ms |

Thirty restored copies of the Python function added 16 MiB each, because copies share every page
they have not written.

**Targets**

- Wake p95 under 300 ms for a function that touches less than 50 MiB in its first request.
- From image to `asleep` under 15 seconds for a 200 MB image.
- At least 50 sleeping-but-recently-used functions kept in the page cache of one 8 GiB host.

**To solve before the build**

- Large first requests. The browser function touches 221 MiB one page at a time. Record the pages
  of the first request at deploy time and read them in one pass at restore. The target is the
  300 ms above.
- Snapshot portability. A snapshot depends on the CPU model and the Firecracker version (open
  decision 19). A Firecracker upgrade rebuilds every snapshot from its root file system.
- The writable overlay was not part of the measurements.

**Version 1 limits**: HTTP and schedule triggers only. No GPU, no persistent disk, no attachment
to tenant networks, one instance per `reuse` function.

**Build order**

1. A function host image and the router, with `fresh` and `reuse`, on one host. The router is
   built. Measured through it on the test host: a request that wakes a `reuse` function p95
   162 ms (15 runs), a `fresh` request p95 168 ms (30 runs), a request to an awake function p95
   3 ms (200 runs). The jailer is built: each instance has its own user, root directory, mount,
   PID and network namespace, a seccomp filter, no capabilities, and a cgroup that limits memory
   to the guest's memory plus 128 MiB and processes to 64. Function files are owned by root and
   read-only to the jails' group, because every instance of a function maps the same snapshot. A
   build's snapshot is taken out of the jail only after its Firecracker process ended. With the
   jailer the same requests measure p95 176 ms, 192 ms and 3 ms. The egress filter is built:
   each slot has a link to the host numbered out of `10.251.0.0/16`, and the private, link-local,
   carrier NAT, loopback and multicast ranges are dropped in the instance's namespace and again
   on the host, with the site's protected addresses and TCP port 25, as for tenant machines
   (section 6.6). Only tracked packets from the guest's one address are forwarded, so a forged
   source or a packet that skips address translation does not leave. Functions leave through one
   named uplink. The host accepts nothing from a function, and a namespace starts nothing of its
   own. A slot's namespace is made new after every instance, so no connection of the last
   instance leads to the next one. The guest gets the uplink's MTU and public resolvers at
   build time. Making the namespace new costs the `fresh` mode on a 1 vCPU host: p50 went from
   172 ms to 234 ms. The disk limits are built: the serial console goes through a pipe into a
   log capped at 5 MiB, every jail directory but a build's output is root's, a build writes to
   its own file system the size of its memory plus 64 MiB, Firecracker may grow no file past
   1 MiB and writes no core file. The traffic limits are built: each instance is shaped to
   100 Mbit/s in both directions (`-rate`), and the guest's packets are policed where they
   enter, so an answer to the router is limited too. An instance holds at most 512
   connections, opens at most 200 new ones a second and sends at most 20,000 packets a second.
   Ended TCP connections and UDP flows time out in 10 to 30 seconds, and the guard trims a
   slot that still holds more than 3,000 entries. A slot's entries in the host's table are
   deleted before the slot is used again. The host needs `conntrack` (conntrack-tools). The
   guard checks every slot's rules every 5 seconds, and `carrel-fnd serve` refuses to start
   when the host's table differs from the expected one. Still open in this step: the host
   image, issues #234, #236 and #239 to #243. Measured on
   the test host: 40 requests at once to a sleeping `reuse` function all answer 200 from one
   instance, and a stop under 30 `fresh` requests leaves no microVM, namespace, link or cgroup.
2. The deploy pipeline and the member tools. The host agent is built: `carrel-fnd serve
   -control <url>` asks the control plane for the host's desired state with the host's one
   token (`GET /functions/v1/agent/state`, a 30 second long poll), builds the versions it lacks
   one at a time, puts each function's current version live, removes the functions and versions
   the state no longer names, and sends its whole inventory after every pass
   (`POST /functions/v1/agent/report`): each version is ready, with its disk use and image
   digest, or failed, with the error. A failed build is tried again after 1 and then 5 minutes,
   so a registry hiccup does not fail the version; the third failure does. Both sides are
   level-triggered, so a lost report or a
   restart heals on the next pass. A function is named `t<tenant>-<name>` on a host. The
   control plane decides which version is current; the host never activates a build on its own.
   The functions' directory must be on a file system without `nodev`, or no tap device opens.
   The control plane side is built: `function_deploy`, `function_get` (with `wait_seconds`, the
   way an agent follows a build), `function_list`, `function_rollback` and `function_remove`,
   the quota `functions` and `function_gb`, and the two agent endpoints, reached only from the
   infra network with a host token whose SHA-256 is in `function_hosts` of the configuration.
   A deploy makes version `v<n>` and returns at once; the host's report makes it current, or
   records its build error and leaves the current version live. `function_logs` reads the
   tail of a function's output, or of its builds, from its host: the agent collects the request
   on a second long poll (`GET /functions/v1/agent/logs`) and posts the answer, so carrel still
   never connects to a host and keeps no log. Each line starts with the time the host read it,
   which `since_seconds` filters on; Firecracker's own log is limited to errors so that the log
   holds the function's output. `function_env` sets the environment through a single-use
   upload link (see Environment and secrets). `function_registry` takes credentials for a private
   registry the same way: a single-use link, sealed on the function and bound to one registry
   host. The desired state marks a version whose image is on that registry (`has_auth`), the host
   fetches the credentials from `GET /functions/v1/agent/auth` to pull it, and an image on any
   other registry is pulled without them.
   The image pull is built: 5.6 seconds for
   `traefik/whoami` from Docker Hub, 6.7 seconds for the 118 MB test image from a tarball, both
   from image to `asleep`.
3. Gateway routes, domains and the OIDC deploy action. The deploy action is built:
   `function_link` binds a repository branch to a function and returns a workflow that builds
   the image, pushes it to ghcr.io and runs `NYCU-WinLab/carrel-deploy@v1` with `function` and
   `image`. The action sends the image by digest to `POST /functions/v1/deploy/<tenant>/<name>`
   with the job's OIDC token, checked as for apps (section 7.9), including the pinned
   repository id. carrel builds a version from the current version's settings and environment
   with that image and records the commit; the action polls
   `GET /functions/v1/deploy/<tenant>/<name>/<version>` until the version is live, failed, or
   superseded by a newer one. The workflow runs one deploy at a time per function. The gateway
   sends the public function paths (`env`, `registry`, `deploy`) to carrel, never the host
   agents' paths.
4. Schedules, logs, quota and sensorium spans.
5. The AIntern job runner as the first tenant, in `fresh` mode.

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

### 8.4 Several sites

A host that cannot meet 8.3 is a separate site with its own cluster. Sites never share a corosync
ring. One control plane manages every site, and each site runs a site agent: it connects out to
the control plane, pulls the desired state, applies it to its own Proxmox and reports the actual
state. The site agent is one process per node (8.6), because each node applies its own firewall
and units. With the control plane away, a site keeps running what it last received. Sites come in two
kinds:

| Kind | Run by | Trust | Who places machines there |
|---|---|---|---|
| Lab site | lab admins (B09, and later GPU, DPU or dev clusters, issue #217) | trusted like B09 | any tenant the site's access rule allows |
| Private site | the member who owns the hardware (issue #568) | untrusted: its owner has root | only the owner's tenants; the quota it adds counts only there |

A private site joins through a WireGuard gateway to a lab site, and the lab site treats its traffic
as external. Its public entry either goes through the lab site's address, which needs an admin's
approval and can be revoked at the lab gateway, or through the owner's own address, which carrel
only records. A lab name such as `*.winlab.tw` always needs approval. The address plan and the
trust model for both kinds are decided in issue #567. Until a second site exists, a tenant's
machines stay in one site.

### 8.5 Core and plugins

The core is what every site must run: machines, images, tenant networks and isolation, tenants,
quota, requests, keys, audit, capacity and reconcile. Every other feature is a plugin that runs next
to the site agent. A site reports which plugins it runs and what each one needs (a capability), and
a tool whose plugin a site lacks fails there with a message that names the sites that have it. The
plugin contract is in issue #564.

| Group | Tools | Core or plugin | Needs from a site | Coupling to the core today |
|---|---|---|---|---|
| Machines | `machine_create`, `_list`, `_get`, `_delete`, `_power`, `_resize`, `_rename`, `_access`, `_metrics`, `_media`, `_console_url`, `_nic_attach`, `_nic_detach` | core | Proxmox | not applicable |
| Images | `image_import`, `_list`, `_delete`, `iso_import` | core | storage for images | not applicable |
| Tenant networks | `network_create`, `_list`, `_delete`, `deployment_plan`, `deployment_apply` | core | the EVPN and VXLAN zones | not applicable |
| Tenants and quota | `whoami`, `quota_get`, `quota_request`, `quota_set`, `request_*`, `tenant_*`, `ssh_key_*`, `audit_log`, `usage_report` | core | nothing | not applicable |
| Operations | `catalog_get`, `capacity_get`, `operation_get`, `operation_retry`, `reconcile_run`, `node_list`, `platform_power` | core | nothing | not applicable |
| Snapshot | `snapshot_create`, `_list`, `_delete`, `_rollback` | plugin | ZFS or LVM-thin | medium: capacity (`capacity.go`, `nodes.go`) and quota (`snapshot_gb` in `platform.go`) read snapshot sizes, and `migrate.go` checks for snapshots |
| Freeze | `machine_freeze`, `machine_thaw` | plugin | a Proxmox Backup Server | high: the gateway keeps a frozen machine's names as 503 routes (`gateway_sources.go`), and `execute.go` and `operations.go` hold freeze steps |
| Migrate and drain | `machine_migrate`, `node_drain`, `node_undrain` | plugin | 2 or more nodes | low: placement skips drained nodes (`nodes.go`), `admin.go` routes the tools |
| Public entry | `domain_*`, `port_*`, `public_ip_*`, `vip_*`, `zone_*` and IPv6 | plugin, installed on every lab site | a public address | high: `network.go`, `intent.go` (`deployment_apply`) and `freeze.go` all build entries |
| Connectivity | `vpn_client_*`, `peer_*`, `machine_ca_backfill` and the jump host | plugin | a gateway; the lab SSH CA | high: `platform.go`, `machine_access.go` and `netbox.go` read it |
| Deploy | `app_*`, `runner_*`, `function_*` | plugin | apps: none; functions: a function host | medium: apps and functions publish through public entry (`domains.go`, `gateway.go`) and have their own config |
| NetBox sync | none (background) | plugin | a NetBox | low: `public_ips.go` and a few hooks |

Coupling counts how many core files name the feature (grep of `internal/carrel`, 2026-11-25). Low
coupling moves first. Snapshot is still the first plugin, because its long operation tests the
operation shape of the contract (issue #564). Freeze goes second: a frozen machine keeps its names
as public entry state, so the contract must let one plugin ask another to hold state.

### 8.6 Site agent protocol (issue #560)

**Today.** The control plane reaches hosts through one seam, `Backend.Call` in `backend.go`: it runs
`ssh <target>` with a JSON request on stdin, and a forced command runs `node-agent.py` as root
with a closed set of ops (about 40: reads such as `inventory` and `status`, writes such as
`create`, `action` and `reconcile`). A call goes to the machine's node, or to the first exit node;
the gateway and the jump host have their own sync scripts. Go has no other path to a host.
Constraints the agent has to keep, found in the code (2026-11-25):

| Constraint | Where | What the agent has to do |
|---|---|---|
| Calls run up to 4 hours (`migrate`, `freeze`) and up to 3 hours for a `create` that imports a disk; `create` and `action` run while the control plane holds its writer lock | `backend.go`, `operations.go` | carry an operation id, survive a reconnect mid-call, and answer the same id twice with one result |
| Only `create` and `action` carry a `request_id` with a node-side journal; its key stays the same when a failed operation is retried, so it cannot stretch to every write | `node-agent.py`, `platform.go` | stop a job delivered twice by its job id, not by `request_id` (#602 closed) |
| Reconcile is per node: every node writes its own nft files and units; only the first exit node runs fetch, DHCP and the guest firewall files | `network.go`, `node-agent.py` | run on every node, not one per site |
| The node keeps `desired.json` but nothing replays it at boot; private DHCP namespaces live in `/run` and come back only with the next reconcile | `node-agent.py` | store the desired state with a revision, replay it at boot, report the revision applied |
| The control plane dials into the site network: readiness probes to machine addresses, guest reports to 10.200.0.3, the gateway's `/gateway/ask` | `lifecycle.go`, `server.go`, `gateway.go` | stays for a lab site, where the control plane sits in the site network; a private site needs the agent to proxy these |
| The jump host drops its lab certificate map after 30 minutes without the control plane | `jump-cert.py` | accepted: a site without the control plane loses new lab certificates, not machines |

**Design.**

1. **Unit.** One `carrel-agent` per node, wrapping `node-agent.py`, so the closed op set and its root
   checks stay as they are. The site agent of 8.4 is the set of its nodes' agents; site-wide ops
   still go to the first exit node. One process per site would have to reach the other nodes
   itself, which is the SSH path again.
2. **Transport.** The agent connects out over HTTPS and long-polls for jobs, as `carrel-fnd` does
   (`GET /sites/v1/agent/jobs`). A job carries an id, the op and its request; the agent posts the
   result to `POST /sites/v1/agent/jobs/{id}`. A job id is unique per dispatch, and the agent
   keeps each job's result until the control plane acknowledges it, so a job delivered twice
   after a reconnect runs once. The agent runs jobs concurrently, as SSH calls run today, so a
   4 hour `migrate` does not hold up `status` or `inventory` on the same node. The control plane
   waits for the result with the timeouts it uses today, so the writer lock and the operation
   phases do not change in the first step.
3. **Identity.** The agent runs root ops it pulls, so it must know whom it talks to: it speaks
   HTTPS only, to a control plane certificate under a CA it pins, in every mode. Tenant machines
   can reach 10.200.0.3, so plain HTTP is never allowed. The agent signs in with a short-lived
   client certificate from the lab step-ca, bound to one node and one site; until that lands, with
   a hashed bearer token and a fixed source address, as `carrel-fnd` does. A node that uses the
   agent has no `authorized_keys` line for the control plane.
4. **Versions.** The first request carries `protocol: "v1"`, the agent's release and its capabilities
   (#561, #562). The control plane serves the current and the previous protocol version.
5. **Durable state.** The agent stores each reconcile request with its revision, replays the last one
   at boot, and reports the applied revision in `inventory`.
6. **Rollout.** A per-node setting `transport` (`ssh` or `agent`) picks the path; the default is `ssh`.
   B09 moves one node at a time with no machine change; the SSH path goes after the last node.
   The release archive ships `carrel-agent` with the other node programs (#565).

Console streams, the gateway sync, the jump host sync and the off-site backup also use the
control plane's SSH key today. They move off it in their own issue (#606) before the key goes
(#604).

## 9. Observability

### 9.1 Signals

| Source | Path | Consumer |
|---|---|---|
| Node and guest metrics | Proxmox OpenTelemetry metric server (cluster-wide in `/etc/pve/status.cfg`) to sensorium | admin agents via sensorium MCP |
| carrel control plane | WARN and ERROR log records as they happen, each node's admission view once a minute, and one span per tool call (tool, tenant number, outcome code; the duration is the span's own), as OTLP/HTTP JSON to the collector in `telemetry_url` (built 2026-11-17, no SDK) | admin agents |
| Host journald, Caddy, Keycloak | an OTel Collector (journald receiver, Prometheus scrape) to sensorium | admin agents |
| Tenant view | `machine_metrics` reads Proxmox RRD data, `audit_log` reads the database | the tenant only |

sensorium accepts OTLP over HTTP only (JSON or protobuf, no gzip, no gRPC), which is why the
Collector sits in front of anything that speaks another format. Its MCP token reads every project,
so tenants never get it. Machine insides are the tenant's business and are not collected.

The control plane's gauges carry a `node` attribute and hold what the Proxmox metric server does
not export:

| Metric | Meaning |
|---|---|
| `carrel.node.reachable` | 1 when the control plane read the node's inventory, 0 when it could not |
| `carrel.node.vcpu.committed`, `.limit` | admission's vCPU count and ceiling |
| `carrel.node.memory.committed`, `.limit` | the same for memory, in bytes |
| `carrel.node.disk.committed`, `.limit` | the same for disk, in bytes |
| `carrel.node.storage.utilization` | real use of the node's pool, 0 to 1: the watermark of section 5.2 |
| `carrel.node.snapshot.counted`, `.declared` | what admission counts for snapshots, and the sum of their disks' sizes |
| `carrel.node.memory.utilization` | real use of the node's memory, 0 to 1 |
| `carrel.node.guest.running`, `.reporting` | the node's running Carrel VMs, and how many of them report their memory through the balloon device |
| `carrel.node.guest.memory.assigned`, `.needed` | for the VMs that report: the memory they were given, and that minus what their kernels could still hand out. One sum for the node, never one machine |

A failed operation is logged at INFO only when the member can fix it: the codes `invalid`,
`not_found`, `forbidden`, `quota_exceeded` and `conflict`. `capacity_exhausted` and
`guest_not_ready` are WARN. Everything else is ERROR: any other code, an error that is not a
refusal, and any refusal whose `recovery` is `retry_infrastructure` or `contact_administrator`.
The sender never blocks the control plane: a full queue drops records, one message leaves at most
20 times a minute, and its own failures stay on stderr. B09 sends to the sensorium instance its
alerting service reads.

### 9.2 Reconciler

A loop compares the database with Proxmox, firewall, NAT, private DHCP, DNS and Caddy every 5 minutes and
at boot. It repairs drift it owns and reports drift it does not understand. `reconcile_run` triggers
it on demand.

### 9.3 Alerts

sensorium only answers queries, so a separate alerting service reads it and notifies the admins.
B09 uses golem, which sends to Telegram (2026-11-17; no email sender was built).

| Alert | Signal |
|---|---|
| A node's pool passes a watermark | `carrel.node.storage.utilization` above 0.7 is a warning and above 0.85 an error |
| Node memory saturated | `carrel.node.memory.utilization` above 0.9 |
| A node the control plane cannot read | `carrel.node.reachable` below 1 |
| Reconciler drift it could not repair, backup failure, certificate failure | the ERROR log records, such as `reconcile_failed`, `gateway_config_rejected`, `backup_failed` and `certificate_issuance_failed` |
| Admission out of room, a guest that did not come up | the WARN record `operation_failed` with `code` `capacity_exhausted` or `guest_not_ready` |
| Freshness | no new data for 10 minutes. Healthy services with stale data are the failure mode seen before |

Nothing acts on a watermark by itself yet: an admin moves machines with `machine_migrate` or asks
owners to free space. Quorum loss is not watched.

The telemetry is also the heartbeat for a site that is down: the collector and the alerting
service run outside the site, the control plane sends every minute, and 10 minutes of silence is
the alert.

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
| `tunnel_group` | name of an existing NetBox tunnel group for the client VPN tunnels (issue #184, phase 2). Empty, the default, leaves WireGuard out of NetBox: no tunnel, no interface, and the token needs none of the permissions below for them. The NetBox operator creates the group and gives it carrel's owner; carrel only reads it, so installations that share a NetBox each name their own. A missing group fails the tunnels with an error and creates nothing; what NetBox already holds stays |
| `tenant_group` | name of an existing NetBox tenant group that every carrel tenant joins. Empty, the default, leaves tenants out of a group. Set it when the token's tenant permission is constrained by the group's owner (`group__owner__users`): a tenant outside the group is then refused. The NetBox operator creates the group; a missing one fails tenants and VNIs with an error and creates none |
| `subject_field` | name of a text custom field on NetBox tenants that receives the tenant's Keycloak subject: `user:<sub>` for a personal tenant, `winlab-projects/<name>` for a project tenant. Empty, the default, leaves it unset. With it, one NetBox permission constrained by `custom_field_data__<field>__in` (or `tenant__custom_field_data__<field>__in` on tenanted objects) shows members their own tenants; NetBox fills the list from the portal developer API at sign-in. The NetBox operator creates the field |
| `vrf` | name of the shared VRF, default `Carrel`; a private network's VRF is `<vrf> <Tenant> <network name>` (`Carrel Alice back`). A VRF that carrel created under the old form (`carrel-alice-back`) is found by that exact name and renamed in place |

Mapping:

| carrel | NetBox |
|---|---|
| machine (VM and CT) | virtual machine `<machine>.<tenant>` in the cluster; vCPU and memory (MiB) from the spec; `active` when running, `planned` while provisioning, otherwise `offline`; `start_on_boot` follows Proxmox `onboot`, which is set by the owner's last power action (`on` after a start, `off` after a stop, pause or tenant suspension), so a guest that shuts itself down stays `on`; a machine with no recorded action is `on` when running; the description says VM or CT; the VMID goes into `vmid_field`; the device is the cluster device whose name, or `device_field`, matches the Proxmox node, none when there is no such device |
| image | platform created and deleted by carrel. The name starts with `Carrel: `: `Carrel: Debian 13` for a platform image (shared by all tenants) and `Carrel: Alice/base` for a tenant image and `Carrel: Alice/base (ISO)` for a tenant ISO (one per tenant; an image and an ISO of one name can both exist, and NetBox keeps names unique, so the ISO says so). The slug keeps them apart and starts with `carrel-` so it cannot meet a platform made by hand: `carrel-catalog-debian-13`, `carrel-alice-tenant-base`, `carrel-alice-iso-win11` (the label in lower case with other characters as `-`); a platform with that slug that carrel did not create is an error. A platform from before the prefix is found by its old slug and renamed in place. NetBox keeps platform names unique, so a platform made by hand with the same name, which the prefix makes unlikely, fails the machines of that image until it is renamed; the error shows in `machine_get` |
| machine disk | one virtual disk in MiB, named by its Proxmox volume (`local-zfs:vm-10100-disk-0`), which a node reports at creation and migration and `reconcile_run` collects for older machines; `scsi0` (VM) or `rootfs` (CT) until then. NetBox sums it into the machine's disk |
| NIC MAC | MAC address object assigned to the interface and set as its primary MAC |
| primary NIC and each extra NIC | VM interface `eth0`, `eth<index>` |
| machine address, managed NIC address | IP address on its interface, in the shared VRF (a private network's address in that network's VRF); the machine address is the primary IPv4, with DNS name `<machine>.<tenant>.internal` as the infra resolver answers it |
| tenant segment `10.200.N.0/24` | prefix in the shared VRF |
| managed private network CIDR | prefix in that network's own VRF |
| client VPN range `10.201.N.0/24` | prefix in the shared VRF, while the tenant has a client |
| client VPN client (`vpn_client_add`) | IP address `10.201.N.x/32` in the shared VRF, bound to no interface, description with the client name and the day it expires; an expired or removed client leaves with its record |
| tenant's client VPN interface `wg-tNNN` (with `tunnel_group`) | tunnel `wg-tNNN` in that group while the tenant has a client: encapsulation WireGuard, `active`, the description names the tenant and the endpoint `<public_address>:<31000+N>`. One per tenant, not one per client, because the interface is the tunnel and the clients are its peers |
| that tunnel after the tenant's last client leaves, while the operator's own ends (spokes) are still on it | the tunnel stays, status `decommissioning`, until the spokes leave; a new client sets it `active` again (issue #201). A changed `tunnel_group` moves the tunnel, found by name |
| the exit node's side of that tunnel | interface `wg-tNNN` (type virtual, owned by carrel) on the NetBox device of the first node, found like a machine's device, and a hub tunnel termination on it. A first node with no device fails the tunnel's end only: the tunnel stands without it |
| tenant | tenant `Carrel: <Tenant>`, slug `carrel-<tenant>`, that every prefix, address, virtual machine, L2VPN and private network VRF of the tenant carries (issue #181); the shared VRF belongs to no tenant; one with that slug carrel did not create is an error |
| primary network VNI `100000 + N`, private network VNI `200000 + N * 100 + k` | L2VPN `tNNN.<tenant>` of type `vxlan-evpn`, and `pNNNkk.<tenant>` of type `vxlan`, with the VNI as identifier and the tenant set, so a VNI seen on the wire leads to its tenant and network (issue #181). A token without the tenancy and L2VPN permissions syncs the rest without a tenant and reports one error |
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
2. Deletion goes dependents first: services, tunnel ends, memberships, IPs, interfaces, VMs,
   tunnels, exit node interfaces, groups, prefixes, VRFs, because NetBox refuses to delete a referenced object.
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
| tenancy.tenant | yes | yes | yes | yes |
| tenancy.tenantgroup (with `tenant_group`) | yes | no | no | no |
| vpn.l2vpn | yes | yes | yes | yes |
| vpn.tunnel (with `tunnel_group`) | yes | yes | yes | yes |
| vpn.tunnelgroup (with `tunnel_group`) | yes | no | no | no |
| vpn.tunneltermination (with `tunnel_group`) | yes | yes | no | yes |
| dcim.interface (with `tunnel_group`) | yes | yes | yes | yes |
| virtualization.cluster | yes | no | no | no |
| users.owner | yes | no | no | no |

A child object is also constrained by its parent's owner, so it cannot be bound to a foreign parent. Interfaces and virtual disks add their machine's cluster (`virtual_machine__cluster__owner__users`), addresses and prefixes add their VRF (`vrf__owner__users`), each next to their own `owner__users` in the same constraint, because NetBox requires every key of one constraint. FHRP group assignments have no owner, so they have only their group's (`group__owner__users`). A tunnel adds its group (`group__owner__users`) next to `owner__users`, so carrel manages tunnels only in a tunnel group that carries its owner. A tunnel termination has no owner either, so it has only its tunnel's and the tunnel group's (`tunnel__owner__users` and `tunnel__group__owner__users`), and carrel deletes one only when its tunnel is carrel's. The exit node's interface is a device interface carrel creates on a device that is the operator's, so it has only its own `owner__users`: NetBox cannot say that it belongs on that one device. Turning `tunnel_group` off stops the sync of tunnels without deleting them; the NetBox operator removes them. An owner that names user groups needs a second constraint with `__user_groups__users` in place of `__users` in every key, because NetBox accepts any one of several constraints.

## 10. Maintenance

### 10.1 Backups

Proxmox Backup Server on a separate machine. Priority: the carrel database and Keycloak client
configuration, then infra machines, then tenant machines (opt-in, counted against quota).

Tenant machines are backed up only to be frozen (issue #190). `machine_freeze` takes a stopped
machine with no disk snapshots and none of the resources on the site's `freeze_release` list
(default: bound public IPs, fixed public ports, special domains), runs `vzdump` to the
PVE storage named by `backup_storage` in the carrel config, waits until PBS reports the backup verified
(a missing or pending result keeps the machine), marks the backup protected (after the verification:
PBS refuses the flag while it verifies a new snapshot), and only then deletes the machine. The copy runs
outside the writer lock, like a migration: the request is planned under it, the node works without it,
and the records change under it again after checking that the machine is still stopped. The machine's
row moves to the `frozen` kind: its VMID, name and internal address stay taken, so the domains,
ports and peers that point at it stay meaningful, and `vcpu`, `memory_mb`, `disk_gb` and `machines`
are released. `machine_thaw` checks the normal quota like a creation, restores the backup to the
same VMID on a node chosen as for a creation, which is kept in the frozen row so a retry or a delete
finds a half-restored machine; the backup goes only after the live row is committed. `machine_delete` on a frozen
machine removes the backup. Frozen machines keep one copy on PBS: freezing is not an off-site backup.
A freeze backup is told apart by its notes, which name the site (`carrel-freeze <site> <operation>`, #202:
two sites may share a datastore and a VMID), and is reused by a retry only while the node's stamp proves
the machine has not run or changed since; scheduled backups of the cluster are never read, counted or
removed. Before a new backup the node asks the backup server whether the datastore verifies new
snapshots and refuses at once if it does not. The site may cap frozen disk space across all
tenants with `frozen_total_gb`. Admin `reconcile_run` sweeps freeze backups that no frozen row,
thawed machine or running freeze names: it lists this site's and removes those older than 7 days.
Scheduled backups of running machines stay out of scope.

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
  `x86-64-v3` unless the owner asks for `nested_virt`.
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
| sensorium-winlab 202 | infra (`N = 0`) | carrel's own telemetry was to go there; since 2026-11-17 it goes to sensorium-zyx, which the alerting service reads (section 9.1) |
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
- IPv6 from the campus (open decision 13.6); a member's routed /48 over a tunnel is 6.13.
- Machines spanning sites, live migration across sites.
- A web UI, apart from the machine console page (section 7.8).
- Builds inside carrel. Apps build in GitHub Actions and carrel only stores and hands out releases
  (section 7.9).
- Apps from GitLab (section 7.9).
- Placing a tenant's machine on another member's private site, or sharing a private site's capacity
  with other tenants (section 8.4).
- A control plane of several replicas with consensus. One control plane plus a tested restore is
  the plan (issue #571).
- Plugins loaded into the control plane process. Plugins run next to the site agent.

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
4. Resolved 2026-11-13: no bandwidth limits. The 100 Mbit/s tenant egress police and the Proxmox `rate` on every NIC (12.5 MB/s primary, 100 MB/s private, 25 MB/s infra) capped tests at 100 Mbit/s, so all of them are removed. Revisit only if a tenant saturates the uplink.
5. How `machine_console_log` captures serial output: a QEMU chardev log file, or a capture of the
   Proxmox terminal proxy.
6. Whether the campus offers IPv6 for the new host. With it, every machine could have a public
   address and port NAT becomes optional. Until then, 6.13 routes a member's /48 over a tunnel.
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
16. Resolved 2026-11-12: function hosts run in platform VMs with nested virtualization, as
    measured. A guest that leaves Firecracker lands in a VM, not on a node that holds every
    tenant's machines, and the guard owns the whole host table, which a node shares with the
    Proxmox firewall. The same `carrel-fnd` runs on a node if nested virtualization proves too slow.
17. Function limits (section 7.11): 2 GiB of memory, a 3,600 second timeout, 20 functions and
    20 GiB per tenant are first guesses. Long batch work may need a longer timeout.
18. How a function reaches its tenant's private addresses (section 7.11). Version 1 allows public
    names only.
19. Whether all four nodes can restore one snapshot (section 7.11). A snapshot depends on the CPU
    model and the Firecracker version. The nodes' CPU models must be compared before a function
    may wake on any node.

## 14. Vocabulary

| Term | Meaning |
|---|---|
| admission | the physical capacity check at create or start, separate from quota |
| agent | the member's own AI client (Claude Code, Codex, any MCP client); not the site agent or `carrel-deployd` |
| capability | something a site can do beyond the core, provided by a plugin, such as snapshots or freeze (section 8.5) |
| control plane | the one carrel service that holds the database and serves MCP, CT 100 at B09 |
| core | what every site runs, with no plugin (section 8.5) |
| `carrel-deployd` | the agent a member installs in a machine to receive app releases (section 7.9) |
| exit node | the node with the public address; does SNAT and DNAT |
| fetch network | the reserved network `N = 255`, used only by the image fetcher's namespace on each node |
| grant | one allocation: a port, a domain (own or special), a peer rule, a snapshot |
| lab site | a site run by the lab admins (section 8.4) |
| managed machine | a machine carrel can configure and check from outside: cloud-init keys and addresses, the SSH check |
| plugin | a separate program next to the site agent that adds one capability (section 8.5) |
| primary network | the tenant's routed `/24`, where every machine's `net0` sits |
| private network | a layer 2 segment of one tenant, with no gateway and no filtering (section 6.8) |
| private site | a site on hardware a member owns, used only by that member's tenants (section 8.4) |
| reconciler | the loop that rebuilds derived state from the database |
| serial `N` | a tenant's permanent number; addresses, VMIDs and ports derive from it |
| site | one Proxmox cluster in one room; carrel's counterpart of an availability zone. Not "zone", which means a DNS zone or an EVPN zone |
| site agent | the program on each site that connects out to the control plane and applies its desired state (section 8.4); today the control plane reaches `node-agent` over SSH instead |
| slug | a tenant's DNS-safe name, fixed at registration |
| source | a Proxmox host that machines are imported from |
| special domain, special port | a name or public port outside the tenant's own subtree or block, granted by an admin (section 6.10) |
| tenant | a member or a project |
| unmanaged machine | a machine installed from an ISO: quota and metrics work, key injection and the SSH check do not |

## 15. B09 rollout record

The record of the B09 rollout, subsections 15.1 to 15.15, lives in
[docs/b09-rollout-record.md](docs/b09-rollout-record.md). It is history, not design: what was
installed, measured and accepted, version by version. References such as "PLAN 15.15" in code and
tests point there.
