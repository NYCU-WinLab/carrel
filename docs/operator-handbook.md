# Operator handbook

For lab admins who install, upgrade, back up and configure a carrel site.

## Templates and node configuration

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
in `/etc/carrel/node.json`, a ZFS pool (`local-zfs` at B09). Set it before `configure-reader.py` and template import. `configure-reader.py` creates the read-only
PVE API token that node-agent uses on every node; it lives in `/etc/pve/priv/carrel-reader.json`,
which the cluster shares and only root reads.
Several nodes are listed in `/etc/carrel/config.json` as
`"nodes": [{"name": "carrel01", "target": "carrel-node-01"}, ...]`, where `target` is a `Host` in
`/etc/carrel/ssh_config`. A new machine goes to the node that admits it with the most admission
memory left, and the new machines of one deployment share a node. Each machine record keeps its
node, and every machine request goes to that node. The first node must reconcile; the others catch
up on the next pass. The configuration also needs `"public_address": "<IPv4>"`, `origin`, `issuer`
and `database`; it is decoded into a typed `Config` at startup, so a misspelt or unknown key stops
the control plane with an error instead of acting as an empty value (`internal/carrel/config.go`
lists every key and its default). The
first node terminates TLS and publishes ports on that address. The control plane issues carrel's
own certificate (live pair `_origin` under `certificate_dir`) through DNS-01. A DNS record points at
the public address only after the gateway confirmed it holds the matching certificate.
New VM disks are linked clones on the guest storage; guest writes remain isolated. Requested extra packages still
refresh APT and install during initialization. Daily unattended security updates stay enabled.
Without a prepared manifest, the original templates retain their first-boot package installation.

## Install a site

Each script is idempotent and runs where it acts (PLAN 8.1):

1. Every node: copy `sites/<site>/cluster.json` to `/etc/carrel/site.json`, set `"storage"` in
   `/etc/carrel/node.json`, then run `scripts/install-network.py`. The site file's
   `content_storage` names the storage for CT templates (`vztmpl`), ISOs and imports; each kind
   defaults to `local`. A shared storage (B09: the NFS storage `rs822rp1`) keeps one copy per site.
   `apt_mirrors` (`debian`, `ubuntu`) points new VMs and CTs at a package mirror (B09: NYCU's);
   Debian's security archive stays upstream.
2. First exit node: `scripts/bootstrap-platform.py --admin-key <public key>` creates CT 100 and CT 101.
   After a node joins the site, or when `JUMP_FIREWALL` changes, run
   `scripts/bootstrap-platform.py --firewall` on the first exit node: it rewrites only the infra
   firewalls. The infra CTs leave through the site file's `management_interface`, which defaults
   to `underlay_interface`.
3. Every node: `scripts/build-templates.py` imports the prepared images (below).
4. CT 100: write `/etc/carrel/config.json` from `sites/<site>/config.example.json`, mode 0640.
5. Workstation, with binaries built on the sandbox:

```sh
python3 scripts/deploy-go.py --host root@192.168.19.101 --artifacts /path/to/sandbox-built/dist
```

`deploy-go.py` copies the release to the first exit node and runs `scripts/install-control.py`
there. It creates the reader token, installs the node programs on every node, sets every node's
sshd to keys only when the site file has `"ssh_keys_only": true` (no passwords, root by key;
issue #56), and installs or
upgrades the control plane service and its backup timer. An upgrade waits for idle jobs, keeps
database, configuration, OAuth and certificates, and saves a private rollback archive; a failed
health check puts the previous binary, units and the first exit node's programs back. Nothing is compiled on the
workstation or a node.
Existing route/NAT state remains in place. See [rollout record 15.9](b09-rollout-record.md#159-go-control-plane-06-2026-10-02)
for the reader credential and rollback details. Secrets travel through SSH stdin and protected files.

Deploy a published release with `deploy-go.py --host <first exit node> --release vX.Y.Z`: it
downloads the release archive, checks it against the release's `SHA256SUMS`, and installs the
binaries and scripts from the archive. `--artifacts` deploys a development build instead, and
`/healthz` then reports `"release": false`.

After a deploy, `node_list` shows the control plane's build (`control_plane`), each node's
`programs` (the release they came from and node-agent's digest) and `stale_nodes`, the nodes whose
programs came from another release. A failed upgrade restores the programs on the first exit node
only, so the other nodes show up there until the next successful deploy.

The `carrel-backup.timer` makes a consistent SQLite backup with config, service key and certificates
each day and sends it off the cluster to the SSH target `carrel-backup`: `scripts/backup-target.py`,
a forced command on spawner (the old PVE), keeps 14 daily archives under `/var/lib/carrel-backups`,
mode 0600.
These are sensitive archives. They do not contain tenant disks and are not a replacement for PBS.
For restoration, stop the control service, restore `carrel.db` (remove stale `-wal`/`-shm` files),
`etc/carrel/`, and `certificates/` to their original locations, set the documented ownership,
then start the service and run `reconcile_run`. The archive also holds
`nodes/<name>/{node.json,templates.json,site.json}` for each node; put them back under `/etc/carrel`
on each node, mode 0644 root, before the control service starts (it reconciles at once, and a node
without its `site.json` fails every reconcile). The result lists the SSH target of a node
that did not answer, or whose files exceeded 256 KiB, as `missing_nodes`, and the service logs a
warning. `/var/lib/carrel` is owned by `carrel:carrel`;
`/etc/carrel/config.json` is `root:carrel` mode 0640 and `node_key` is owned by `carrel`, mode 0600. The backup's database was restored to a temporary
location and passed SQLite integrity checking; a full infra/tenant disaster restore is pending.

## Keys from the portal

With `portal_keys_url` and `portal_keys_token_file` in `config.json`, a creation that has no key
in the request or the tenant reads its creator's key from the portal:

```json
"portal_keys_url": "https://portal.winlab.tw/api/ssh-keys/services/carrel",
"portal_keys_token_file": "/etc/carrel/portal-keys-token"
```

The URL is https, and is a portal SSH service's route (a portal admin makes the service on `/keys/services`);
the file holds its read key, mode 600. carrel asks for one username at a time, the caller's own,
when the call arrives, and keeps the key type and key only. Without these two settings nothing
changes.

## Lab SSH CA

With `ssh_user_ca` in `config.json`, every new VM and CT trusts SSH user certificates from the
lab CA (`https://ca.winlab.tw`) for its creator:

```json
"ssh_user_ca": "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEypPi2eUS00sJeJA9ebfrquCmA8reWrgdWSL4yGkfm4bKEuRyPmVJoM72JdUwzhH/v3VWkAkfPQ6sxMtzgruck="
```

The value is one public key with no comment (`public/ssh_user_ca.pub` in `NYCU-WinLab/pki`).
carrel takes the caller's Keycloak `preferred_username` when the call arrives; a caller cannot
name another. In a project tenant (`winlab-projects/<name>`) the principal is `project:<name>`
instead, so every current member of that Keycloak group logs in: the portal puts
`project:<name>` in a member's certificate for each such group. Someone who leaves the group keeps
access until their certificate expires (at most 24 hours). A VM gets `/etc/ssh/ssh_user_ca.pub`, `/etc/ssh/sshd_config.d/50-carrel-user-ca.conf`
(`TrustedUserCAKeys` and `AuthorizedPrincipalsFile /etc/ssh/principals/%u`) and
`/etc/ssh/principals/user` through cloud-init, before sshd first starts; a CT gets the same files
for `root` at creation. ISO installs and images that serve their own ports get nothing. Existing
machines are not changed. Without the setting nothing changes.

The node op `ca_backfill` writes the same files into an existing, stopped VM's disk. It attaches the
disk with `qemu-nbd` and mounts the root partition on the node, so the node kernel parses a
filesystem the tenant controls. The mount is read-write only (needed for the write) with
`nodev,nosuid,noexec`, plus `errors=remount-ro` on ext4. Nodes must run a patched kernel before the
maintenance-window run (#443).

The admin tool `machine_ca_backfill` calls it per VM: it skips a VM that already has `ssh_user_ca`, a
CT, a running VM, a VM with a queued or running operation, an ISO install, a VM with
`service_ports` and a VM with snapshots (a rollback restores a pre-backfill disk that never pulls; delete
the snapshots, then run it again); after the node op succeeds it saves
`ssh_user_ca`, `ca_principals` and `ca_sync: pull`, so a failure leaves the record old and a second run
retries. A personal tenant does not record its owner's portal username, so the call names it in `owner`,
and a VM is skipped unless that username's slug is the tenant's slug. For a tenant whose slug an
administrator assigned, `alias_confirmed: true` waives only that slug gate; it needs `tenant` and
`owner`, is only for a personal tenant (a project tenant is refused as `invalid`), applies to every eligible VM of the tenant when `machine` is omitted, and is recorded in the
audit log. A lossless recorded username (a saved key's `by`, or `ca_principals` of a live or frozen VM
created with the CA) that contradicts `owner` still refuses, flag or not, and so does a tenant that records more
than one distinct username (an administrator must resolve its records first). A personal tenant with no recorded
username is skipped unless the Keycloak lookup succeeds and `user:<sub>` equals the tenant subject, flag or
not; the lookup runs at most once per call and a failure is remembered for that call; a project tenant gets `project:<name>`. Give `tenant` and `machine` for one VM, `tenant` alone for all
its VMs, or neither for every tenant; `dry_run` lists what would change.

Maintenance window runbook for the backfill (#443). Prerequisite: `keycloak_url`, `keycloak_realm`,
`keycloak_client_id` and `keycloak_client_secret_file` must be configured, and `keycloak_url` + `/realms/` +
`keycloak_realm` must equal `issuer`. Without them every VM of a personal tenant with no username record is
skipped (`sites/b09/config.example.json` has no such fields, add them).

The Keycloak client must be a separate one: the lookup uses the client credentials grant and then calls
`GET /admin/realms/<realm>/users`, so it needs a confidential client with service accounts enabled, and its
service account needs a narrow realm-management role (`view-users` or `query-users`). The checked-in
`sites/b09/keycloak-client.json` (`carrel-mcp`) is public with service accounts disabled and cannot be reused.
Provision the new client, put its secret in `keycloak_client_secret_file`, and before any downtime run a
`dry_run` for one known tenant and confirm it reports `owner checked against Keycloak sub`. Startup validation
passes without this, so a wrong client only shows up as skipped VMs.

During the preflight `dry_run`, a running VM that passes the owner check still reports `skipped` with
"stop it first". That is not an owner refusal; it only means the VM must be stopped before the real run.

Read the `dry_run` messages before you stop any VM. Stop the VM, run `machine_ca_backfill` for it
(use `dry_run` first; a VM with snapshots is skipped until an admin deletes them), start the VM, then check. Per VM, after start:

1. `ssh_user_ca`, `ca_principals` and `ca_sync` are set on the machine record (`machine_get`).
2. A lab certificate login with the principal succeeds.
3. `machine_access` grants a second user and that user's login works; after a revoke the login fails
   within about 15 seconds.
4. The guest reports to carrel: the `guest_reports` row is fresh and comes from the new reporter.

Never change the cloud-init instance id of a VM: it reruns first boot and regenerates the host keys.
The `machine_access` message that tells owners to add files by hand applies only to a machine
without `ca_sync`; once a VM is backfilled it has a puller and the message no longer applies.

`machine_access` lets the tenant name other members who may log in with a certificate: grant and
revoke take portal usernames, and the machine's principals file becomes its own principal followed
by the grants. A VM's guest reporter (`scripts/guest-report.py`) sends the file it has and writes the
list Carrel answers, so a change lands within 15 seconds while the VM runs; a CT's node pushes the
file with `pct push` when the grants change, so the CT must be running. The machine record keeps
`ca_sync` (`pull` or `push`); a machine created before it has no puller, and the tool says so instead
of saving a grant it cannot apply. `machine_get` shows the list and whether the machine has it
(`lab_ca.applied`). A grant needs no new certificate (the username is in every member's), hand
edits of the principals file are replaced on the next change, and on a CT a grant logs in as root.

The jump host takes the same certificates on its own user, `ca`, so a member needs no saved key:
`ssh -J ca@carrel.winlab.tw user@<address>` (`ssh_jump_certificate` in `machine_get`). `jump@` keeps
taking only keys. A separate user, because the client offers the certificate from `step ssh login`
before its keys and sshd uses the first line that matches: on `jump@` a certificate line would shut a
member out of service ports and teammates' machines that their keys open. Carrel sends the jump host
a map from each principal to port 22 of the machines whose principals file names it (`op: certs` to
`scripts/jump-sync.py`, kept in `/etc/carrel-jump/certs.json`), with every reconcile and right after
`machine_access`, so `ca@` reaches exactly the machines that let the certificate log in. sshd runs
`scripts/jump-cert.py` as its `AuthorizedKeysCommand`: for a user certificate offered to `ca` it
prints one line that forwards to every machine any of the certificate's principals opens. One line,
because sshd uses only the first line that matches. sshd still checks the signature, the validity
period and the principal itself. `configure-nodes.py` installs the script, the user and the sshd
file; a jump host without them keeps taking keys, and the reconcile reports `keys_only`. Without a CA
the map goes as null and the jump host drops it; a map no control plane has refreshed for 30 minutes
(Carrel rolled back or stopped) admits no certificate.

Repairing a damaged jump sidecar: `jump-sync.py` keeps the last accepted generation of each write in
`/var/lib/carrel-jump/keys.gen` (the `sync` op) and `/var/lib/carrel-jump/certs.gen` (the `certs` op),
each one decimal integer and a newline. A file that is not an integer in [0, 2^53) makes that write
fail with `adapter_internal` ("unreadable generation file") on purpose, so a damaged file cannot
reset the stale-write guard. To repair it, on the jump host as root, write a valid integer into the
file and never delete it, because a missing file drops the guard. Use the last known good value, or
the current clock in microseconds, which is never below what Carrel sends and always in range:
`echo $(( $(date +%s) * 1000000 )) > /var/lib/carrel-jump/keys.gen` (same for `certs.gen`). Do not
pick a value above the clock, or the jump host refuses Carrel's writes as stale until the clock
catches up. No control plane restart is needed: the next reconcile sends a generation in range and
the writes are accepted again. Check with `{"op": "status"}` or the next reconcile result.

Carrel spots one kind of damage itself. A refusal whose held value is more than 24 hours above
both the clock and the last generation Carrel took is logged as `jump_sync_held_damaged`. Carrel
does not resend above it, because that would climb to the top of the range. The writes stay
`stale` or `keys_only` until the file is repaired as above.

## Telemetry

With `telemetry_url` in `config.json`, the control plane exports to any OTLP/HTTP collector
(OpenTelemetry Collector 0.166.0 tested). Without it nothing leaves the control plane.

```json
"telemetry_url": "https://otel.example:4318",
"telemetry_token_file": "/etc/carrel/telemetry-token"
```

- `telemetry_token_file` is optional. When set, the file holds a bearer token, mode 600, read on
  every send, and the URL must be https.
- Without a token the URL may be http, for a collector on the same host or a private network.
- Requests go to `/v1/logs`, `/v1/metrics` and `/v1/traces` as JSON, uncompressed.
- Sending never blocks a request. A collector that does not answer costs one
  `telemetry_export_failed` line on stderr a minute.

A stock collector needs only the OTLP receiver:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318
exporters:
  debug: {}   # replace with your backend
service:
  pipelines:
    logs: {receivers: [otlp], exporters: [debug]}
    metrics: {receivers: [otlp], exporters: [debug]}
    traces: {receivers: [otlp], exporters: [debug]}
```

### Signals

Every record carries the resource attributes `service.name` (`carrel`), `service.version` and
`service.instance.id` (the host name of `origin`), so one collector can hold several sites.

| Signal | What | Attributes |
|---|---|---|
| Logs | every WARN and ERROR record, at most 20 a minute per message | the record's own, such as `code` |
| Metrics | `carrel.node.*` gauges, once a minute per node (PLAN 9.1 lists them) | `node` |
| Traces | one span per tool call; arguments and results stay out | `carrel.tool`, `carrel.outcome`, `carrel.tenant` (a number) |

The gauges are what the Proxmox metric server does not export: admission's committed and limit
for vCPU, memory and disk, the real use of the pool and the memory, snapshots, and the memory the
running VMs need. Export node and guest metrics with the Proxmox OpenTelemetry metric server.

### Alerts worth having

carrel sends no alerts itself. Point an alerting service at the collector's backend:

| Alert | Rule |
|---|---|
| Pool filling | `carrel.node.storage.utilization` above 0.7 warns, above 0.85 is an error |
| Memory saturated | `carrel.node.memory.utilization` above 0.9 |
| Node unreadable | `carrel.node.reachable` below 1 |
| Repair or backup failed | ERROR records such as `reconcile_failed`, `backup_failed`, `certificate_issuance_failed`, `gateway_config_rejected` |
| Out of room, guest not up | WARN `operation_failed` with `code` `capacity_exhausted` or `guest_not_ready` |
| Site silent | no new `carrel.node.reachable` point for 10 minutes; run the alerting outside the site |

## Function environment key

`function_env_key` encrypts function environments and registry credentials. To rotate it:

1. Generate a new key: `openssl rand -base64 32`.
2. In `/etc/carrel/config.json`, move the current key into `function_env_old_keys` and put the new
   key in `function_env_key`. Restart carrel.
3. New uploads are sealed with the new key. Values sealed earlier (every kept version, the rollback
   target included, and every function's registry credentials) stay sealed with their old key
   until you re-seal them.
4. Count what each key still opens: `carrel -reseal-function-values -dry-run`. It prints
   `{"counts":{"current":N,"old:0":N,"none":N},...}`, where `old:i` is the i-th entry of
   `function_env_old_keys` (from 0). Then re-seal with `carrel -reseal-function-values`, which
   changes only values an old key opens, in one transaction. Run it with the same config and
   database as the service, and take a backup first.
5. When a key's count is zero, remove it from `function_env_old_keys` and restart carrel. A count
   under `none` is values no key opens; those fail as below until the member uploads them again.

Copy the old key exactly: a wrong old key passes validation, and the versions it should open fail.

A version no configured key opens fails when a function host builds it: the host reports
`environment: ... cannot be decrypted with any configured key` (or `registry credentials: ...`),
and the control plane logs `function_value_open_failed`. The member uploads the environment again
with `function_env`, which builds a new version. For registry credentials, the member uploads
them again with `function_registry`, then deploys again.

## NetBox sync

carrel can push machines, networks, addresses, published ports and virtual addresses to NetBox. It
is off unless `config.json` has a `netbox` section with `"enabled": true`, `url`, a `token` or
`token_file`, the NetBox `cluster` name and an `owner` (NetBox 4.5+):

```json
"netbox": {"enabled": true, "url": "https://netbox.example", "token_file": "/etc/carrel/netbox-token",
           "cluster": "carrel", "owner": "carrel", "vmid_field": "vmid"}
```

The NetBox operator creates the cluster, the owner and an integer custom field (default `vmid`) on virtual
machines first. Every object carrel creates carries the owner, and carrel changes only objects with
that owner, so scope the token's permissions with it. PLAN 9.4 has the mapping and the permissions.
`machine_get` shows `netbox.last_synced` and `netbox.last_error` for each machine.

The client VPN's addresses sync with no more setup. To show each tenant's WireGuard interface as a NetBox
tunnel too, create a tunnel group, give it carrel's owner, and set `"tunnel_group": "<its name>"`; the token then
needs the `vpn.*` and `dcim.interface` permissions of PLAN 9.4.
Unsetting `tunnel_group` later leaves the tunnels carrel made in NetBox; the NetBox operator removes them.
When the token may create tenants only inside a tenant group, set `"tenant_group": "<its name>"` so each
carrel tenant joins that group.
To let members see their own tenants in NetBox, create a text custom field on tenants and set
`"subject_field": "<its name>"`: each tenant then carries its Keycloak subject (`user:<sub>` or
`winlab-projects/<name>`), which a NetBox permission can match against the signed-in member.

## Known limits

Lost-key console recovery remains unavailable. Control backups include SQLite, configuration and
certificates, not tenant disks. Full tenant disaster restoration and install-from-scratch acceptance
remain separate release gates.
