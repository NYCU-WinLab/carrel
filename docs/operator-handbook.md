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
The script keeps libguestfs scratch files and its appliance cache in `<output-dir>/.guestfs`, so a
small shared tmpfs `/tmp` cannot fill halfway, and stops at once when the output directory has less
than 6 GiB free. It also stops with the fix when the host kernel is root-only (set `SUPERMIN_KERNEL`
to a readable copy). Before apt runs it checks that the appliance resolves the Debian mirror; when
`passt` gets no DHCP lease it retries with a task-local shim that selects libguestfs's SLIRP
fallback, without replacing the shared installation or resolver.
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

`scripts/install.sh` runs steps 1 to 3 below on one host, in order. Run it as root from a checkout
of this repository on each node:

```sh
# The first exit node: the network, then CT 100 and CT 101.
scripts/install.sh --site sites/<site>/cluster.json --admin-key admin.pub
# Every other node: join the first node's Proxmox cluster, then the network.
scripts/install.sh --site sites/<site>/cluster.json --join <first node>
```

- The host must be listed under `nodes` in the site file.
- Guest storage (`storage`, or `--storage`) must be a ZFS pool.
- `--join` runs `pvecm add <node> --use_ssh 1` once, on a host with no guests.
  - Root on the joining host must reach `root@<node>` by that name without a prompt: its key in the
    node's `authorized_keys`, and the node's host key in its `known_hosts` under that name.
  - `pvecm add` exits 0 when it stops early, so `install.sh` checks for `/etc/pve/corosync.conf`.
- Root's `authorized_keys` must be the cluster's shared file, a link to `/etc/pve/priv/authorized_keys`.
  A host made from a cloud image before Proxmox was installed keeps its own file, and `install.sh`
  stops: append its lines to the shared file, without cloud-init's `no-port-forwarding,...` lines
  that refuse root, then make the link.
  - Afterwards, run `scripts/bootstrap-platform.py --firewall` on the first exit node.
- `--prepared-dir`, `--image` and `--vmid-base` pass through to `build-templates.py`.
- Running `install.sh` again repairs; on the first exit node it rewrites the infra firewalls.
- `CARREL_DRY_RUN=1` prints each change instead of making it.

Step 4 and the release stay separate. The steps one by one (PLAN 8.1):

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
   Optional site file fields for this step: `infra_nameserver` (CT 100 and CT 101's resolver,
   default `1.1.1.1`) and `jump_exempt_sources` (networks many members share, such as a campus
   NAT, that the jump host's sshd never locks out; B09: `140.113.0.0/16`).
   `install-network.py` also takes `evpn_asn` (default 65009) and `vrf_vxlan` (default 99999)
   for a site whose network already uses those numbers.
3. Every node: `scripts/build-templates.py` imports the prepared images (below).
4. CT 100: write `/etc/carrel/config.json` from `sites/<site>/config.example.json`, mode 0640.
   `domain` is the site's own DNS zone, where tenants get `*.<slug>.<domain>` (default
   `winlab.tw`); `public_host` is the name members reach SSH ports and the jump host at (default
   `carrel.<domain>`). Both are fixed for the life of a site: names already handed out keep them.
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

With `"node_ssh_ca"` in the site file, root on every node also takes a lab SSH certificate whose
principal is listed there. Keys keep working beside certificates.

```json
"node_ssh_ca": {"key": "<the lab user CA public key>", "principals": ["<member>", "svc:<portal service>"]}
```

A principal is a member name, or `svc:<slug>` for everyone a portal service grants. To add or
remove someone, change `principals` in `/etc/carrel/site.json` on the first exit node, then run
`python3 configure-nodes.py` from the newest `/var/lib/carrel/go-upgrade-*` directory there, or
deploy again. Removing `node_ssh_ca` removes the CA files while `ssh_keys_only` stays on; the
node sshd step does not run without it. A certificate already issued keeps working until it
expires (at most 24 hours). A run that fails on a node puts that node's previous drop-in and CA
files back.

Deploy a published release with `deploy-go.py --host <first exit node> --release vX.Y.Z`: it
downloads the release archive, checks it against the release's `SHA256SUMS`, and installs the
binaries and scripts from the archive. `--artifacts` deploys a development build instead, and
`/healthz` then reports `"release": false`.

After a deploy, `node_list` shows the control plane's build (`control_plane`), each node's
`programs` (the release they came from and node-agent's digest) and `stale_nodes`, the nodes whose
programs came from another release. A failed upgrade restores the programs on the first exit node
only, so the other nodes show up there until the next successful deploy.

The `carrel-backup.timer` makes a consistent SQLite backup with config, SSH keys and certificates
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
warning. `carrel -backup` asks the running control service to make the backup, over the
control socket `/var/lib/carrel/control.sock` (mode 0600, user `carrel`), because only the service
reaches nodes on the agent transport. When the service does not answer (it is stopped, or stops
midway), the timer makes the backup
itself and logs `backup_without_server`; an agent node it cannot reach over SSH is listed in
`missing_nodes`.
`/var/lib/carrel` is owned by `carrel:carrel`;
`/etc/carrel/config.json` is `root:carrel` mode 0640; `node_key` and `service_key` are owned by `carrel`, mode 0600.

CT 100 has 2 SSH keys. `node_key` reaches `node-agent.py` on nodes that still use SSH.
`service_key` reaches the 3 forced commands outside the nodes: `gateway-sync.py` in CT 101,
`jump-sync.py` in CT 102 and `backup-target.py` on the backup host. `configure-nodes.py` makes
`service_key` and installs it in CT 101 and CT 102 beside `node_key`, so a failed deploy that puts
back the older `ssh_config` still reaches them; the `node_key` lines go with #604. It does not reach
the backup host. There, ssh offers `node_key` first, so a backup that lands does not prove the
`service_key` line works. Move the backup host in this order:

1. Add a line for `/etc/carrel/service_key.pub` with the same forced command as the `node_key` line.
2. Remove the `node_key` line.
3. In CT 100, run `systemctl start carrel-backup.service` and check that the journal says
   `backup_complete`. If it fails, put the `node_key` line back and check the new line.

The backup's database was restored to a temporary
location and passed SQLite integrity checking; a full infra/tenant disaster restore is pending.

## Upgrade and rollback

### Order

1. Upgrade the control plane first, with `deploy-go.py --host <first exit node> --release vX.Y.Z`.
2. Then upgrade each site's node programs, agents and plugins, one site at a time. Check
   `node_list` for `stale_nodes` before the next site.

A control plane serves its own agent protocol version and the one before it (#561). So an agent
one release behind keeps working while its site waits, and a site must not skip a release of the
control plane.

### What a rollback needs

Release N always reads the data release N-1 wrote. Going back from N to N-1 depends on the
database:

- **N adds no schema migration:** roll back by binaries alone. Deploy N-1 again, or let a failed
  health check restore it.
- **N appends to `schemaMigrations`:** N-1 refuses the newer database. Restoring the
  pre-migration copy (see [Database schema](#database-schema)) loses every write since the upgrade.
  The release notes of such a release say so.

### Roll back the running release

On the first exit node, run `python3 /var/lib/carrel/<newest go-upgrade-*>/install-control.py rollback`.
It undoes the upgrade that installed the running release:

- It picks the newest stage whose `release.json` matches the installed one and whose previous
  release differs. A newer upgrade that failed and put the previous release back is skipped, and so
  is a deploy of the release that was already running.
- It puts back the previous binary, units, configuration and node programs, and waits for the
  previous version's health check.
- When that upgrade migrated the database, it stops and names `--database`. With `--database`, it
  first unpacks and checks the database copy taken before the upgrade while carrel still runs. Then
  it stops carrel and puts the copy in place, and every write since is lost. If that step fails,
  carrel starts again on the running release.
- It holds the node's deploy lock, so no deploy or second rollback runs beside it. Running it again
  goes one more upgrade back.
- Once the previous version is healthy, it runs the previous release's own node step from the
  newest kept stage of that release whose `configure-nodes.py` matches its recorded hash.
  `configure-nodes.py` copies the restored node programs and `release.json` to the other nodes and
  rewrites `config.json`, carrel restarts and must pass the health check again, and every
  `carrel-agent` restarts on the restored binary and must reach the control plane, as after a
  deploy. Without such a stage it says so and leaves the other nodes and the agents at the newer
  release: deploy the previous release again so every node matches.
- It leaves `carrel-deployd` in CT 100 and `carrel-fetch` in CT 103 at the newer release. Deploy the
  previous release again when those must match too.

## Node agent

A node reaches the control plane over SSH by default. On the agent transport (PLAN 8.6),
`carrel-agent` on the node connects out to the control plane instead and runs each job through
the same `node-agent.py`. Any site node can use it. The other nodes reach `10.200.0.3:8443` by a host
route through the first exit node (no NAT): `carrel-agent.service` adds it before it starts, from the
node's own underlay address, so `agent_source` is that address. The infra firewall
(`bootstrap-platform.py --firewall` rewrites it) admits port 8443 from the site nodes' underlay
addresses only. Each other node has its own token in `/etc/carrel/agent-tokens/<node>` on the first
exit node, copied to `/etc/carrel/agent-token` on the node together with the CA certificate.

To move the first exit node to the agent:

1. Add `"agent_nodes": ["<first exit node>"]` to `sites/<site>/cluster.json` and copy it to
   `/etc/carrel/site.json` on that node.
2. Deploy as usual with `deploy-go.py`. `configure-nodes.py` then:
   - makes a CA in `/etc/carrel/agent-ca/` on the node (root only, 10 years) and a listener
     certificate for `10.200.0.3` (825 days; any deploy with less than 90 days left renews it);
   - copies the listener certificate and key to CT 100 under `/etc/carrel/agent/` and sets
     `agent_listen`, `agent_cert_file` and `agent_key_file` in `config.json`;
   - makes the node's token in `/etc/carrel/agent-token` (mode 0600, kept across deploys) and
     writes `transport`, `agent_token_sha256` and `agent_source` into the node's `config.json` entry;
   - once the new control plane answers its health check, writes `/etc/carrel/agent.json` and
     starts `carrel-agent.service`. A failed deploy never touches a running agent. The deploy
     then waits up to 60 seconds for the agent's `agent_connected` log line and fails loudly
     without it.
3. Check it: `node_list` shows the node, and `journalctl -u carrel-agent` on the node shows
   `agent_started` and no `claim_failed`.

To move another node to the agent, after the first exit node runs it:

1. Run `bootstrap-platform.py --firewall` on the first exit node first, so the infra firewall
   admits port 8443 from the other nodes' underlay addresses. Without that rule the node's agent
   never connects.
2. Add the node to `agent_nodes` in `sites/<site>/cluster.json`, copy it to
   `/etc/carrel/site.json` on the first exit node, and deploy. The deploy makes the node's token
   in `/etc/carrel/agent-tokens/<node>` on the first exit node, pushes the CA, token,
   `agent.json`, binary and unit to the node over SSH, starts the agent after the health check,
   then waits up to 60 seconds for `agent_connected` in `journalctl -u carrel-agent` on that node
   and fails loudly without it.
3. Check it as above, on that node.

To go back to SSH, remove the node from `agent_nodes` and deploy again: the node's entry loses
its transport, `config.json` loses the listener keys, and the agent stops after the health
check. The CA, the token and the certificate files stay, so moving back needs no new ones. The SSH key line stays in both modes until #604, so either
transport works at any time.

Consoles (`machine_console_url`) go through the agent too, once the agent says it can stream: its
claims carry `capabilities: ["stream"]`, and `node_list` shows them under `agent`. The claim hands
out the console, the agent connects back to `/sites/v1/agent/streams/<id>` with the same token, and
that connection carries `node-agent.py`'s stdin and stdout. An agent that has not polled in the
last 90 seconds, or one from before streams, leaves the console on SSH. Restarting the agent cuts
open consoles, as a dropped SSH session does; the member reloads the page.

The listener serves only `10.200.0.3:8443`, TLS 1.3. The infra firewall drops tenant traffic to
`10.200.0.3` on any port but 8080; port 8443 is open only to the other site nodes' underlay
addresses, arriving on the underlay interface. A request needs the node's token and must come from
the node's `agent_source`: `10.200.0.1` for the first exit node, the node's underlay address for
any other. Stopping the agent lets running jobs finish: systemd waits up to 4 hours 30 minutes
(`TimeoutStopSec`), the longest a root op runs. To rotate a token, on the first exit node create
`/etc/carrel/agent-token.rotate` for the first exit node's own token, or
`/etc/carrel/agent-tokens/<node>.rotate` for another node's, and deploy again. A failed health
check keeps the first exit node's old token; a rotated token of another node takes effect at the
next deploy that passes the health check. Do not delete the token file: the restored configuration would then name a token no file
holds.

### Certificate sign-in

An agent can sign in with a client certificate from the lab step-ca instead of its token (#601).
The certificate names one node, `<node>.<site>.agent.carrel.winlab.tw`, comes from the
`carrel-agents` JWK provisioner, is for client use only and lasts 7 days. The agent renews it
itself over mTLS once a third of its life has passed, so the only secret on the node is the
agent's own key in `/etc/carrel/agent-identity/`. The provisioner's private key stays with the
operator: the CA lists its public key only, and no signing secret sits on the site or in its
backup.

The site file turns it on:

```json
"agent_identity": {
  "ca_url": "https://ca.winlab.tw",
  "lab_root": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "provisioner": "<the carrel-agents key id>",
  "certificate_nodes": [],
  "domain": "agent.carrel.winlab.tw"
}
```

`domain` is the suffix of each agent certificate's name, `<node>.<site>.<domain>`.

With `agent_identity`, a deploy writes the lab root to `/etc/carrel/lab-root.pem` on every agent
node and to `/etc/carrel/agent/lab-root.pem` in CT 100, adds the certificate fields to each
`agent.json`, and sets `agent_client_ca_file` and `agent_provisioner` in `config.json`. The
listener then asks for a client certificate but does not require one. A node in
`certificate_nodes` gets `agent_certificate` in its `config.json` entry instead of
`agent_token_sha256`: the control plane takes only a certificate for that name, from that
provisioner, chained to the lab root, checked on every request. The source address check stays.
A node not listed keeps its token, and its agent presents the certificate beside the token once
it has one.

To move a node to certificate sign-in:

1. Add `agent_identity` with an empty `certificate_nodes` and deploy.
2. On the operator machine, mint a one-time token for the node's name:
   `step ca token <node>.<site>.agent.carrel.winlab.tw --provisioner carrel-agents --key <the
   provisioner's private JWK> --ca-url https://ca.winlab.tw --root <lab root>`.
3. Enrol the node over root SSH, with the token on stdin, never in arguments:
   `ssh root@<node> '/usr/local/lib/carrel/carrel-agent -config /etc/carrel/agent.json -enroll'`
   and paste the token. The agent makes a P-256 key, gets the certificate and logs `enrolled`.
4. Restart the agent (`systemctl restart carrel-agent`) so it presents the certificate at once;
   otherwise it picks it up within the hour.
5. Add the node to `certificate_nodes` and deploy. `node_list` then shows
   `certificate_expires` under the node's agent.

To go back to the token, remove the node from `certificate_nodes` and deploy: the token file
was never removed.

Expiry and outages. The agent checks its certificate every hour and logs `certificate_renewed`,
or `certificate_renew_failed` while the CA cannot renew it. The control plane logs a WARN
`agent_certificate_expiring` once an hour when a node's certificate has less than 48 hours left,
and `node_list` shows `certificate_expiring`. Every node renews on the same schedule, so a CA
outage of more than about 4 days lets every node's certificate run out together, and every job
on a certificate node then waits. The CA renews no expired certificate: enrol the node again
(steps 2 to 4). Root SSH to the nodes does not depend on the agent, so it stays the way in.
Break-glass, when the lab CA itself is down, is the operator's personal root key: it signs in
to every node with no CA, then either enrol the nodes once the CA is back or remove them from
`certificate_nodes` and deploy to go back to tokens.

A console stream that is already open is not cut when the certificate expires; the next request
is refused.

The CA keeps no revocation list for these certificates: a stolen agent key works until its
certificate expires, at most 7 days. To cut one node off at once, remove it from `agent_nodes`
and deploy, then enrol it again with a new key before adding it back.

### Plugins

A plugin is a service on a unix socket, `<name>.sock`, in the agent's `plugin_dir`
(`/run/carrel/plugins` by default; #564, #660). The contract is `proto/plugin/v1/plugin.proto`.

- The agent trusts the directory only when its own user owns it and nobody else can write to it.
  Otherwise it reports one entry named `plugin-dir` with the reason, and runs no plugin.
- The same holds for every parent of `plugin_dir` up to `/` (#666): none may be a symlink, be owned
  by anyone but root or the agent's user, or be writable by group or others (a sticky directory
  such as `/tmp` is accepted). A plugin unit must never own `/run/carrel`, for example through
  systemd `RuntimeDirectory=` with `User=`: it could replace `plugins`.
- Every claim carries a report of each socket: name, version, contract, operations, and whether
  the node can run it. The report is at most 30 s old. `node_list` shows it per node.
- The agent serves the contract revisions in `PluginContracts`, the current and the previous one.
  A plugin built for another revision is reported with a message that names what to install, and
  every call to it is refused with `plugin_refused`.
- A job with `"op": "plugin"` runs in the agent, not in `node-agent.py`. `call` is `start`, `get`
  or `cancel`, and `idempotency_key` names the operation. `plugin_unavailable` means the plugin
  did not answer: ask again with the same key once it is back.

#### Plugin tools

Each operation a node reports is a tool named `<plugin>_<operation>` (#661). No core change and
no restart are needed: the tool is listed while some node reports the plugin as supported, and is
gone once none does. Clients cache tool lists, so a member may need to reconnect to see a new one.

- An operation is admin-only unless the plugin sets `member`. A member operation must require a
  top-level `machine`. carrel checks that machine against the caller's tenant and passes the
  plugin its VMID, never the name.
- `read_only` operations are also listed on `/mcp/read-only`. A read, and a call with `dry_run`,
  answers at once on one node, as a core read does: no operation, one audit row. An operation
  that sets `dry_run` in its description gets `dry_run` on the start, and must answer `done` in
  its first reply. For any other operation carrel answers a dry run itself, `state` planned: a
  plugin built before the field would run the operation for real.
- A plugin's result keys are added to the answer, as a core tool's result. carrel's own keys
  (`ok`, `error`, `operation`, `state` and the like) are never taken from a result.
- A plugin that fails an operation with `error_code` `invalid`, `conflict`, `not_found`,
  `quota_exceeded`, `capacity_exhausted` or `unsupported` gives the caller that code, its own
  message and the keys of `error_details`. Any other failure is `plugin_failed`.
- An operation may name a `toolset` of the tool contract, such as `machines`, to be listed there
  as well as under `plugins`. `destructive` and `idempotent` become the tool's hints.
- Over HTTP, `GET /v1/tools` lists the tools the caller may call, plugin tools included (marked
  `"plugin": true`). `POST /plugins/v1/tools/<tool>` calls a plugin tool, with the tool's arguments as
  the JSON body. Both take the same bearer token as `/mcp`, and a call is checked and gated as on `/mcp`. Send the same arguments
  with the same `idempotency_key` to poll the operation.
- The control plane checks the arguments against the schema before the call is queued, and again
  against the schema of the node that runs it. A schema may not use `$ref` outside itself, or declare
  `tenant`, `idempotency_key`, `dry_run`, `detail` or `wait_seconds`.
- A core tool's name wins. `catalog_get` lists the plugin tools under `sites[].plugins.tools`. It lists each
  operation left out, with the reason, under `left_out`.
- A call is an operation. On the node with the call's machine, or the first undrained node with
  the plugin, it starts the plugin operation with the key `<operation id>-<run>`. It then polls until done,
  and keeps `progress` and `message` on the operation. A restart polls the same key again.
  `operation_retry` asks after the same key while the last run may still be going. It starts a
  new run under a new key only once the last run is known to have ended.
- The node that runs a call decides its access. A node that reports other `member` or
  `read_only` flags than the first node does not run the tool, as during a rolling update.
- A queued call waits up to 5 minutes for a node to report the plugin (`waiting_for_plugin`),
  as after a control plane restart. A plugin that cannot be reached for 10 minutes fails the
  call with `backend_unavailable`.

#### Plugin objects

A plugin can declare kinds of objects its operations make on a machine, such as a disk snapshot
(#663). carrel keeps a record of each object, so quota, admission and the core actions read it at
once, as they read carrel's own rows. The records are in the `plugin_objects` rows.

- A plugin declares its quota dimensions, each with a default limit, and its object kinds. A kind
  names what one object charges: an amount per object, or times the machine's `cpu`, `memory_mb`
  or `disk_gb`. A dimension may not have the name of one carrel counts itself, such as
  `snapshots`; the operations are then left out, with the reason.
- An operation names its `object_kind`, its `object_effect` (`create`, `delete`, `use` or
  `list`) and the required string parameter that names the object. It must also require
  `machine`. A `list` is `read_only`, names no parameter and answers with the machine's records
  of the kind.
- A dimension marked `measured` counts, once the nodes have sampled the tenant's storage, what
  the tenant's disk objects hold, as `snapshot_gb` does. A create then adds nothing yet, and a
  tenant already over the limit gets no more. Without a fresh sample it counts what was charged.
- An object operation answers as a core action does. carrel adds `delta`, `quota_before` and
  `quota_after`, the record under the kind's name (`snapshot`), the list under its plural
  (`snapshots`) and, for a kind charged to a measured dimension, the storage sample under
  `<kind>_storage` with `<dimension>_counts` (`held` or `declared`). A kind whose keys would be
  carrel's own is left out.
- A disk kind's record keeps the machine's resources and NICs at creation. A `rewinds`
  operation on it is refused once they changed, and while a resize is pending.
- An operation that declares `confirm` requires a string `confirm` that repeats the object's
  name. carrel checks it before anything changes, as a core rollback does.
- Before a create starts, carrel checks the name is free, charges the tenant's quota and, for a
  kind with `disk`, checks the node's storage as for a snapshot. It records the object as
  `creating` and sends the record's id to the plugin as `reservation`. A plugin must refuse a
  start of an object operation without one: an agent built before the field drops it. The agent
  starts it only if the plugin declares the object now as the report carrel charged by did.
- carrel drops a record only on proof the object does not exist: a first start the agent or the
  plugin refused for the run that made the record, or a delete the plugin fails with `not_found`. Any other failure keeps it
  charged and holding. A delete of the object clears it.
- A kind's `holds` names what its objects block: `freeze`, `migrate` (also `node_drain`, which
  leaves the machine with `has_plugin_objects`), `backfill` and `delete`. A kind without
  `delete` dies with its machine: `machine_delete` frees its charge and forgets the records.
- A record keeps the holds it was made with, and the plugin's dimensions keep their limits, while
  no node reports the plugin. An admin sets a plugin dimension with `quota_set` as any other.

#### Plugin operations on a machine

An operation whose schema requires `machine` gets the machine's facts with the start, as
`machine`: VMID, kind, node, CPU, memory, disk, power state and `configuration`, a digest of
what a disk rewind must find unchanged (#663).

- `stopped`: the guest must be stopped while the operation runs. carrel refuses a paused guest,
  and a machine that is provisioning, deleting, migrating or resizing. It shuts a running guest
  down gracefully before the start. A dry run reports `downtime_expected`.
- Once the run has ended, carrel starts the guest again if it was running, and waits for a report
  from the new boot. The result says `power_state` and `power_state_restored`.
- A run whose fate is unknown, such as a plugin that stopped answering, leaves the guest stopped:
  the plugin may still be writing its disk. The error says `machine_left_stopped`. The machine is
  fenced (`plugin_fence`): every other operation on it is refused until `operation_retry` asks
  after the same run and restores the guest when it ends.
- When a retry cannot settle the run (the plugin lost its state, or keeps answering that it has
  no record), clear the fence with `machine_unfence`. It reads the node first and refuses while
  the guest has an active Proxmox task or holds a lock. A lock with no task is stale: check the
  guest, run the `qm unlock` or `pct unlock` the error names, then run it again. The fenced
  operation ends there: `operation_retry` refuses it, because a retry would resume it with the
  power it recorded before the fence. Submit the action again. The guest stays stopped until
  someone starts it.
- Each new run reads the guest's power again, so a retry never runs on a guest the last run
  brought back.
- A run that succeeded is not repeated: when the guest does not come back, a retry only starts it.
- `rewinds`: the operation may bring the disk back to an earlier state. It must also be
  `stopped`. carrel treats the guest's access files as unknown and pushes the principals again.
- The start carries a digest of what carrel did around the operation (`operation_spec`). The agent
  starts it only if the plugin declares the same now. A plugin must refuse a `stopped` start whose
  `machine` does not say `power_state` stopped: an older agent sends none.

#### Installing plugins

The site file lists the plugins a site runs (#662). carrel installs them on every agent node and
removes every plugin the list no longer names:

```json
"plugins": [
  {"name": "snapshot", "version": "1.0.0", "url": "https://github.com/<org>/<repo>/releases/download/v1.0.0/snapshot.tar.gz",
   "sha256": "<64 lowercase hex digits>"}
]
```

- `deploy-go.py` reads the list from `/etc/carrel/site.json` on the host, downloads each `url` and
  checks its `sha256`. The nodes need no outbound access. A bad entry or a wrong checksum stops the
  deploy before anything changes.
- After the control plane is healthy, `configure-nodes.py --agent-service` unpacks each artifact to
  `/usr/local/lib/carrel/plugins/<name>/<version>` and points `current` at it. A plugin restarts
  only when its version or its unit changed. A plugin that changed must then answer Describe and Probe (`carrel-agent -check-plugin`); if it does not, `current` returns to the previous version, which stays, and the run fails. Older versions and their artifacts are removed once the new one answers.
- carrel writes the units, not the artifact. `carrel-plugin-<name>.socket` holds
  `/run/carrel/plugins/<name>.sock`, owned by root with mode 0600. systemd starts
  `carrel-plugin-<name>.service` on the first connection, as a dynamic user that can write only
  its state directory. A plugin that keeps failing is restarted every 5 s, and its socket stays.
- `network: true` lets the plugin open network sockets; without it, it has unix sockets only.
  `env_file: true` reads `/etc/carrel/plugins/<name>.env`, which the operator writes, for
  credentials such as an API token. Make it root's, mode 0600: other plugins can read
  `/etc/carrel`.
- Every plugin service is capped at `TasksMax=256`, `MemoryMax=512M` and `CPUQuota=100%`, so a
  leaking or forking plugin cannot starve the node. Raise one per plugin with `tasks_max`,
  `memory_max` (such as `2G`) or `cpu_quota` (such as `200%`) in its site file entry.
- A plugin removed from the list loses its units and program. Its state directory stays, so a
  plugin listed again keeps its operations.

The artifact is a `.tar.gz` with an executable `plugin` at its top. It serves the contract on the
socket systemd passes it as fd 3 (`LISTEN_FDS=1`), and keeps its state in `$STATE_DIRECTORY`.

#### The snapshot plugin

`plugins/snapshot` takes, deletes and rolls back disk snapshots through the PVE HTTP API (#663).
It has its own release, tagged `snapshot-v<version>`, whose `snapshot.tar.gz` a site file lists
with `network: true` and `env_file: true`. Until the core snapshot tools are removed, their
names win and the plugin's tools are left out.

1. Run `scripts/configure-snapshot-plugin.py` as root on every node that runs the plugin. It
   makes the token `root@pam!carrel-snapshot` with `VM.Audit`, `VM.Snapshot` and
   `VM.Snapshot.Rollback` on `/vms`, and nothing else: power stays with carrel. The secret is
   kept in `/etc/pve/priv/carrel-snapshot.json`, so every node uses one token.
2. The script writes `/etc/carrel/plugins/snapshot.env` (root's, mode 0600) with the API URL, the
   token and this node's PVE name, read from `/etc/pve/local`: it can differ from the host name.
3. It copies the cluster CA to `/etc/carrel/plugins/snapshot-ca.pem`, mode 0644. The plugin's
   dynamic user cannot read `/etc/pve/pve-root-ca.pem`. A second run keeps the token; one that
   finds the token without its secret replaces it. `--remove` takes all of it away.

The plugin saves each run under its idempotency key before it sends the request, and the task's
UPID once PVE answers. A plugin that restarts follows the same task; one whose answer was lost
finds the task by its type and start time, and sends the request again only when PVE has none.
A snapshot name has at least 2 characters: PVE refuses a one-character name.

#### Database schema

The database keeps its schema version in `PRAGMA user_version` (#565). At start carrel refuses a
version newer than it knows, and applies each missing migration in its own transaction. Before the
first one it copies the whole database to `<database>.schema-<from>-<stamp>` (mode 0600) and logs
`schema_migrated` with the copy's path as `backup`. For each version it migrated from it keeps
that newest copy and the oldest earlier one, logged as `first_backup`, and deletes any in between.
Openers wait on `<database>-schema.lock`, so the service and the backup timer never migrate at
once. To roll back across a migration, stop carrel and restore the `backup` copy, or the store
backup, before starting the older release; `first_backup` holds the data from before the first
upgrade, without anything written since. Releases from this one on refuse a newer database; earlier ones
do not check the version.

#### Rolling back to a release before the snapshot plugin

1. Stop carrel first (`systemctl stop carrel`). `carrel -move-snapshots-back` refuses unless
   `carrel.service` is inactive or failed, and while another carrel process holds the store's
   lock file (`<database>.lock`).
2. Run `runuser -u carrel -- carrel -move-snapshots-back` with the newer binary: as the service's
   user, so the lock file and the database stay the service's. It moves the plugin's snapshot records
   back to core rows, so the older release charges each snapshot once. It also removes the
   plugin's tool and quota site rows, so the older release does not treat `snapshots` and
   `snapshot_gb` as plugin dimensions or route snapshot calls to plugin tools. It refuses, changing
   nothing, while a snapshot operation runs or a record is not ready.
3. Start the older release.

A deploy (`scripts/deploy-go.py`) restores the previous binaries when the new version fails its
health check, but it does not run the move back. A failed deploy after the forward move committed starts
the older release with the records still in the plugin ledger, which is how a collision below
happens. After such a rollback, stop carrel and run the move back with the newer binary as above.

If the older release took a snapshot under a name the plugin ledger already holds, it recorded
the existing PVE snapshot as `ready` again, without taking a new one: PVE keeps one snapshot per VM
and name. When the core row and the record agree on configuration and size, both moves merge them
and name the core row they gave up: the move back under `replaced`, the forward move under
`dropped` in the `snapshot_migration` log.

When they differ, a member deleted that snapshot on the older release and took a new one under
other resources, and only PVE can tell which row is right. Both moves then stop with `has a core
row and a plugin record that differ` and change nothing. Compare the 2 rows with
`qm config <vmid> --snapshot <name>`, then, with carrel stopped and the store backed up, delete the
wrong one (`snapshots/<vmid>-<name>` or `plugin_objects/snapshot/snapshot/<vmid>/<name>` in
`objects`) and run the move again. Do not touch PVE, or the tenant loses that snapshot.

## Identity provider

`issuer` in `config.json` names the OIDC provider members sign in with. Carrel reads its
`/.well-known/openid-configuration` for the signing keys and the authorize, token and revoke
endpoints. A provider without discovery, or a document whose `issuer` differs or whose endpoint
uses another scheme, gets Keycloak's paths under the issuer. `issuer` must be an https URL, and a
trailing `/` is ignored. The sign-in callback requires `iss` (RFC 9207) only when discovery says
`authorization_response_iss_parameter_supported` is true. A provider whose discovery lists no
`revocation_endpoint` is not asked to revoke. Carrel refuses redirects from the provider.

The `oidc` block names the provider's claims and groups. Every field is optional, and an empty one
keeps WinLab's value:

```json
"oidc": {
  "audience": "carrel-mcp",
  "client_id": "carrel-mcp",
  "client_secret_file": "/etc/carrel/oidc-secret",
  "username_claim": "preferred_username",
  "groups_claim": "groups",
  "admin_groups": ["winlab-admin"],
  "member_groups": ["lab-member/112", "lab-member/master"],
  "project_group_prefix": "winlab-projects/"
}
```

- `audience` is the `aud` every token carries.
- `client_id` is the client Carrel signs members in with. A token names it in `azp`, or in
  `client_id` when it has no `azp` (RFC 9068).
- `client_secret_file` is a file holding the secret of a confidential client. Carrel sends it with
  every token and revocation request. Empty: a public client.
- `admin_groups` and `member_groups` are patterns over group names without the leading `/`:
  `staff/*` matches `staff/phd` but not `staff/phd/old`. WinLab's default lists 9 member groups.
- A group `<project_group_prefix><name>` makes the member a member of project tenant `<name>`.
  Carrel stores the tenant as `winlab-projects/<name>` whatever the prefix, so a new prefix keeps
  existing project tenants.

A bad pattern stops the service at start. Carrel keeps its own OAuth proxy, since many providers
have no dynamic client registration: a claude.ai team connector can instead use its own OAuth
client with `client_id`.

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

The portal key goes into the machine once, at creation. A retried creation (`operation_retry`,
by anyone) uses the key the first attempt read. A key removed from the portal later stays on the
machines made with it, and carrel-keys and the jump host follow the tenant's saved keys only.

## How fast access ends

A member or key that loses access keeps it for at most 24 hours. This is the accepted limit
(#358, #282): a lab certificate stays valid until it expires, on the jump host and on the
machine, and nothing checks a revocation list. A saved key removed with `ssh_key_remove` stops
working on the jump host at its next sync, and on a machine that runs carrel-keys at its next
pull. A machine without carrel-keys keeps the keys it was created with. To end access at once,
remove the key from the machine itself or stop the machine.

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

### Function host keys

Each function host's `carrel-fnd` makes its own key on the first start (`/etc/carrel-fn/env.key`)
and registers the public key. From then on function environments and registry credentials are
sealed to that key, and
carrel cannot open them; `-reseal-function-values` counts them under `host` and leaves them alone.
The first registration seals the host's older values again, then runs `VACUUM` and empties the
write-ahead log, so the database files keep no copy under `function_env_key`. Backups taken before
still hold those copies: they open with `function_env_key`, so keep that key as secret as the
backups until they expire.

After a function host is rebuilt, its agent logs `the control plane holds another key for this
host` with the new fingerprint, and versions sealed to the old key fail. Check the fingerprint on
the host's log, then on the control plane run:

```sh
carrel -trust-function-host-key fn01=SHA256:...
```

Members then upload each function's environment again with `function_env`, after the trust:
an upload before it is sealed to the old key and fails on the rebuilt host.

Rolling carrel or `carrel-fnd` back to a release before host keys is one way for these values: an
older carrel answers 409 for them, and an older `carrel-fnd` keeps asking for them. Members upload
the environments again after such a rollback.

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
