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
  ⚡ machine_create { kind: "vm", image: "ubuntu-24.04", size: "medium", nested_virt: true }
✓ sdn-hw ready: ssh -p 20170 ubuntu@<public address>
```

## Status and connection

The first B09 deployment is running at **https://carrel.winlab.tw/mcp** (Streamable HTTP,
OAuth through the WinLab Keycloak realm). In Claude Code:

```sh
claude mcp add --transport http carrel https://carrel.winlab.tw/mcp
# Open /mcp, select carrel, and authenticate with your own WinLab account.
```

Other MCP clients can use the same URL and OAuth discovery. Dynamic registration accepts
loopback callbacks and the explicitly configured ChatGPT callback. A new hosted client's callback
must be added by an administrator; arbitrary callback origins are refused.

Start with `whoami`, accept the use policy, add a **public** SSH key with `ssh_key_add`, and
check `quota_get`. Dry-run `machine_create` before creating a VM. Its result contains the actual
public SSH command. VM user: `user`; CT user: `root`. Never put private SSH keys or tokens in tool
arguments. Registration requires current `lab-member` membership or exact `winlab-admin` membership.
Project membership selects shared project tenants. All administrator tools check the admin group.

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
