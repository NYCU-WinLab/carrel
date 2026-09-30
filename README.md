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

## Status

Private bootstrap deployed on 2026-09-30. [PLAN.md](PLAN.md) remains the only design document: scope, decisions,
address plan, tool surface, milestones and the B09 rollout record (section 15). The first host
is `carrel01` in site `b09`, using LVM-thin. The MCP server and member-facing platform are not
implemented yet. B09 currently has no assigned public ingress.

The scripts in `scripts/` prepare **admin-only staging**. They are not a complete `install.sh`
and do not establish M0 or M1 acceptance. Run them on the PVE host after reviewing the node
inventory; credentials and administrator private keys never belong in this repository.
[sites/b09/ssh-config.example](sites/b09/ssh-config.example) contains the administrator SSH aliases.

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
