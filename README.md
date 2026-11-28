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

## Connect

The B09 site runs at **https://carrel.winlab.tw/mcp**. In Claude Code:

```sh
claude mcp add --scope user --transport http carrel https://carrel.winlab.tw/mcp
claude mcp login carrel
```

Sign in with your WinLab account, then start a new session. Codex and other clients are in the
member guide.

## Lost every key

If no saved key logs in to a VM, ask the agent to run `machine_reset_access` for it. It adds your
public key (or the keys you pass as `ssh_keys`) through cloud-init and restarts a running VM; keys
already on the VM stay and the host key does not change. A key that had `command=` or `from=` options comes back without them, so re-add them by hand, and the guest's `lock_passwd`, `timezone` and `ssh_pwauth` settings return to their creation values. Only a VM that carrel configures through
cloud-init can be reset, and the call needs `confirm` equal to the machine name. Every reset is
audited; the owner is not emailed yet (issue #821). Details are in the `rescue` skill and PLAN
section 7.10.

## Documentation

| Reader | Document |
|---|---|
| Members and their agents | [docs/member-guide.md](docs/member-guide.md) |
| Admins who run a site | [docs/operator-handbook.md](docs/operator-handbook.md) |
| People changing carrel | [docs/developer-guide.md](docs/developer-guide.md) and [AGENTS.md](AGENTS.md) |
| Design and decisions | [PLAN.md](PLAN.md) |

## License

Private to NYCU WinLab.
