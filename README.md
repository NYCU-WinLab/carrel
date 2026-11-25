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

## Documentation

| Reader | Document |
|---|---|
| Members and their agents | [docs/member-guide.md](docs/member-guide.md) |
| Admins who run a site | [docs/operator-handbook.md](docs/operator-handbook.md) |
| People changing carrel | [docs/developer-guide.md](docs/developer-guide.md) and [AGENTS.md](AGENTS.md) |
| Design and decisions | [PLAN.md](PLAN.md) |

## License

Private to NYCU WinLab.
