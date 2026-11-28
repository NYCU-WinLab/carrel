# Staging site

A nested Proxmox VE node for installing carrel from scratch (#569, PLAN 10.5).

- Host: VM 1110 `carrel-stg01` on anvil, 10.10.11.110, 8 vCPU, 16 GiB, CPU type `host`.
- Guest storage: ZFS pool `tank` on a second 120 GB disk.
- Second node (M10): VM 1112 `carrel-stg02` on anvil, 10.10.11.112, the same size, joined with `install.sh --join carrel-stg01`. It has no public interface. The anvil firewalls of VM 1110 and VM 1112 accept traffic to each other ahead of the `spoke` group, which otherwise drops guest to guest traffic. Its interface is `ens18`, and cloud-init is disabled (`/etc/cloud/cloud-init.disabled`) so it does not rewrite `/etc/hosts` at boot.
- Shared storage: NFS `stg-shared` (`10.10.11.111:/srv/stg-shared`, on the PBS VM 1111) holds ISOs, imported images and the disks of linked clones while they move between nodes, as `rs822rp1` does on B09. With two nodes, `install-network.py` refuses `fetch` on `local`. The anvil firewalls of VM 1110 and VM 1112 accept TCP 2049 and 8007 to VM 1111.
- Public network: there is no real prefix. `edge.sh` (installed as `/usr/local/sbin/stg-edge`, run by `stg-edge.service`) makes a network namespace that holds the gateway `198.18.61.1` on VLAN 61 of `vmbr0` and NATs both ways. `198.18.0.0/15` is a benchmark range, so the installer's ingress filter does not drop it as private.
- Tailnet access: anvil joins VLAN 61 as `198.18.61.2` (`carrel-stg-route.service` on anvil) and advertises `198.18.61.0/24` to the tailnet (zyx-tw/network#9). It SNATs tailnet clients to `198.18.61.2`, so they reach `198.18.61.10` through the public interface, the way the internet does. A route to the node's `vmbr0` address does not work for tenant ports: the return path leaves through the edge gateway.
- DNS: the zone `zhanyongxiang.com`, set as `domain` in CT 100's `config.json` (decision 13.11). Sign-in uses the winlab Keycloak client `carrel-stg`, whose only redirect is `https://carrel.zhanyongxiang.com/oauth/callback`.
- Root SSH: cloud-init's `disable_root` is turned off (`/etc/cloud/cloud.cfg.d/99-carrel-root.cfg`), because `deploy-go.py` connects as root.

Install, as root on the node:

```sh
scripts/install.sh --site sites/stg/cluster.json --admin-key admin.pub
```

Edge units, copied to `/etc/systemd/system/` on the node:

- `stg-edge.service` runs `edge.sh` once at boot.
- `stg-edge-heal.service` and `stg-edge.timer` run `edge.sh` again every minute. A network reload by the installer (`ifreload`) takes `edge-br` out of `vmbr0`, and the public address stops answering until it is attached again. `edge.sh` is safe to run any number of times.

```sh
install -m 755 sites/stg/edge.sh /usr/local/sbin/stg-edge
cp sites/stg/stg-edge*.service sites/stg/stg-edge.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now stg-edge.service stg-edge.timer
```

## Skill bench

`scripts/skill-bench.py` (PLAN 4.5.3) runs here. The pieces in `bench/`:

- `bench.py arm` is the `--arm-command`: it sets `skills_hidden` in CT 100's `config.json`, restarts the control plane, and recreates the case's machines.
- `bench.py oracle` serves the admin paths the cases check (`/admin/machines/<name>/ssh-check` and `/ports`) on `127.0.0.1:8790`.
- `agent.sh` is the `--agent-cmd`: it runs each agent in the bench container, CT 1113 `carrel-bench` on anvil (10.10.11.113).

The agents never run on an operator's machine. They run with `bypassPermissions`, and on macOS `ssh` reads the account's real home, not `$HOME`: an early run added the operator's public keys to a test machine and wrote to the operator's `~/.ssh/config`.

CT 1113 is in the `spoke` firewall group: it reaches the internet and the public address, not the nodes. Inside it:

- User `agent` (unprivileged) with Claude Code, Codex and `codex-code-mode-host` (Codex 0.172 needs it) in `~/.local/bin`, `~/run-claude.sh` and `~/run-codex.sh` (from `bench/`), and its own key pair in `~/.ssh`.
- The key comment is `member@laptop` and the hostname `laptop`: an agent that reads `bench-agent` there takes the key for the bench's, not the member's, and asks for another one (Codex did, twice).
- Both agents use a subscription, not an API key:
  - `~/.claude.env` (mode 600) holds `CLAUDE_CODE_OAUTH_TOKEN`.
  - `~/.codex/auth.json` is a ChatGPT sign-in made in the CT with `codex login --device-auth`. Do not copy it from another machine: the two copies would refresh the same token.
- Each run starts from an empty agent config, an empty work directory and only the key pair in `~/.ssh`.

Run, from a clone on the operator's machine, with a member token from `login.py` (it lasts about 30 minutes) and a copy of the agent's private key:

```sh
export CARREL_TOKEN_FILE=/path/to/token BENCH_KEY=/path/to/bench-key
python3 sites/stg/bench/bench.py oracle &
python3 scripts/skill-bench.py rescue --runs 1 --agents claude --admin-url http://127.0.0.1:8790 \
  --arm-command "python3 sites/stg/bench/bench.py arm" --agent-cmd claude=sites/stg/bench/agent.sh
```

For Codex, pass `--agents codex --agent-cmd "codex=sites/stg/bench/agent.sh codex"`.
