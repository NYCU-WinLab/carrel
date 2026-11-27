# Staging site

A nested Proxmox VE node for installing carrel from scratch (#569, PLAN 10.5).

- Host: VM 1110 `carrel-stg01` on anvil, 10.10.11.110, 8 vCPU, 16 GiB, CPU type `host`.
- Guest storage: ZFS pool `tank` on a second 120 GB disk.
- Public network: there is no real prefix. `edge.sh` (installed as `/usr/local/sbin/stg-edge`, run by `stg-edge.service`) makes a network namespace that holds the gateway `198.18.61.1` on VLAN 61 of `vmbr0` and NATs both ways. `198.18.0.0/15` is a benchmark range, so the installer's ingress filter does not drop it as private.
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
