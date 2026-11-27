# Staging site

A nested Proxmox VE node for installing carrel from scratch (#569, PLAN 10.5).

- Host: VM 1110 `carrel-stg01` on anvil, 10.10.11.110, 8 vCPU, 16 GiB, CPU type `host`.
- Guest storage: ZFS pool `tank` on a second 120 GB disk.
- Public network: there is no real prefix. `edge.sh` (installed as `/usr/local/sbin/stg-edge`, run by `stg-edge.service`) makes a network namespace that holds the gateway `198.18.61.1` on VLAN 61 of `vmbr0` and NATs both ways. `198.18.0.0/15` is a benchmark range, so the installer's ingress filter does not drop it as private.
- DNS: a zyx.tw subdomain set as `domain` in CT 100's `config.json` (decision 13.11).

Install, as root on the node:

```sh
scripts/install.sh --site sites/stg/cluster.json --admin-key admin.pub
```
