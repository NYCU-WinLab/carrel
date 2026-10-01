#!/usr/bin/env python3
"""Configure the single-node SDN baseline. Peers need a separate underlay rollout."""

import json
from pathlib import Path
import socket
import subprocess


def run(*args):
    p = subprocess.run(args, check=True, text=True, capture_output=True)
    return p.stdout.strip()


def main():
    node = socket.gethostname().split(".")[0]
    assert node in ("carrel01", "carrel-stg01")
    address = "192.168.13.159" if node == "carrel01" else "172.31.255.2"
    # PVE's SDN regeneration hook requires dnsmasq@.service even though carrel
    # runs its own reservations-only DHCP instance for EVPN.
    run("systemctl", "mask", "dnsmasq.service")
    run("apt-get", "install", "-y", "dnsmasq")
    run("systemctl", "enable", "--now", "frr")
    for path, key, ident, args in [
        ("controllers", "controller", "carrel", ["--type", "evpn", "--asn", "65009", "--peers", address]),
        (
            "zones",
            "zone",
            "tenants",
            [
                "--type",
                "evpn",
                "--controller",
                "carrel",
                "--vrf-vxlan",
                "99999",
                "--mtu",
                "1450",
                "--exitnodes",
                node,
                "--exitnodes-local-routing",
                "1",
                "--advertise-subnets",
                "1",
            ],
        ),
        ("zones", "zone", "private", ["--type", "vxlan", "--peers", address, "--mtu", "1450"]),
    ]:
        objects = json.loads(run("pvesh", "get", "/cluster/sdn/" + path, "--output-format", "json"))
        if not any(x[key] == ident for x in objects):
            run("pvesh", "create", "/cluster/sdn/" + path, "--" + key, ident, *args)
    Path("/etc/carrel").mkdir(exist_ok=True)
    Path("/var/lib/carrel").mkdir(exist_ok=True)
    Path("/etc/carrel/node.json").write_text(
        json.dumps({"protected_addresses": [address + "/32", "140.113.194.229/32", "140.113.60.189/32"]})
    )
    # A separate owned table, never a flush of Proxmox/staging/edge rules.
    Path("/etc/carrel/tenant-host.nft").write_text("""add table inet carrel_tenant_host
flush table inet carrel_tenant_host
table inet carrel_tenant_host {
 chain input {
  type filter hook input priority -25; policy accept;
  iifname { "t*", "vrf_tenants" } udp sport 68 udp dport 67 accept
  ip saddr 10.200.0.0/16 udp sport 68 udp dport 67 accept
  ip saddr { 10.200.0.2, 10.200.0.3 } accept
  ip saddr 10.200.0.0/16 counter drop
  iifname "t*" counter drop
  iifname "vrf_tenants" counter drop
  udp dport 4789 counter drop
  tcp dport 179 counter drop
 }
}
""")
    Path("/etc/systemd/system/carrel-tenant-host.service").write_text("""[Unit]
Description=Carrel tenant host and underlay protection
After=network.target
Before=pve-guests.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/carrel/tenant-host.nft
ExecReload=/usr/sbin/nft -f /etc/carrel/tenant-host.nft
[Install]
WantedBy=multi-user.target
""")
    Path("/etc/carrel/dhcp.conf").touch(exist_ok=True)
    if not Path("/etc/carrel/dhcp.conf").read_text():
        Path("/etc/carrel/dhcp.conf").write_text(
            "port=0\nbind-dynamic\nexcept-interface=lo\nno-dhcp-interface=vmbr0\n"
        )
    Path("/etc/systemd/system/carrel-dhcp.service").write_text("""[Unit]
Description=Carrel reserved-address DHCP
After=network.target frr.service
[Service]
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/carrel/dhcp.conf --user=root
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
""")
    Path("/etc/sysctl.d/91-carrel-tenants.conf").write_text(
        "net.ipv4.ip_forward=1\nnet.ipv4.udp_l3mdev_accept=1\nnet.ipv4.conf.all.rp_filter=0\nnet.ipv4.conf.default.rp_filter=0\n"
    )
    Path("/etc/network/if-up.d/carrel-vrf").write_text(
        '#!/bin/sh\n[ "$IFACE" = xvrfp_tenants ] || exit 0\nip route replace vrf vrf_tenants default via 10.255.255.1 dev xvrfp_tenants\n'
    )
    Path("/etc/network/if-up.d/carrel-vrf").chmod(0o755)
    Path("/etc/systemd/system/carrel-conntrack.service").write_text("""[Unit]
Description=Carrel cross-VRF connection tracking
After=network.target
Before=pve-guests.service
ConditionPathExists=/etc/carrel/conntrack.nft
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/carrel/conntrack.nft
[Install]
WantedBy=multi-user.target
""")
    run("sysctl", "-p", "/etc/sysctl.d/91-carrel-tenants.conf")
    firewall = Path("/etc/pve/firewall/cluster.fw")
    if not firewall.exists():
        firewall.write_text("[OPTIONS]\nenable: 1\npolicy_in: ACCEPT\npolicy_out: ACCEPT\n")
    run("pvesh", "set", f"/nodes/{node}/firewall/options", "--nftables", "1")
    run("systemctl", "daemon-reload")
    run("nft", "-c", "-f", "/etc/carrel/tenant-host.nft")
    run(
        "systemctl",
        "enable",
        "--now",
        "proxmox-firewall",
        "carrel-tenant-host",
        "carrel-dhcp",
        "carrel-conntrack",
    )
    storage = json.loads(run("pvesh", "get", "/storage/local", "--output-format", "json"))
    content = set(storage["content"].split(","))
    if "snippets" not in content:
        run("pvesm", "set", "local", "--content", ",".join(sorted(content | {"snippets"})))
    print(json.dumps({"node": node, "zones": ["tenants", "private"], "firewall": "nftables"}))


if __name__ == "__main__":
    main()
