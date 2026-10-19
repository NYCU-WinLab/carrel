#!/usr/bin/env python3
"""Configure the SDN baseline on one node.

With a site file (/etc/carrel/site.json, from sites/<site>/cluster.json) the EVPN
and VXLAN peers, the exit nodes and the underlay filter cover every node. Without
one, the R640 node and its nested staging keep their single-node layout.
"""

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import subprocess


# Tenant vnets are t001, t002, ... (node-agent's f"t{n:03d}") and guest taps are tap*.
# nft has no character classes, so "t" plus a digit is spelled out; a bare "t*" would
# also drop host interfaces such as tailscale0.
TENANT_IFACES = ", ".join([f'"t{d}*"' for d in range(10)] + ['"tap*"'])

def underlay_rules(interface, address, peers):
    # PLAN 6.3: VXLAN and BGP only on the underlay interface, to this node's own
    # address, from another node. With no peers both stay dropped everywhere.
    rules = []
    if peers:
        sources = ", ".join(peers)
        for match in ("udp dport 4789", "tcp dport 179"):
            rules.append(f'iifname "{interface}" ip saddr {{ {sources} }} ip daddr {address} {match} accept')
    return rules + ["udp dport 4789 counter drop", "tcp dport 179 counter drop"]


def tenant_host_nft(underlay):
    rules = "\n".join("  " + rule for rule in underlay)
    return f"""add table inet carrel_tenant_host
flush table inet carrel_tenant_host
table inet carrel_tenant_host {{
 chain input {{
  type filter hook input priority -25; policy accept;
  iifname {{ {TENANT_IFACES}, "vrf_tenants" }} udp sport 68 udp dport 67 accept
  ip saddr 10.200.0.0/16 udp sport 68 udp dport 67 accept
  iifname "vmbr98" ip saddr {{ 10.200.0.2, 10.200.0.3 }} accept
  ip saddr 10.200.0.0/16 counter drop
  iifname {{ {TENANT_IFACES} }} counter drop
  iifname "vrf_tenants" counter drop
{rules}
 }}
}}
"""


# The single-node table: no peers, so VXLAN and BGP are dropped everywhere.
TENANT_HOST_NFT = tenant_host_nft(underlay_rules("vmbr0", "", []))


def site_layout(node, site):
    """Return this node's address, the other nodes' addresses and the exit nodes."""
    if site is None:
        # The R640 node and its nested staging predate site files.
        assert node in ("carrel01", "carrel-stg01")
        address = "192.168.13.159" if node == "carrel01" else "172.31.255.2"
        return {"address": address, "peers": [], "exit_nodes": [node], "interface": "vmbr0",
                "protected": [address + "/32", "140.113.194.229/32", "140.113.60.189/32"],
                "entries": [{"address": "140.113.194.229/32", "port": 443}]}
    addresses = {n["name"]: str(ipaddress.IPv4Address(n["address"])) for n in site["nodes"]}
    if node not in addresses:
        raise SystemExit(f"{node} is not in the site file")
    exits = site["exit_nodes"]
    if not exits or any(e not in addresses for e in exits):
        raise SystemExit("exit nodes must be site nodes")
    public = str(ipaddress.IPv4Interface(site["public"]["address"]).ip) + "/32"
    protected = [a + "/32" for a in addresses.values()] + [public]
    protected += [str(ipaddress.IPv4Network(p)) for p in site.get("protected_addresses", [])]
    return {"address": addresses[node], "peers": [a for n, a in addresses.items() if n != node],
            "all": list(addresses.values()), "exit_nodes": exits, "interface": site["underlay_interface"],
            "protected": protected, "entries": [{"address": public, "port": 443}]}


def run(*args):
    p = subprocess.run(args, check=True, text=True, capture_output=True)
    return p.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=Path("/etc/carrel/site.json"),
                        help="Site file shared by every node (sites/<site>/cluster.json)")
    args = parser.parse_args()
    node = socket.gethostname().split(".")[0]
    layout = site_layout(node, json.loads(args.site.read_text()) if args.site.exists() else None)
    address = layout["address"]
    peers = ",".join(layout.get("all", [address]))
    exits = ",".join(layout["exit_nodes"])
    # PVE's SDN regeneration hook requires dnsmasq@.service even though carrel
    # runs its own reservations-only DHCP instance for EVPN.
    run("systemctl", "mask", "dnsmasq.service")
    run("apt-get", "install", "-y", "dnsmasq")
    run("systemctl", "enable", "--now", "frr")
    sdn_changed = False
    for path, key, ident, args in [
        ("controllers", "controller", "carrel", ["--type", "evpn", "--asn", "65009", "--peers", peers]),
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
                exits,
                "--exitnodes-local-routing",
                "1",
                "--advertise-subnets",
                "1",
            ],
        ),
        ("zones", "zone", "private", ["--type", "vxlan", "--peers", peers, "--mtu", "1450"]),
    ]:
        objects = json.loads(run("pvesh", "get", "/cluster/sdn/" + path, "--output-format", "json"))
        current = next((x for x in objects if x[key] == ident), None)
        if current is None:
            run("pvesh", "create", "/cluster/sdn/" + path, "--" + key, ident, *args)
            sdn_changed = True
        else:
            # Joining a node changes peers and exit nodes; keep the rest as created.
            wanted = {"peers": peers} if "--peers" in args else {}
            if "--exitnodes" in args:
                wanted["exitnodes"] = exits
            stale = [f for f, v in wanted.items() if ",".join(sorted(str(current.get(f, "")).split(","))) != ",".join(sorted(v.split(",")))]
            if stale:
                run("pvesh", "set", f"/cluster/sdn/{path}/{ident}", *[x for f in stale for x in ("--" + f, wanted[f])])
                sdn_changed = True
    Path("/etc/carrel").mkdir(exist_ok=True)
    Path("/var/lib/carrel").mkdir(exist_ok=True)
    # Keep keys this installer does not own, such as storage and go_pve_reader.
    node_config = Path("/etc/carrel/node.json")
    config = json.loads(node_config.read_text()) if node_config.exists() else {}
    config.update(
        {
            "protected_addresses": layout["protected"],
            # The public HTTPS entry (PLAN 6.4 hairpin): carrel and lab sites live there.
            "public_entries": layout["entries"],
        }
    )
    node_config.write_text(json.dumps(config))
    # A separate owned table, never a flush of Proxmox/staging/edge rules.
    Path("/etc/carrel/tenant-host.nft").write_text(
        tenant_host_nft(underlay_rules(layout["interface"], address, layout["peers"]))
    )
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
    if sdn_changed:
        run("pvesh", "set", "/cluster/sdn")
    run(
        "systemctl",
        "enable",
        "--now",
        "proxmox-firewall",
        "carrel-tenant-host",
        "carrel-dhcp",
        "carrel-conntrack",
    )
    # enable --now leaves an already active oneshot unit with its old rules.
    run("systemctl", "reload", "carrel-tenant-host")
    storage = json.loads(run("pvesh", "get", "/storage/local", "--output-format", "json"))
    content = set(storage["content"].split(","))
    if "snippets" not in content:
        run("pvesm", "set", "local", "--content", ",".join(sorted(content | {"snippets"})))
    print(json.dumps({"node": node, "zones": ["tenants", "private"], "firewall": "nftables",
                      "peers": layout["peers"], "exit_nodes": layout["exit_nodes"]}))


if __name__ == "__main__":
    main()
