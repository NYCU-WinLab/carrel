#!/usr/bin/env python3
"""Configure the SDN baseline on one node.

The site file (/etc/carrel/site.json, from sites/<site>/cluster.json) gives the
EVPN and VXLAN peers, the exit nodes and the underlay filter for every node.
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
  iifname "vmbr98" ip saddr {{ 10.200.0.2, 10.200.0.3 }} accept
  # Answers to the node's own connections, such as its public address
  # forwarded to a tenant port (issue #48); nothing new from tenants.
  ip saddr 10.200.0.0/16 ct direction reply ct state established accept
  ip saddr 10.200.0.0/16 counter drop
  iifname {{ {TENANT_IFACES} }} counter drop
  iifname "vrf_tenants" counter drop
{rules}
 }}
}}
"""


PUBLIC_MARK = "0x60"
PUBLIC_TABLE = 160


def public_nft(interface, address):
    """Host protection and return routing for the public address on the exit node.

    Nothing on the public interface reaches the host itself except replies and
    ping: SSH, 8006 and every other host port stay off the internet. Only
    connections that DNAT sends to a tenant or the infra gateway are forwarded.
    Connections that arrive here carry a mark, and only their replies get the
    routing mark: the arriving packets must still reach local addresses, which
    the l3mdev rule order puts after the policy rules.
    """
    return f"""add table inet carrel_public
flush table inet carrel_public
table inet carrel_public {{
 chain prerouting {{
  type filter hook prerouting priority mangle; policy accept;
  iifname "{interface}" ct state new ct mark set {PUBLIC_MARK}
  ct mark {PUBLIC_MARK} ct direction reply meta mark set {PUBLIC_MARK}
 }}
 chain input {{
  type filter hook input priority -30; policy accept;
  iifname "{interface}" ct state established,related accept
  iifname "{interface}" meta nfproto ipv4 icmp type echo-request limit rate 10/second accept
  # The tenants' client VPN endpoints (PLAN 6.11): WireGuard on 31000 + N.
  iifname "{interface}" udp dport 31001-31254 accept
  iifname "{interface}" counter drop
 }}
 chain forward {{
  type filter hook forward priority -30; policy accept;
  iifname "{interface}" ip saddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }} counter drop
  iifname "{interface}" ct state established,related accept
  iifname "{interface}" ct status dnat accept
  iifname "{interface}" counter drop
 }}
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  oifname "{interface}" ip saddr 10.200.0.0/16 snat to {address}
 }}
}}
"""


def public_rules(address):
    return [
        # The node's own connections to its public address that the output
        # hook sends to carrel's networks (issue #48): main, not the uplink.
        (f"from {address} to 10.200.0.0/16 lookup main priority 1599"),
        (f"fwmark {PUBLIC_MARK} lookup {PUBLIC_TABLE} priority 1600"),
        (f"from {address} lookup {PUBLIC_TABLE} priority 1601"),
        # Tenant egress leaves the VRF into main on xvrf_tenants and goes out the
        # public address (carrel_public SNATs it); carrel's own networks stay on
        # main. Local addresses come first: ARP from the VRF for 10.255.255.1
        # is answered only if that lookup finds a local route, and the local
        # table sits after these rules (l3mdev order).
        ("iif xvrf_tenants lookup local priority 1602"),
        ("iif xvrf_tenants to 10.200.0.0/16 lookup main priority 1603"),
        (f"iif xvrf_tenants lookup {PUBLIC_TABLE} priority 1604"),
        # Replies of the SSH jump host (CT 102, issue #98). Its Proxmox firewall
        # sets the conntrack mark to its VMID, so the fwmark rule misses them.
        (f"from 10.200.0.4 ipproto tcp sport 22 lookup {PUBLIC_TABLE} priority 1605"),
    ]


def public_interface(interface, cidr, gateway, address):
    network = ipaddress.IPv4Interface(cidr).network
    rules = public_rules(address)
    up = [f"    post-up ip route replace {network} dev {interface} table {PUBLIC_TABLE}",
          f"    post-up ip route replace default via {gateway} dev {interface} table {PUBLIC_TABLE}"]
    up += [f"    post-up ip rule del {r} 2>/dev/null; ip rule add {r}" for r in rules]
    down = [f"    pre-down ip rule del {r} 2>/dev/null || true" for r in rules]
    return "\n".join([
        "# Managed by carrel install-network.py: the site's public address (PLAN 15.15).",
        f"auto {interface}",
        f"iface {interface} inet static",
        f"    address {cidr}",
        # Never bring the address up without its protection.
        "    pre-up nft list table inet carrel_public > /dev/null",
        f"    post-up echo 1 > /proc/sys/net/ipv6/conf/{interface}/disable_ipv6",
        *up,
        *down,
    ]) + "\n"


def site_layout(node, site):
    """Return this node's address, the other nodes' addresses and the exit nodes."""
    addresses = {n["name"]: str(ipaddress.IPv4Address(n["address"])) for n in site["nodes"]}
    if node not in addresses:
        raise SystemExit(f"{node} is not in the site file")
    exits = site["exit_nodes"]
    if not exits or any(e not in addresses for e in exits):
        raise SystemExit("exit nodes must be site nodes")
    cidr = ipaddress.IPv4Interface(site["public"]["address"])
    public = str(cidr.ip) + "/32"
    protected = [a + "/32" for a in addresses.values()] + [public]
    protected += [str(ipaddress.IPv4Network(p)) for p in site.get("protected_addresses", [])]
    return {"address": addresses[node], "peers": [a for n, a in addresses.items() if n != node],
            "all": list(addresses.values()), "exit_nodes": exits, "interface": site["underlay_interface"],
            "protected": protected, "entries": [{"address": public, "port": 443}],
            # The first exit node holds the public address and terminates ingress.
            "public": {"interface": f'{site["underlay_interface"]}.{int(site["public"]["vlan"])}',
                       "cidr": str(cidr), "address": str(cidr.ip),
                       "gateway": str(ipaddress.IPv4Address(site["public"]["gateway"]))}
            if node == exits[0] else None}


def check_underlay(interface, address, node):
    found = json.loads(run("ip", "-j", "-4", "addr", "show", "dev", interface))
    if not any(a.get("local") == address for i in found for a in i.get("addr_info", [])):
        raise SystemExit(f"{address} is not on {interface}: this is not {node} of this site")


def mark(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()


def run(*args):
    p = subprocess.run(args, check=True, text=True, capture_output=True)
    return p.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=Path("/etc/carrel/site.json"),
                        help="Site file shared by every node (sites/<site>/cluster.json)")
    args = parser.parse_args()
    node = socket.gethostname().split(".")[0]
    layout = site_layout(node, json.loads(args.site.read_text()))
    address = layout["address"]
    # The hostname alone could match another machine, such as an older host
    # with the same name (issue #48): the site's address must be here.
    check_underlay(layout["interface"], address, node)
    peers = ",".join(layout.get("all", [address]))
    exits = ",".join(layout["exit_nodes"])
    # PVE's SDN regeneration hook requires dnsmasq@.service; carrel's private
    # network DHCP also runs dnsmasq, in its own namespace.
    run("systemctl", "mask", "dnsmasq.service")
    run("apt-get", "install", "-y", "dnsmasq", "wireguard-tools")
    run("systemctl", "enable", "--now", "frr")
    # A change made before a failed run is still owed its apply (issue #48):
    # the marker survives the failure, and the rerun applies.
    pending = Path("/var/lib/carrel/sdn-pending")
    sdn_changed = pending.exists()
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
            mark(pending)
            run("pvesh", "create", "/cluster/sdn/" + path, "--" + key, ident, *args)
            sdn_changed = True
        else:
            # Joining a node changes peers and exit nodes; keep the rest as created.
            wanted = {"peers": peers} if "--peers" in args else {}
            if "--exitnodes" in args:
                wanted["exitnodes"] = exits
            stale = [f for f, v in wanted.items() if ",".join(sorted(str(current.get(f, "")).split(","))) != ",".join(sorted(v.split(",")))]
            if stale:
                mark(pending)
                run("pvesh", "set", f"/cluster/sdn/{path}/{ident}", *[x for f in stale for x in ("--" + f, wanted[f])])
                sdn_changed = True
    Path("/etc/carrel").mkdir(exist_ok=True)
    Path("/var/lib/carrel").mkdir(exist_ok=True)
    # Keep keys this installer does not own, such as storage.
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
    public = layout.get("public")
    if public:
        # Load the protection before the address exists, at boot and now.
        Path("/etc/carrel/public.nft").write_text(public_nft(public["interface"], public["address"]))
        run("nft", "-c", "-f", "/etc/carrel/public.nft")
        run("nft", "-f", "/etc/carrel/public.nft")
        Path("/etc/systemd/system/carrel-public.service").write_text("""[Unit]
Description=Carrel public address protection
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/carrel/public.nft
ExecReload=/usr/sbin/nft -f /etc/carrel/public.nft
[Install]
WantedBy=multi-user.target
""")
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "carrel-public")
        Path("/etc/network/interfaces.d/carrel-public").write_text(
            public_interface(public["interface"], public["cidr"], public["gateway"], public["address"])
        )
        run("ifup", public["interface"])
        # ifup skips post-up on an interface already up: a rule added since
        # the last boot is applied here too.
        for rule in public_rules(public["address"]):
            # Only a missing one: deleting a present rule would leave a gap.
            priority = rule.rsplit(" ", 1)[1]
            subprocess.run(["sh", "-c", f"ip rule list priority {priority} | grep -q . || ip rule add {rule}"], check=True)
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
        pending.unlink(missing_ok=True)
    run(
        "systemctl",
        "enable",
        "--now",
        "proxmox-firewall",
        "carrel-tenant-host",
        "carrel-conntrack",
    )
    # enable --now leaves an already active oneshot unit with its old rules.
    run("systemctl", "reload", "carrel-tenant-host")
    storage = json.loads(run("pvesh", "get", "/storage/local", "--output-format", "json"))
    content = set(storage["content"].split(","))
    if "snippets" not in content:
        run("pvesm", "set", "local", "--content", ",".join(sorted(content | {"snippets"})))
    print(json.dumps({"node": node, "zones": ["tenants", "private"], "firewall": "nftables",
                      "peers": layout["peers"], "exit_nodes": layout["exit_nodes"],
                      "public": (public or {}).get("cidr")}))


if __name__ == "__main__":
    main()
