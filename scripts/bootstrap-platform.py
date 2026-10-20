#!/usr/bin/env python3
"""Bootstrap owned infrastructure only. Run locally on a PVE 9 node as root.

Run on the first exit node of the site file, which holds CT 100 and CT 101.
Never touches tenant disks.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

# The gateway's Caddy: Debian's package gives the unit and the user; the
# official release (older ones reject stream_close_delay) is the binary.
CADDY_VERSION = "2.11.4"
CADDY_SHA512 = "8220d1f013b6f27510247b2360c9e0ca9f018feebd82515f07635318b34ff9777ccc8fd0b6e6f2486ce3a33fe389fbb7db12d05baa474f4587509fb4f5ebf1c9"
CADDY_UNIT = """[Service]
ExecStart=
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
Restart=on-failure
RestartSec=3
"""


def run(*args, capture=False):
    p = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return p.stdout.strip() if capture else None


def write(path, data, mode=0o644):
    p = Path(path)
    if p.exists() and p.read_text() == data:
        return False
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data)
    p.chmod(mode)
    return True


def ct(vmid, name, ip, bridge, gateway, memory, key, storage):
    config = Path(f"/etc/pve/lxc/{vmid}.conf")
    if config.exists():
        if f"hostname: {name}\n" not in config.read_text() or "carrel-infra" not in config.read_text():
            raise RuntimeError(f"refusing existing unowned CT {vmid}")
        return
    template = "debian-13-standard_13.1-2_amd64.tar.zst"
    if not Path(f"/var/lib/vz/template/cache/{template}").exists():
        run("pveam", "download", "local", template)
    run(
        "pct",
        "create",
        str(vmid),
        f"local:vztmpl/{template}",
        "--hostname",
        name,
        "--unprivileged",
        "1",
        "--features",
        "nesting=1",
        "--cores",
        "2",
        "--memory",
        str(memory),
        "--swap",
        "0",
        "--rootfs",
        f"{storage}:12",
        "--onboot",
        "1",
        "--startup",
        "order=2,up=5",
        "--tags",
        "carrel-infra",
        "--net0",
        # The infra bridge runs at the tenant MTU; a 1500-byte CT NIC there
        # drops large replies to clients that reach it directly (PLAN 15.15).
        f"name=eth0,bridge={bridge},ip={ip}/24,gw={gateway},type=veth" + (",mtu=1450" if bridge == "vmbr98" else ""),
        "--nameserver",
        "1.1.1.1",
        "--ssh-public-keys",
        key,
    )
    run("pct", "start", str(vmid))
    run("pct", "exec", str(vmid), "--", "mkdir", "-p", "/etc/systemd/system/systemd-journald.service.d")
    fix = Path("/tmp/carrel-journald.conf")
    fix.write_text("[Service]\nImportCredential=\n")
    run("pct", "push", str(vmid), str(fix), "/etc/systemd/system/systemd-journald.service.d/carrel.conf")
    run("pct", "exec", str(vmid), "--", "systemctl", "daemon-reload")
    run("pct", "exec", str(vmid), "--", "systemctl", "reset-failed", "systemd-journald")
    run("pct", "exec", str(vmid), "--", "systemctl", "restart", "systemd-journald")


SITE = Path("/etc/carrel/site.json")


def underlay(config, node):
    # Same rule as install-network.py (PLAN 6.3): VXLAN and BGP from the other
    # site nodes on the underlay interface only; dropped everywhere else.
    rules = []
    addresses = {n["name"]: str(ipaddress.IPv4Address(n["address"])) for n in config["nodes"]}
    peers = [a for n, a in addresses.items() if n != node]
    if peers and node in addresses:
        for match in ("udp dport 4789", "tcp dport 179"):
            rules.append(f'iifname "{config["underlay_interface"]}" ip saddr {{ {", ".join(peers)} }} '
                         f"ip daddr {addresses[node]} {match} accept")
    return rules + ["udp dport 4789 counter drop", "tcp dport 179 counter drop"]


def peer_ssh(config, node):
    # PLAN 15.15 gap 5: the control plane reaches the other nodes' adapters
    # over SSH on their management addresses (masqueraded as this node).
    peers = [str(ipaddress.IPv4Address(n["address"])) for n in config["nodes"] if n["name"] != node]
    return [f'iifname "vmbr98" ip saddr 10.200.0.3 ip daddr {{ {", ".join(peers)} }} tcp dport 22 accept'] if peers else []


def caddy(vmid):
    """Install the pinned official Caddy in the gateway CT."""
    with tempfile.TemporaryDirectory() as temp:
        url = f"https://github.com/caddyserver/caddy/releases/download/v{CADDY_VERSION}/caddy_{CADDY_VERSION}_linux_amd64.tar.gz"
        archive = Path(temp) / "caddy.tar.gz"
        archive.write_bytes(urllib.request.urlopen(url, timeout=60).read())
        if hashlib.sha512(archive.read_bytes()).hexdigest() != CADDY_SHA512:
            raise SystemExit("Caddy checksum mismatch")
        binary, unit = Path(temp) / "caddy", Path(temp) / "carrel.conf"
        with tarfile.open(archive) as tar:
            binary.write_bytes(tar.extractfile("caddy").read())
        unit.write_text(CADDY_UNIT)
        run("pct", "push", str(vmid), str(binary), "/usr/local/bin/caddy", "--perms", "755")
        run("pct", "exec", str(vmid), "--", "mkdir", "-p", "/etc/systemd/system/caddy.service.d")
        run("pct", "push", str(vmid), str(unit), "/etc/systemd/system/caddy.service.d/carrel.conf", "--perms", "644")
    run("pct", "exec", str(vmid), "--", "systemctl", "daemon-reload")
    run("pct", "exec", str(vmid), "--", "/usr/local/bin/caddy", "version")


def packages(vmid, role):
    run("pct", "exec", str(vmid), "--", "apt-get", "update", "-qq")
    wanted = ["ca-certificates", "curl"]
    if role == "control":
        wanted += ["openssh-client"]
    else:
        wanted += ["caddy", "dnsmasq-base", "python3"]
    run("pct", "exec", str(vmid), "--", "apt-get", "install", "-y", *wanted)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--admin-key", required=True)
    a = p.parse_args()
    assert os.geteuid() == 0
    host = run("hostname", "-s", capture=True)
    config = json.loads(SITE.read_text())
    assert host == config["exit_nodes"][0], "run on the first exit node of the site file"
    storage = config["storage"]
    run("apt-get", "update", "-qq")
    run("apt-get", "install", "-y", "dnsmasq-base")
    bridge = """# Managed by carrel infrastructure bootstrap
auto vmbr98
iface vmbr98 inet static
    address 10.200.0.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    mtu 1450
"""
    if write("/etc/network/interfaces.d/carrel-infra", bridge):
        run("ifup", "vmbr98")
    rules = """add table inet carrel_infra
flush table inet carrel_infra
table inet carrel_infra {
 chain input {
  type filter hook input priority -15; policy accept;
  iifname "vmbr98" ct state established,related accept
  iifname "vmbr98" ip saddr 10.200.0.3 tcp dport 22 accept
  iifname "vmbr98" counter drop
UNDERLAY
 }
 chain forward {
  type filter hook forward priority -15; policy accept;
  iifname "vmbr98" ip saddr != { 10.200.0.2, 10.200.0.3 } counter drop
  iifname "vmbr98" meta nfproto ipv6 drop
  iifname "vmbr98" ct state established,related accept
  iifname "vmbr98" ip daddr 10.200.0.0/16 accept
PEER_SSH
  iifname "vmbr98" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop
  iifname "vmbr98" tcp dport 25 drop
  oifname "vmbr98" ct state established,related accept
  oifname "vmbr98" udp dport 53 ip daddr 10.200.0.2 accept
  oifname "vmbr98" tcp dport 53 ip daddr 10.200.0.2 accept
  oifname "vmbr98" ip saddr 10.200.0.0/16 ip daddr 10.200.0.3 tcp dport 8080 accept
  oifname "vmbr98" ct status dnat ip daddr 10.200.0.2 tcp dport { 80, 443 } accept
  oifname "vmbr98" ip saddr 10.200.0.0/16 ip daddr 10.200.0.2 tcp dport { 80, 443 } accept
  oifname "vmbr98" counter drop
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.200.0.0/24 oifname "vmbr0" masquerade
 }
}
"""
    rules = rules.replace("UNDERLAY", "\n".join("  " + rule for rule in underlay(config, host)))
    rules = rules.replace("PEER_SSH\n", "".join("  " + rule + "\n" for rule in peer_ssh(config, host)))
    write("/etc/carrel/infra.nft", rules)
    run("nft", "-c", "-f", "/etc/carrel/infra.nft")
    run("nft", "-f", "/etc/carrel/infra.nft")
    write(
        "/etc/systemd/system/carrel-infra-firewall.service",
        """[Unit]
Description=Carrel infrastructure isolation
After=network.target
Before=pve-guests.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/carrel/infra.nft
ExecReload=/usr/sbin/nft -f /etc/carrel/infra.nft
[Install]
WantedBy=multi-user.target
""",
    )
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", "carrel-infra-firewall")
    ct(100, "carrel-control", "10.200.0.3", "vmbr98", "10.200.0.1", 2048, a.admin_key, storage)
    ct(101, "carrel-gateway", "10.200.0.2", "vmbr98", "10.200.0.1", 512, a.admin_key, storage)
    packages(100, "control")
    packages(101, "gateway")
    caddy(101)
    print(json.dumps({"node": host, "infra_cts": [100, 101]}))


if __name__ == "__main__":
    main()
