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
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

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


# Same pin as CT_TEMPLATES["debian-13"] in node-agent.py (tests/test_storage.py checks).
DEBIAN_CT = ("debian-13-standard_13.6-1_amd64.tar.zst", "4c0c27ca6ceab5ef0b84db57825a00f26157ef1854bafe97297813e1cbe8ecb8cc9c453cab6b3b0efe1ba193a50c47ece1e41d950e411b8730b835b71e9e754b")

def ct_template_file(name, digest, site):
    """Make sure a pinned CT template is on the site's template storage (issue #92).

    pveam checks the signed index; the pin also holds when a file is already
    there, since on shared storage every node uses that one copy.
    """
    storage = site.get("content_storage", {}).get("vztmpl", "local")
    path = Path(run("pvesm", "path", f"{storage}:vztmpl/{name}", capture=True))
    if not path.exists():
        run("pveam", "download", storage, name)
    with path.open("rb") as f:
        if hashlib.file_digest(f, "sha512").hexdigest() != digest:
            raise SystemExit(f"CT template checksum mismatch: {path}")
    return f"{storage}:vztmpl/{name}"


def infra_mtu(vmid, bridge):
    if not (bridge == "vmbr98" or bridge.startswith("t")):
        return
    if "status: running" not in run("pct", "status", str(vmid), capture=True):
        print(f"CT {vmid} is not running: start it and rerun to set its MTU", file=sys.stderr)
        return
    # ifupdown2 in the CT resets a NIC without an mtu line to 1500 at every
    # boot, over the 1450 that pct sets: write it where it stays.
    run("pct", "exec", str(vmid), "--", "sh", "-c",
        "grep -q '^\\s*mtu 1450' /etc/network/interfaces"
        " || sed -i '/^iface eth0 inet static/a\\\tmtu 1450' /etc/network/interfaces")
    run("pct", "exec", str(vmid), "--", "ip", "link", "set", "eth0", "mtu", "1450")


def ct(vmid, name, ip, bridge, gateway, memory, key, storage, template, disk=12, nameserver="1.1.1.1", firewall=False):
    config = Path(f"/etc/pve/lxc/{vmid}.conf")
    if config.exists():
        if f"hostname: {name}\n" not in config.read_text() or "carrel-infra" not in config.read_text():
            raise RuntimeError(f"refusing existing unowned CT {vmid}")
        # A rerun repairs CTs made before this, or a create cut short after start.
        infra_mtu(vmid, bridge)
        return
    run(
        "pct",
        "create",
        str(vmid),
        template,
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
        f"{storage}:{disk}",
        "--onboot",
        "1",
        "--startup",
        "order=2,up=5",
        "--tags",
        "carrel-infra",
        "--net0",
        # The infra bridge runs at the tenant MTU; a 1500-byte CT NIC there
        # drops large replies to clients that reach it directly (PLAN 15.15).
        f"name=eth0,bridge={bridge},ip={ip}/24,gw={gateway},type=veth"
        + (",mtu=1450" if bridge == "vmbr98" or bridge.startswith("t") else "")
        + (",firewall=1,rate=25" if firewall else ""),
        "--nameserver",
        nameserver,
        "--ssh-public-keys",
        key,
    )
    run("pct", "start", str(vmid))
    infra_mtu(vmid, bridge)
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
    # The Debian package already started its older Caddy, which rejects a
    # reload from the pinned binary's config: start the pinned one now.
    run("pct", "exec", str(vmid), "--", "systemctl", "restart", "caddy")
    run("pct", "exec", str(vmid), "--", "/usr/local/bin/caddy", "version")


JUMP_SSHD = """# Managed by carrel (issue #98). The jump user forwards to port 22 of the
# machines its key may open (per-key permitopen) and gets no session.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin forced-commands-only
AuthorizedKeysFile .ssh/authorized_keys /etc/carrel-jump/%u
PermitTTY no
X11Forwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
AllowTcpForwarding local
LogLevel VERBOSE
MaxStartups 10:30:100
# Members share the campus NAT: one mistyped key must not lock out the lab.
PerSourcePenaltyExemptList 140.113.0.0/16
LoginGraceTime 20
"""


# CT 102's own firewall (issue #98): even with sshd broken into, it keeps
# its address (ipfilter) and reaches only SSH of tenant machines, DNS and
# package mirrors.
JUMP_FIREWALL = """[OPTIONS]
enable: 1
ipfilter: 1
macfilter: 1
dhcp: 0
ndp: 0
radv: 0
policy_in: DROP
policy_out: DROP

[IPSET ipfilter-net0]
10.200.0.4

[IPSET tenant-gateways]
TENANT_GATEWAYS

[RULES]
IN ACCEPT -p tcp -dport 22
OUT ACCEPT -dest 10.200.0.2 -p udp -dport 53
OUT ACCEPT -dest 10.200.0.2 -p tcp -dport 53
# Not the infra network, the fetch network or any tenant network's gateway
# (the node itself, issue #125), on any port.
OUT DROP -dest 10.200.0.0/24
OUT DROP -dest 10.200.255.0/24
OUT DROP -dest +guest/tenant-gateways
# Tenant machines: SSH (issue #98) and the declared ports of machines without
# SSH (issue #94); sshd's permitopen and each guest's firewall decide which.
OUT ACCEPT -dest 10.200.0.0/16 -p tcp
OUT DROP -dest 10.0.0.0/8
OUT DROP -dest 172.16.0.0/12
OUT DROP -dest 192.168.0.0/16
OUT DROP -dest 100.64.0.0/10
OUT ACCEPT -p tcp -dport 80
OUT ACCEPT -p tcp -dport 443
""".replace("TENANT_GATEWAYS", "\n".join(f"10.200.{n}.1" for n in range(1, 255)))


def jump(vmid):
    """The SSH jump host: one locked account, forwarding only."""
    run("pct", "exec", str(vmid), "--", "sh", "-c",
        "id jump >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent jump; "
        "install -d -m 755 /etc/carrel-jump; touch /etc/carrel-jump/jump; chmod 644 /etc/carrel-jump/jump")
    conf = Path("/tmp/carrel-jump-sshd.conf")
    conf.write_text(JUMP_SSHD)
    run("pct", "push", str(vmid), str(conf), "/etc/ssh/sshd_config.d/carrel-jump.conf", "--perms", "644")
    run("pct", "exec", str(vmid), "--", "sshd", "-t")
    # Restart, not reload: ssh.socket holds port 22 (PLAN 15.15).
    run("pct", "exec", str(vmid), "--", "systemctl", "try-restart", "ssh.service")


def packages(vmid, role):
    run("pct", "exec", str(vmid), "--", "apt-get", "update", "-qq")
    wanted = ["ca-certificates", "curl"]
    if role == "control":
        wanted += ["openssh-client"]
    elif role == "jump":
        wanted += ["openssh-server", "python3"]
    elif role == "fetch":
        wanted += ["qemu-utils"]
    else:
        wanted += ["caddy", "dnsmasq-base", "python3"]
    run("pct", "exec", str(vmid), "--", "apt-get", "install", "-y", *wanted)


def infra_firewall(config, host):
    """The infra bridge's isolation: what CT 100, 101 and 102 may reach.

    CT 102 reaches tenant machines over TCP only, on any port: SSH, and the
    declared ports of machines without SSH (Talos, issue #125). Each guest's
    firewall admits it on exactly those ports, and sshd's permitopen decides
    which machine a key opens.
    """
    rules = """add table inet carrel_infra
flush table inet carrel_infra
table inet carrel_infra {
 chain input {
  type filter hook input priority -15; policy accept;
  iifname "vmbr98" ct state established,related accept
  iifname "vmbr98" ip saddr 10.200.0.3 tcp dport 22 accept
  iifname "vmbr98" counter drop
  # CT 102 reaches a tenant gateway (the node, 10.200.N.1) through the VRF,
  # not vmbr98: drop it here too, below its own firewall.
  iifname "xvrfp_tenants" ip saddr 10.200.0.4 counter drop
UNDERLAY
 }
 chain forward {
  type filter hook forward priority -15; policy accept;
  iifname "vmbr98" ip saddr != { 10.200.0.2, 10.200.0.3, 10.200.0.4 } counter drop
  iifname "vmbr98" ip saddr 10.200.0.4 ip daddr 10.200.0.2 meta l4proto { tcp, udp } th dport 53 accept
  iifname "vmbr98" ip saddr 10.200.0.4 ip daddr { 10.200.0.0/24, 10.200.255.0/24 } drop
  iifname "vmbr98" ip saddr 10.200.0.4 ip daddr 10.200.0.0/16 meta l4proto != tcp drop
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
  oifname "vmbr98" ct status dnat ip daddr 10.200.0.4 tcp dport 22 accept
  oifname "vmbr98" ip saddr 10.200.0.0/16 ip daddr 10.200.0.2 tcp dport { 80, 443 } accept
  oifname "vmbr98" counter drop
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.200.0.0/24 oifname "MANAGEMENT" masquerade
  # CT 100 or 101 reaching the public address lands back on vmbr98 (issue
  # #48): the answer must come back through the node.
  iifname "vmbr98" oifname "vmbr98" ct status dnat masquerade
 }
}
"""
    # The management interface, which carries the infra CTs out (issue #56).
    rules = rules.replace("MANAGEMENT", config.get("management_interface", config["underlay_interface"]))
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


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--admin-key")
    p.add_argument("--firewall", action="store_true",
                   help="Only rewrite the infra firewalls, for example after a node joins the site (issue #48)")
    a = p.parse_args()
    assert os.geteuid() == 0
    host = run("hostname", "-s", capture=True)
    config = json.loads(SITE.read_text())
    assert host == config["exit_nodes"][0], "run on the first exit node of the site file"
    if a.firewall:
        infra_firewall(config, host)
        if config.get("ssh_jump"):
            write("/etc/pve/firewall/102.fw", JUMP_FIREWALL, 0o640)  # pmxcfs takes 0640 only
        return
    if not a.admin_key:
        p.error("--admin-key is required")
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
    infra_firewall(config, host)
    template = ct_template_file(*DEBIAN_CT, config)
    ct(100, "carrel-control", "10.200.0.3", "vmbr98", "10.200.0.1", 2048, a.admin_key, storage, template)
    ct(101, "carrel-gateway", "10.200.0.2", "vmbr98", "10.200.0.1", 512, a.admin_key, storage, template)
    packages(100, "control")
    packages(101, "gateway")
    caddy(101)
    infra = [100, 101]
    if config.get("ssh_jump"):
        write("/etc/pve/firewall/102.fw", JUMP_FIREWALL, 0o640)  # pmxcfs takes 0640 only
        ct(102, "carrel-jump", "10.200.0.4", "vmbr98", "10.200.0.1", 512, a.admin_key, storage, template,
           nameserver="10.200.0.2", firewall=True)
        packages(102, "jump")
        jump(102)
        infra.append(102)
    if config.get("fetch"):
        # The fetch container (PLAN 7.8) on the fetch network t255, which the
        # node adapter creates on its first reconcile with fetch enabled.
        ct(103, "carrel-fetch", "10.200.255.10", "t255", "10.200.255.1", 1024, a.admin_key, storage, template,
           disk=64, nameserver="10.200.0.2", firewall=True)
        packages(103, "fetch")
        run("pct", "exec", "103", "--", "sh", "-c",
            "id carrel-fetch >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin carrel-fetch; "
            "install -d -m 700 -o carrel-fetch -g carrel-fetch /var/lib/carrel-fetch")
        infra.append(103)
    print(json.dumps({"node": host, "infra_cts": infra}))


if __name__ == "__main__":
    main()
