#!/usr/bin/env python3
"""Install a dedicated WireGuard edge link without changing existing routes/rules."""

import argparse
from pathlib import Path
import subprocess


def run(*args):
    subprocess.run(args, check=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["site", "edge"])
    p.add_argument("peer_public_key")
    a = p.parse_args()
    assert len(a.peer_public_key) == 44 and "\n" not in a.peer_public_key
    edge = a.role == "edge"
    secret = Path("/etc/wireguard/carrel.key").read_text().strip()
    conf = (
        f"""[Interface]
Address = 10.254.200.{1 if edge else 2}/30
PrivateKey = {secret}
MTU = 1420
"""
        + ("ListenPort = 51890\n" if edge else "")
        + f"""
[Peer]
PublicKey = {a.peer_public_key}
AllowedIPs = {"10.254.200.2/32, 10.200.0.0/16" if edge else "10.254.200.1/32, 10.10.10.207/32"}
"""
        + ("" if edge else "Endpoint = 140.113.194.229:51890\nPersistentKeepalive = 25\n")
    )
    path = Path("/etc/wireguard/wg-carrel.conf")
    changed = not path.exists() or path.read_text() != conf
    path.write_text(conf)
    path.chmod(0o600)
    if edge:
        rules = """add table inet carrel_link
flush table inet carrel_link
table inet carrel_link {
 chain input {
  type filter hook input priority -15; policy accept;
  iifname "wg-carrel" ct state established,related accept
  iifname "wg-carrel" ip saddr 10.254.200.2 ip daddr 10.254.200.1 icmp type echo-request accept
  iifname "wg-carrel" counter drop
 }
 chain forward {
  type filter hook forward priority -15; policy accept;
  iifname "wg-carrel" ct state established,related accept
  iifname "wg-carrel" counter drop
  oifname "wg-carrel" ip saddr 10.10.10.207 ip daddr 10.200.0.3 tcp dport 8080 accept
  oifname "wg-carrel" ip saddr 10.10.10.207 ip daddr 10.200.0.2 tcp dport { 80,443 } accept
  oifname "wg-carrel" ct status dnat ip daddr 10.200.0.0/16 accept
  oifname "wg-carrel" counter drop
 }
 chain mss {
  type filter hook forward priority mangle; policy accept;
  oifname "wg-carrel" tcp flags syn tcp option maxseg size set rt mtu
 }
}
"""
    else:
        rules = """add table inet carrel_link
flush table inet carrel_link
table inet carrel_link {
 chain input {
  type filter hook input priority -16; policy accept;
  iifname "wg-carrel" ct state established,related accept
  iifname "wg-carrel" ip saddr 10.254.200.1 ip daddr 10.254.200.2 icmp type echo-request accept
  iifname "wg-carrel" counter drop
 }
 chain forward {
  type filter hook forward priority -16; policy accept;
  iifname "wg-carrel" ip saddr != { 10.254.200.1, 10.10.10.207 } counter drop
  iifname "wg-carrel" ip daddr != 10.200.0.0/16 counter drop
  oifname "wg-carrel" ct state established,related accept
  oifname "wg-carrel" counter drop
 }
 chain mss {
  type filter hook forward priority mangle; policy accept;
  oifname "wg-carrel" tcp flags syn tcp option maxseg size set rt mtu
 }
}
"""
    Path("/etc/carrel").mkdir(exist_ok=True)
    Path("/etc/carrel/link.nft").write_text(rules)
    run("nft", "-c", "-f", "/etc/carrel/link.nft")
    run("nft", "-f", "/etc/carrel/link.nft")
    Path("/etc/systemd/system/carrel-link-firewall.service").write_text("""[Unit]
Description=Carrel edge tunnel boundaries
After=network.target
Before=wg-quick@wg-carrel.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/carrel/link.nft
ExecReload=/usr/sbin/nft -f /etc/carrel/link.nft
[Install]
WantedBy=multi-user.target
""")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", "carrel-link-firewall")
    run("systemctl", "enable", "--now", "wg-quick@wg-carrel")
    if changed:
        run("systemctl", "restart", "wg-quick@wg-carrel")
    run("wg", "show", "wg-carrel", "latest-handshakes")


if __name__ == "__main__":
    main()
