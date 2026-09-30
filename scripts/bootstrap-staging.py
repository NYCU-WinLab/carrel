#!/usr/bin/env python3
"""Create the admin-only nested PVE staging VM on carrel01.

This bootstraps its Debian guest, not the tenant platform. Install PVE inside
the guest with install-staging-pve.py afterwards. Existing disks are never
formatted by this host script. Re-running it preserves the staging VM.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

VMID = "190"
NAME = "carrel-stg01"
TAG = "carrel-staging"
MARKER = "# Managed by carrel staging bootstrap.\n"
IMAGE = "debian-13-genericcloud-amd64-20260914-2601.qcow2"
URL = "https://cloud.debian.org/images/cloud/trixie/20260914-2601/" + IMAGE
SHA512 = "95e110dfcdbd0ed8a82a75ed9579802f9950cabf51a810dcc6388e81bc778188713878b9f28d583a0ea602fbf48b35996ae9ad37f584166d8fbd6489df248f53"


def run(*args, capture=False, timeout=120):
    result = subprocess.run(args, check=True, text=True, timeout=timeout,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def managed_file(filename, content, mode=0o644):
    path = Path(filename)
    if path.exists():
        old = path.read_text()
        if old == content:
            return False
        if MARKER.strip() not in old:
            raise RuntimeError(f"refusing to replace unmanaged file {path}")
        path.with_name(path.name + ".carrel-backup").write_text(old)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)
    print(f"wrote {path}", flush=True)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-key", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or run("hostname", "-s", capture=True) != "carrel01":
        parser.error("run as root on carrel01; this bootstrap is scoped to that node")
    if not run("pveversion", capture=True).startswith("pve-manager/9."):
        parser.error("PVE 9 is required")
    key = args.admin_key.read_text().strip()
    if not key.startswith("ssh-ed25519 ") or "\n" in key:
        parser.error("provide one administrator ed25519 public key")
    run("ssh-keygen", "-l", "-f", str(args.admin_key), capture=True)
    storage = json.loads(run("pvesh", "get", "/nodes/carrel01/storage/local-lvm/status", "--output-format", "json", capture=True))
    if not storage.get("active") or storage["type"] != "lvmthin":
        parser.error("active local-lvm LVM-thin storage is required")
    if storage["avail"] < 220 * 1024**3:
        parser.error("keep at least 220 GiB free before staging provisioning")
    guests = json.loads(run("pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json", capture=True))
    existing = next((g for g in guests if str(g["vmid"]) == VMID), None)
    config = {}
    if existing:
        if existing["node"] != "carrel01" or existing["type"] != "qemu":
            parser.error("VMID 190 is already used by another node or guest type")
        config = json.loads(run("pvesh", "get", f"/nodes/carrel01/qemu/{VMID}/config", "--output-format", "json", capture=True))
        if config.get("name") != NAME or TAG not in config.get("tags", "").split(";"):
            parser.error("VMID 190 is not owned by this staging bootstrap")
    routes = json.loads(run("ip", "-j", "-4", "route", "show", capture=True))
    import ipaddress
    for route in routes:
        if route["dst"] == "default":
            continue
        if ipaddress.ip_network(route["dst"]).overlaps(ipaddress.ip_network("172.31.255.0/24")) and route.get("dev") != "vmbr99":
            parser.error("staging subnet overlaps an existing route")
    if not args.apply:
        print(json.dumps({"vmid": 190, "name": NAME, "cores": 8, "memory_mb": 24576, "root_gb": 32,
                          "data_gb": 160, "storage": "local-lvm", "bridge": "vmbr99", "address": "172.31.255.2/24",
                          "existing": bool(existing), "public_ingress": False}, indent=2))
        return

    changed = []
    bridge = MARKER + """auto vmbr99
iface vmbr99 inet static
    address 172.31.255.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
"""
    if managed_file("/etc/network/interfaces.d/carrel-staging", bridge):
        changed.append("bridge configuration")
    if "vmbr99" not in run("ip", "-o", "link", "show", capture=True):
        run("ifup", "vmbr99")
        changed.append("bridge activation")
    sysctl = MARKER + "net.ipv4.ip_forward=1\n"
    if managed_file("/etc/sysctl.d/90-carrel-staging.conf", sysctl):
        changed.append("forwarding configuration")
    if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
        run("sysctl", "-w", "net.ipv4.ip_forward=1")
        changed.append("forwarding activation")
    rules = MARKER + """add table inet carrel_staging
flush table inet carrel_staging
table inet carrel_staging {
    chain input {
        type filter hook input priority -20; policy accept;
        iifname "vmbr99" ct state established,related accept
        iifname "vmbr99" counter drop
    }
    chain forward {
        type filter hook forward priority -20; policy accept;
        iifname "vmbr99" meta nfproto ipv6 counter drop
        iifname "vmbr99" ip saddr != 172.31.255.2 counter drop
        iifname "vmbr99" ct state established,related accept
        iifname "vmbr99" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } counter drop
        iifname "vmbr99" tcp dport 25 counter drop
        oifname "vmbr99" ct state established,related accept
        oifname "vmbr99" counter drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 172.31.255.2 oifname "vmbr0" masquerade
    }
}
"""
    rules_changed = managed_file("/etc/carrel/staging.nft", rules)
    if rules_changed:
        changed.append("staging firewall")
    run("nft", "--check", "--file", "/etc/carrel/staging.nft")
    unit = MARKER + """[Unit]
Description=Carrel staging egress and management isolation
After=network.target
Before=pve-guests.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft --file /etc/carrel/staging.nft
ExecReload=/usr/sbin/nft --file /etc/carrel/staging.nft

[Install]
WantedBy=multi-user.target
"""
    if managed_file("/etc/systemd/system/carrel-staging-firewall.service", unit):
        run("systemctl", "daemon-reload")
        changed.append("firewall service")
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "carrel-staging-firewall.service"]).returncode == 0
    if not enabled:
        run("systemctl", "enable", "carrel-staging-firewall.service")
        changed.append("firewall boot activation")
    # is-active returns a nonzero status for a newly installed service.
    active = subprocess.run(["systemctl", "is-active", "--quiet", "carrel-staging-firewall.service"]).returncode == 0
    if not active:
        run("systemctl", "start", "carrel-staging-firewall.service")
        changed.append("firewall activation")
    elif rules_changed or subprocess.run(["nft", "list", "table", "inet", "carrel_staging"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        run("systemctl", "reload", "carrel-staging-firewall.service")

    if not config.get("scsi0"):
        cache = Path("/var/lib/carrel/bootstrap")
        cache.mkdir(parents=True, exist_ok=True)
        image = cache / IMAGE
        if not image.exists():
            part = image.with_suffix(".part")
            run("curl", "--fail", "--location", "--silent", "--show-error", "--connect-timeout", "15", "--max-time", "1800", URL, "--output", str(part), timeout=1810)
            image = part
        with image.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha512").hexdigest()
        if digest != SHA512:
            raise RuntimeError("Debian image checksum mismatch; no VM disk imported")
        final_image = cache / IMAGE
        if image != final_image:
            image.rename(final_image)
        info = json.loads(run("qemu-img", "info", "--output=json", str(final_image), capture=True))
        if info["format"] != "qcow2" or info.get("backing-filename") or info.get("data-file"):
            raise RuntimeError("unexpected Debian image format or external backing file")
        if not existing:
            run("qm", "create", VMID, "--name", NAME, "--cores", "8", "--memory", "24576", "--balloon", "0", "--cpu", "host", "--machine", "q35", "--ostype", "l26", "--scsihw", "virtio-scsi-single", "--serial0", "socket", "--vga", "serial0", "--agent", "enabled=1", "--onboot", "1", "--startup", "order=1", "--tags", TAG, "--description", "Admin-only nested PVE staging, managed by carrel bootstrap")
            changed.append("staging VM")
        run("qm", "set", VMID, "--scsi0", f"local-lvm:0,import-from={final_image},discard=on,ssd=1,iothread=1", timeout=600)
        changed.append("staging root disk")
    config = json.loads(run("pvesh", "get", f"/nodes/carrel01/qemu/{VMID}/config", "--output-format", "json", capture=True))
    if "size=32G" not in config["scsi0"]:
        run("qm", "resize", VMID, "scsi0", "32G")
        changed.append("root disk expansion")
    if not config.get("scsi1"):
        run("qm", "set", VMID, "--scsi1", "local-lvm:160,discard=on,ssd=1,iothread=1,serial=carrel-staging-data")
        changed.append("nested data disk")
    if not config.get("ide2"):
        run("qm", "set", VMID, "--ide2", "local-lvm:cloudinit", "--boot", "order=scsi0", "--net0", "virtio,bridge=vmbr99,mtu=1", "--ciuser", "root", "--sshkeys", str(args.admin_key), "--ipconfig0", "ip=172.31.255.2/24,gw=172.31.255.1", "--nameserver", "1.1.1.1", "--searchdomain", "staging.internal")
        changed.append("staging cloud-init")
    if "status: running" not in run("qm", "status", VMID, capture=True):
        run("qm", "start", VMID)
        changed.append("staging boot")
    print(json.dumps({"changed": changed, "vmid": 190, "address": "172.31.255.2", "next": "install PVE inside this admin-only staging guest"}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"staging bootstrap failed: {exc}", file=sys.stderr)
        sys.exit(1)
