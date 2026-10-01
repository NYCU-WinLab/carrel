#!/usr/bin/env python3
"""Prepare a standalone, empty PVE node rename; reboot separately afterwards.

Reference: https://pve.proxmox.com/wiki/Renaming_a_PVE_node
The expected name and address prevent using this on the wrong host. Clustered
nodes and nodes with guests are refused. A private backup precedes every write.
"""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tarfile


def run(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--from-name", required=True)
    p.add_argument("--to-name", required=True)
    p.add_argument("--address", required=True)
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()
    for name in (args.from_name, args.to_name):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
            p.error("invalid node name")
    address = str(ipaddress.IPv4Address(args.address))
    if os.geteuid() != 0:
        p.error("run as root on the target PVE node")
    current = run("hostname", "-s")
    addresses = json.loads(run("ip", "-j", "-4", "address", "show"))
    if not any(a.get("local") == address for link in addresses for a in link["addr_info"]):
        p.error("expected management address is absent")
    if not run("pveversion").startswith("pve-manager/9."):
        p.error("this procedure has only been checked on PVE 9")
    if current == args.to_name:
        print("Node already has the requested name; no changes")
        return
    if current != args.from_name:
        p.error("current name does not match --from-name")
    if Path("/etc/pve/corosync.conf").exists():
        p.error("refusing to rename a clustered node")
    if json.loads(run("pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json")):
        p.error("refusing to rename a node with guests or templates")
    if Path(f"/etc/pve/nodes/{args.to_name}").exists():
        p.error("target node directory already exists; inspect it before renaming")
    old_nodes = list(Path("/etc/pve/nodes").iterdir())
    if len(old_nodes) != 1 or old_nodes[0].name != current:
        p.error("unexpected additional node state")
    for directory in ("qemu-server", "lxc", "openvz"):
        if list((old_nodes[0] / directory).glob("*.conf")):
            p.error("guest configuration exists despite the empty guest inventory")
    replacement = re.compile(r"(?<![\w.-])" + re.escape(args.from_name) + r"(?=\.|\s|$)")
    changes = {}
    for filename in ("/etc/hosts", "/etc/hostname", "/etc/mailname", "/etc/postfix/main.cf"):
        path = Path(filename)
        if path.exists():
            original = path.read_text()
            updated = replacement.sub(args.to_name, original)
            if original != updated:
                changes[path] = updated
    hosts = changes.get(Path("/etc/hosts"), Path("/etc/hosts").read_text())
    if not any(line.split() and line.split()[0] == address and args.to_name in line.split()[1:] for line in hosts.splitlines()):
        p.error("/etc/hosts would not map the new node name to its management address")
    print(json.dumps({"from": current, "to": args.to_name, "files": [str(p) for p in changes], "reboot_required": True}, indent=2))
    if not args.apply:
        print("Check only; use --apply to prepare the rename")
        return
    os.umask(0o077)
    backup = Path("/var/backups/carrel") / ("rename-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    backup.mkdir(parents=True, mode=0o700)
    with tarfile.open(backup / "etc.tar.gz", "w:gz") as archive:
        for path in (*changes, Path("/etc/pve"), Path("/etc/network/interfaces")):
            archive.add(path, arcname=str(path).lstrip("/"))
    with sqlite3.connect("file:/var/lib/pve-cluster/config.db?mode=ro", uri=True) as source:
        with sqlite3.connect(backup / "config.db") as destination:
            source.backup(destination)
    for path, content in changes.items():
        # Preserve ownership, permissions and symlink behavior of the existing file.
        with path.open("w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    print(f"Backup: {backup}")
    print("Rename prepared. Reboot now; verify /etc/pve/local and the new certificate afterwards.")


if __name__ == "__main__":
    main()
