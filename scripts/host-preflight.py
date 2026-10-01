#!/usr/bin/env python3
"""Read-only PVE host inventory and production prerequisite checks.

Run on the target node with a site/node JSON file. This does not install carrel,
format disks, configure networking, join a cluster, or prove tenant isolation.
Exit 0 means these prerequisites passed, 2 means a prerequisite is unresolved,
and 1 means configuration or collection failed.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def command(*args):
    return subprocess.run(
        args, check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30,
    ).stdout.strip()


def validate(config):
    for field in ("site", "node"):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", config[field]):
            raise ValueError(f"invalid {field}")
    management = config["management"]
    address = ipaddress.IPv4Interface(management["address"])
    if address.ip not in ipaddress.IPv4Network("192.168.0.0/16") and not address.ip.is_private:
        raise ValueError("management must use a private IPv4 address")
    gateway = ipaddress.IPv4Address(management["gateway"])
    if gateway not in address.network or gateway == address.ip:
        raise ValueError("management gateway must be another address on its subnet")
    ipaddress.IPv4Address(management["dns"])
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", management["interface"]):
        raise ValueError("invalid management interface")
    storage = config["storage"]
    if storage["decision"] not in ("pending", "approved"):
        raise ValueError("storage decision must be pending or approved")
    if config["ingress"]["public_address"] is not None:
        if not ipaddress.IPv4Address(config["ingress"]["public_address"]).is_global:
            raise ValueError("public ingress address must be globally routable")
    return config


def collect():
    hostname = command("hostname", "-s")
    memory_kib = int(re.search(r"^MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text(), re.M)[1])
    nested = {}
    for module in ("kvm_intel", "kvm_amd"):
        path = Path(f"/sys/module/{module}/parameters/nested")
        if path.exists():
            nested[module] = path.read_text().strip()
    return {
        "hostname": hostname,
        "fqdn": command("hostname", "-f"),
        "pve_version": command("pveversion"),
        "cpu_threads": os.cpu_count(),
        "memory_kib": memory_kib,
        "nested_virtualization": nested,
        "addresses": json.loads(command("ip", "-j", "-4", "address", "show")),
        "routes": json.loads(command("ip", "-j", "-4", "route", "show")),
        "block_devices": json.loads(command("lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,FSTYPE,MODEL"))["blockdevices"],
        "storage": json.loads(command("pvesh", "get", f"/nodes/{hostname}/storage", "--output-format", "json")),
        "cluster_configured": Path("/etc/pve/corosync.conf").exists(),
        "cluster_status": json.loads(command("pvesh", "get", "/cluster/status", "--output-format", "json")),
        "guests": json.loads(command("pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json")),
    }


def assess(config, inventory):
    checks = []

    def check(name, passed, detail):
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    check("pve_major", inventory["pve_version"].startswith("pve-manager/9."), "PVE 9 required; all future cluster members must use the same version")
    check("node_name", inventory["hostname"] == config["node"], f"expected {config['node']}, observed {inventory['hostname']}")
    management = config["management"]
    expected = ipaddress.IPv4Interface(management["address"])
    actual = [a for link in inventory["addresses"] if link["ifname"] == management["interface"] for a in link["addr_info"]]
    check("management_address", any(a.get("local") == str(expected.ip) and a.get("prefixlen") == expected.network.prefixlen for a in actual), management["address"])
    check("management_gateway", any(r.get("dst") == "default" and r.get("gateway") == management["gateway"] and r.get("dev") == management["interface"] for r in inventory["routes"]), management["gateway"])
    storage = config["storage"]
    check("storage_decision", storage["decision"] == "approved", "storage backend must be explicitly chosen for this node")
    check("production_storage", any(s["storage"] == storage["production_id"] and s["type"] == storage["production_type"] and s.get("active") for s in inventory["storage"]), f"expected active {storage['production_id']} ({storage['production_type']}); no storage is changed by this script")
    ingress = config["ingress"]
    check("access_mode", ingress.get("mode") == "private" or ingress["public_address"] is not None, "private mode permits staging only; public MCP, tenant SSH and domains require a separately verified ingress path")
    if config["cluster"]["peers"]:
        cluster = config["cluster"]
        check("cluster_links", cluster["corosync_interface"] and cluster["underlay_interface"] and cluster["corosync_interface"] != cluster["underlay_interface"], "corosync and tenant VXLAN/BGP must use separate links; validate latency and quorum before joining")
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = validate(json.loads(args.config.read_text()))
        if os.geteuid() != 0:
            raise ValueError("run as root on the PVE node to read PVE inventory")
        inventory = collect()
        checks = assess(config, inventory)
        result = {
            "scope": "host prerequisites only; not M0/M1 acceptance or service readiness",
            "site": config["site"], "node": config["node"],
            "prerequisites_met": all(c["passed"] for c in checks),
            "checks": checks, "inventory": inventory,
        }
        print(json.dumps(result, indent=2))
        return 0 if result["prerequisites_met"] else 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"preflight failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
