#!/usr/bin/env python3
"""Verify B09 bootstrap from an admin workstation with its SSH aliases.

Reads both PVE hosts, probes management isolation from staging, and briefly
starts an empty KVM process inside staging (timeout removes that process).
This does not test tenant isolation or the unimplemented MCP control plane.
"""

import json
import shlex
import subprocess


def remote(alias, source):
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", alias,
         "python3 -c " + shlex.quote(source)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90,
    )
    if result.returncode:
        raise RuntimeError(f"{alias}: {result.stderr or result.stdout}")
    return json.loads(result.stdout)


INSPECT = r'''
import json, pathlib, socket, subprocess, urllib.request
def run(*args):
    return subprocess.check_output(args, text=True, timeout=20).strip()
name = run("hostname", "-s")
expected = EXPECTED
assert name == expected, (name, expected)
address = ADDRESS
# curl validates the local PVE CA and IP SAN. Python 3.13's additional X509
# strict mode rejects PVE's generated CA for its absent keyUsage extension.
assert run("curl", "--fail", "--silent", "--show-error", "--cacert", "/etc/pve/pve-root-ca.pem", "--max-time", "10", "--output", "/dev/null", "--write-out", "%{http_code}", "https://" + address + ":8006/") == "200"
storage = json.loads(run("pvesh", "get", "/nodes/"+name+"/storage/local-lvm/status", "--output-format", "json"))
assert storage["type"] == "lvmthin" and storage["active"]
assert all(s == "active" for s in run("systemctl", "is-active", "pve-cluster", "pvedaemon", "pveproxy", "pvestatd").splitlines())
result = {"node": name, "pve_version": run("pveversion"), "kernel": run("uname", "-r"),
          "management_https_verified": True, "local_lvm_active": True, "pve_services_active": True}
EXTRA
print(json.dumps(result))
'''

HOST_EXTRA = r'''
assert run("systemctl", "is-active", "carrel-staging-firewall.service") == "active"
run("nft", "list", "table", "inet", "carrel_staging")
assert "status: running" in run("qm", "status", "190")
result["staging_vm_running"] = True
result["staging_firewall_active"] = True
'''

GUEST_EXTRA = r'''
assert result["kernel"].endswith("-pve")
assert pathlib.Path("/dev/kvm").exists()
assert any(link["ifname"] == "vmbr0" for link in json.loads(run("ip", "-j", "link", "show")))
blocked = []
for destination, port in [("172.31.255.1",22),("172.31.255.1",8006),("192.168.13.159",22),("192.168.13.159",8006),("192.168.13.253",22)]:
    try:
        with socket.create_connection((destination, port), timeout=2):
            pass
    except (TimeoutError, OSError):
        blocked.append({"address": destination, "port": port})
    else:
        raise RuntimeError("staging can reach a protected management endpoint: " + destination)
with urllib.request.urlopen("https://deb.debian.org", timeout=15) as response:
    assert response.status == 200
smoke = subprocess.run(["timeout", "--kill-after=3s", "2s", "kvm", "-machine", "q35", "-accel", "kvm", "-cpu", "host", "-m", "128", "-smp", "1", "-nodefaults", "-nographic", "-monitor", "none", "-serial", "none"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
assert smoke.returncode == 124, smoke.stderr
result.update({"management_endpoints_blocked": blocked, "outbound_https_verified": True, "nested_kvm_start_verified": True})
'''


def inspect(alias, address, extra):
    source = INSPECT.replace("EXPECTED", repr(alias)).replace("ADDRESS", repr(address)).replace("EXTRA", extra)
    return remote(alias, source)


if __name__ == "__main__":
    report = {
        "scope": "admin staging bootstrap; not M0 CI, tenant networking, or MCP acceptance",
        "host": inspect("carrel01", "192.168.13.159", HOST_EXTRA),
        "staging": inspect("carrel-stg01", "172.31.255.2", GUEST_EXTRA),
    }
    print(json.dumps(report, indent=2))
