#!/usr/bin/env python3
"""Fixed, owner-visible boot reporter. No remote commands or command output leave the VM."""

import json
from pathlib import Path
import socket
import subprocess
import urllib.request


def collect(config):
    status = subprocess.run(["cloud-init", "status", "--format=json"], capture_output=True, text=True, check=False)
    try:
        data = json.loads(status.stdout[status.stdout.index("{"):])
        init = "running" if data.get("status") in ("running", "not started") else "complete"
        if status.returncode == 1 or data.get("errors") or data.get("status") in ("error", "disabled"):
            init = "failed"
    except (ValueError, KeyError):
        init = "running"
    bootstrap_path = Path("/var/lib/carrel-bootstrap.json")
    bootstrap = json.loads(bootstrap_path.read_text()) if bootstrap_path.exists() else {}
    if bootstrap.get("state") == "failed":
        init = "failed"
    checks = []
    if init == "complete":
        for check in config.get("health_checks", []):
            healthy = False
            try:
                if check["type"] == "service":
                    healthy = subprocess.run(["systemctl", "is-active", "--quiet", check["service"]],
                                             timeout=10, check=False).returncode == 0
                elif check["type"] == "tcp":
                    with socket.create_connection(("127.0.0.1", check["port"]), timeout=5):
                        healthy = True
                elif check["type"] == "http":
                    url = f"http://127.0.0.1:{check['port']}" + check.get("path", "/")
                    with urllib.request.urlopen(url, timeout=5) as response:
                        healthy = response.status == check.get("status", 200)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
            checks.append({"status": "healthy" if healthy else "failed"})
    application = "pending" if init == "running" else "not_checked"
    if checks:
        application = "healthy" if all(c["status"] == "healthy" for c in checks) else "failed"
    interfaces = []
    try:
        network = subprocess.run(["ip", "-j", "address", "show"], capture_output=True, text=True, check=False)
        for interface in json.loads(network.stdout):
            if interface.get("address", "").startswith("02:cb:"):
                interfaces += [{"mac": interface["address"], "ip": address["local"], "mtu": interface["mtu"]}
                               for address in interface.get("addr_info", []) if address["family"] == "inet"]
    except (ValueError, KeyError):
        pass
    return {"vmid": config["vmid"], "token": config["token"], "interfaces": interfaces,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "initialization_status": init, "application_status": application, "checks": checks,
            "failed_step": bootstrap.get("step") if bootstrap.get("state") == "failed" else None}


def main():
    config = json.loads(Path("/etc/carrel/guest.json").read_text())
    report = collect(config)
    request = urllib.request.Request("http://10.200.0.3:8080/internal/guest-status",
                                     data=json.dumps(report).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("Report rejected")


if __name__ == "__main__":
    main()
