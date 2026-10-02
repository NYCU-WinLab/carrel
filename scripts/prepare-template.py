#!/usr/bin/env python3
"""Prepare a key-free VM image in the development sandbox, never on the PVE host.

Requires guestfs-tools and qemu-utils. Input must be a verified vendor image.
The output manifest is consumed by build-templates.py --prepared-dir on the node.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request
from datetime import datetime, timezone


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", choices=["debian-13", "ubuntu-24.04"])
    parser.add_argument("source", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if digest(args.source) != args.sha256:
        parser.error("vendor image digest mismatch")
    info = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", args.source]))
    if info.get("backing-filename") or info.get("data-file") or info["format"] != "qcow2":
        parser.error("expected a standalone qcow2 vendor image")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / (args.image + ".qcow2")
    if output.exists():
        parser.error("output already exists; use a new build directory")
    run("qemu-img", "create", "-f", "qcow2", output, "10G")
    run("virt-resize", "--expand", "/dev/sda1", args.source, output)
    node_base = "https://nodejs.org/dist/latest-v24.x/"
    sums = urllib.request.urlopen(node_base + "SHASUMS256.txt", timeout=30).read().decode()
    node_hash, node_name = next(line.split() for line in sums.splitlines() if line.endswith("-linux-x64.tar.xz"))
    node = args.output_dir / node_name
    urllib.request.urlretrieve(node_base + node_name, node)
    if digest(node) != node_hash:
        raise RuntimeError("Node.js archive digest mismatch")
    compose = "docker-compose" if args.image == "debian-13" else "docker-compose-v2"
    packages = ["qemu-guest-agent", "unattended-upgrades", "python3", "python3-pip", "python3-venv",
                "build-essential", "cmake", "pkg-config", "git", "curl", "ca-certificates", "jq", "unzip",
                "xz-utils", "docker.io", compose]
    blocked = "guest-exec,guest-exec-status,guest-file-open,guest-file-close,guest-file-read,guest-file-write,guest-file-seek,guest-file-flush,guest-set-user-password"
    run(
        "virt-customize", "-a", output, "--update",
        "--install", ",".join(packages),
        "--copy-in", str(node) + ":/tmp",
        "--run-command", f"tar -xJf /tmp/{node_name} -C /usr/local --strip-components=1 && rm /tmp/{node_name}",
        "--write", "/etc/qemu/qemu-ga.conf:[general]\nblock-rpcs=" + blocked + "\n",
        "--run-command", "systemctl enable qemu-guest-agent fstrim.timer apt-daily.timer apt-daily-upgrade.timer docker.service",
        "--run-command", "export PATH=/usr/local/bin:$PATH; gcc --version && g++ --version && python3 --version && node --version && npm --version && docker --version && docker compose version && git --version && apt-get clean",
        "--run-command", "cloud-init clean --logs --machine-id --seed",
    )
    run("virt-sysprep", "-a", output, "--operations", "defaults", "--hostname", "localhost")
    run(
        "virt-customize", "-a", output, "--no-network",
        "--run-command", "test ! -e /root/.ssh/authorized_keys && test -z \"$(find /home -name authorized_keys -print -quit)\"",
        "--run-command", "test -z \"$(find /etc/ssh -name 'ssh_host_*' -print -quit)\"",
        "--run-command", "test ! -d /var/lib/cloud/instances && test ! -e /etc/carrel/guest.json",
        "--run-command", "truncate -s 0 /etc/machine-id; rm -f /var/lib/dbus/machine-id",
    )
    manifest = {
        "image": args.image, "file": output.name, "sha256": digest(output),
        "source_sha256": args.sha256, "prepared": True,
        "packages": packages, "node_archive": node_name, "node_sha256": node_hash,
        "built_at": datetime.now(timezone.utc).isoformat(),
    }
    node.unlink()
    output.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
