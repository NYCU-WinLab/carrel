#!/usr/bin/env python3
"""Prepare a key-free VM image in the development sandbox, never on the PVE host.

Requires guestfs-tools, guestfish and qemu-utils. Input must be a verified vendor image.
The output manifest is consumed by build-templates.py --prepared-dir on the node.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
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
    parser.add_argument("image", choices=["debian-13-minimal", "debian-13", "ubuntu-24.04"])
    parser.add_argument("source", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if digest(args.source) != args.sha256:
        parser.error("vendor image digest mismatch")
    info = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", args.source]))
    if info.get("backing-filename") or info.get("data-file") or info["format"] != "qcow2":
        parser.error("expected a standalone qcow2 vendor image")
    if info["virtual-size"] > 10 * 1024**3:
        parser.error("vendor image exceeds the 10 GiB template disk; shrinking is unsupported")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / (args.image + ".qcow2")
    if output.exists():
        parser.error("output already exists; use a new build directory")
    # Preserve partition numbers, GUIDs and boot-loader offsets. virt-resize can
    # renumber Ubuntu's separate /boot partition and leave BIOS GRUB in rescue.
    run("qemu-img", "convert", "-O", "qcow2", args.source, output)
    run("qemu-img", "resize", output, "10G")
    roots = subprocess.check_output(
        ["guestfish", "--ro", "-a", str(output), "run", ":", "inspect-os"], text=True
    ).split()
    if len(roots) != 1 or not re.fullmatch(r"/dev/sda[1-9][0-9]*", roots[0]):
        raise RuntimeError("expected one partitioned root filesystem on /dev/sda")
    root = roots[0]
    filesystem = subprocess.check_output(
        ["guestfish", "--ro", "-a", str(output), "run", ":", "vfs-type", root], text=True
    ).strip()
    if filesystem != "ext4":
        raise RuntimeError("expected an ext4 root filesystem")
    # Debian's GPT keeps a 1 MiB tail reservation. Leave it intact instead of
    # assuming the last usable sector is always only 34 sectors from disk end.
    run("guestfish", "-a", output, "run", ":", "part-expand-gpt", "/dev/sda", ":",
        "part-resize", "/dev/sda", root.removeprefix("/dev/sda"), str(10 * 1024**3 // 512 - 2049), ":", "resize2fs", root)
    minimal = args.image == "debian-13-minimal"
    packages = ["cloud-init", "openssh-server", "sudo", "qemu-guest-agent", "unattended-upgrades",
                "python3", "curl", "ca-certificates", "rsync", "cloud-guest-utils"]
    extra, node, node_metadata = [], None, {}
    verify = "python3 --version && command -v sshd && command -v growpart && rsync --version"
    if not minimal:
        compose = "docker-compose" if args.image == "debian-13" else "docker-compose-v2"
        packages += ["python3-pip", "python3-venv", "build-essential", "cmake", "pkg-config", "git",
                     "jq", "unzip", "xz-utils", "docker.io", compose]
        node_base = "https://nodejs.org/dist/latest-v24.x/"
        sums = urllib.request.urlopen(node_base + "SHASUMS256.txt", timeout=30).read().decode()
        node_hash, node_name = next(line.split() for line in sums.splitlines() if line.endswith("-linux-x64.tar.xz"))
        node = args.output_dir / node_name
        urllib.request.urlretrieve(node_base + node_name, node)
        if digest(node) != node_hash:
            raise RuntimeError("Node.js archive digest mismatch")
        extra = ["--copy-in", str(node) + ":/tmp", "--run-command",
                 f"tar -xJf /tmp/{node_name} -C /usr/local --strip-components=1 && rm /tmp/{node_name}",
                 "--run-command", "systemctl enable docker.service"]
        node_metadata = {"node_archive": node_name, "node_sha256": node_hash}
        verify += " && gcc --version && g++ --version && node --version && npm --version && docker --version && docker compose version && git --version"
    else:
        verify += " && ! command -v node && ! command -v docker && ! command -v gcc"
    blocked = "guest-exec,guest-exec-status,guest-file-open,guest-file-close,guest-file-read,guest-file-write,guest-file-seek,guest-file-flush,guest-set-user-password"
    run(
        "virt-customize", "-a", output,
        "--write", '/etc/apt/apt.conf.d/99carrel-build:APT::Update::Error-Mode "any";\n',
        "--run-command", "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",
        "--install", ",".join(packages),
        *extra,
        "--write", "/etc/qemu/qemu-ga.conf:[general]\nblock-rpcs=" + blocked + "\n",
        "--run-command", "systemctl enable qemu-guest-agent fstrim.timer apt-daily.timer apt-daily-upgrade.timer",
        "--run-command", "export PATH=/usr/local/bin:/usr/sbin:$PATH; " + verify + " && apt-get clean",
        "--delete", "/etc/apt/apt.conf.d/99carrel-build",
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
        "environment": "minimal" if minimal else "development", "disk_gb": 10,
        "packages": packages, **node_metadata,
        "built_at": datetime.now(timezone.utc).isoformat(),
    }
    if node:
        node.unlink()
    output.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
