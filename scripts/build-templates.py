#!/usr/bin/env python3
"""Build key-free templates from vendor images. Never changes an existing template."""

import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request


def run(*args):
    return subprocess.run([str(a) for a in args], check=True, text=True, capture_output=True).stdout.strip()


def build(vmid, name, path):
    conf = Path(f"/etc/pve/qemu-server/{vmid}.conf")
    if conf.exists():
        text = conf.read_text()
        if f"name: carrel-template-{name}\n" not in text or "template: 1" not in text:
            raise RuntimeError("Refusing occupied template VMID")
        return
    info = json.loads(run("qemu-img", "info", "--output=json", path))
    if info.get("backing-filename") or info.get("data-file"):
        raise RuntimeError("External image data refused")
    run(
        "qm",
        "create",
        vmid,
        "--name",
        "carrel-template-" + name,
        "--memory",
        "2048",
        "--cores",
        "2",
        "--cpu",
        "x86-64-v2-AES",
        "--scsihw",
        "virtio-scsi-single",
        "--serial0",
        "socket",
        "--vga",
        "serial0",
        "--agent",
        "enabled=1",
        "--tags",
        "carrel-template",
    )
    run("qm", "set", vmid, "--scsi0", f"local-lvm:0,import-from={path},discard=on,ssd=1,iothread=1")
    run("qm", "resize", vmid, "scsi0", "10G")
    run("qm", "set", vmid, "--ide2", "local-lvm:cloudinit", "--boot", "order=scsi0")
    run("qm", "template", vmid)


def main():
    cache = Path("/var/lib/carrel/bootstrap")
    cache.mkdir(parents=True, exist_ok=True)
    debian = cache / "debian-13-genericcloud-amd64-20260914-2601.qcow2"
    if not debian.exists():
        urllib.request.urlretrieve(
            "https://cloud.debian.org/images/cloud/trixie/20260914-2601/" + debian.name, debian
        )
    with debian.open("rb") as f:
        assert (
            hashlib.file_digest(f, "sha512").hexdigest()
            == "95e110dfcdbd0ed8a82a75ed9579802f9950cabf51a810dcc6388e81bc778188713878b9f28d583a0ea602fbf48b35996ae9ad37f584166d8fbd6489df248f53"
        )
    build(9000, "debian-13", debian)
    base = "https://cloud-images.ubuntu.com/releases/noble/release/"
    ubuntu = cache / "ubuntu-24.04-server-cloudimg-amd64.img"
    sums = urllib.request.urlopen(base + "SHA256SUMS", timeout=20).read().decode()
    expected = next(
        line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip("*") == ubuntu.name
    )
    if not ubuntu.exists():
        urllib.request.urlretrieve(base + ubuntu.name, ubuntu)
    with ubuntu.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == expected
    build(9001, "ubuntu-24.04", ubuntu)
    for image in ["debian-13-standard_13.1-2_amd64.tar.zst", "ubuntu-24.04-standard_24.04-2_amd64.tar.zst"]:
        if not Path("/var/lib/vz/template/cache/" + image).exists():
            run("pveam", "download", "local", image)
    print(json.dumps({"vm_templates": [9000, 9001], "ubuntu_sha256": expected}))


if __name__ == "__main__":
    main()
