"""Current node/template behavior."""

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def load_script(name):
    path = Path(__file__).parents[1] / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("swap", [None, 0, 2048])
def test_minimal_cloud_init_keeps_management_without_docker(monkeypatch, swap):
    module = load_script("node-agent.py")
    files = {}
    read_text = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *args, **kw: (
            "# guest reporter"
            if str(path) == "/usr/local/lib/carrel/guest-report.py"
            else read_text(path, *args, **kw)
        ),
    )
    monkeypatch.setattr(module, "write", lambda path, data, mode: files.update({path: data}))
    machine = {
        "name": "minimal",
        "vmid": 10100,
        "tenant_n": 1,
        "host": 10,
        "mac": "02:ca:01:00:00:01",
        "ip": "10.200.1.10",
        "ssh_keys": ["ssh-ed25519 AAAA fixture"],
        "readiness_token": "fixture-token",
        "packages": ["nginx"],
        "runcmd": [["systemctl", "enable", "--now", "nginx"]],
    }
    if swap is not None:
        machine["swap_mb"] = swap
    module.cloud_init(machine, prepared=True, environment="minimal")
    data = json.loads(files["/var/lib/vz/snippets/carrel-10100-user.json"].split("\n", 1)[1])
    assert not data["users"][0].get("groups")
    assert data["packages"] == ["nginx"] and data["package_update"] is True
    assert data["disable_root"] is True and data["ssh_pwauth"] is False
    written = {entry["path"]: entry for entry in data["write_files"]}
    assert "guest-exec" in written["/etc/qemu/qemu-ga.conf"]["content"]
    assert written["/etc/carrel/guest.json"]["permissions"] == "0600"
    assert "nginx" in written["/usr/local/lib/carrel/bootstrap.py"]["content"]
    assert any("carrel-guest-report.timer" in command for command in data["runcmd"])
    if swap == 0:
        assert "swap" not in data
    else:
        assert data["swap"]["size"] == f"{1024 if swap is None else swap}M"


@pytest.mark.parametrize("environment", [None, "development", "minimal"])
def test_minimal_requires_its_own_prepared_template(tmp_path, monkeypatch, environment):
    module = load_script("node-agent.py")
    path = tmp_path / "templates.json"
    manifest = {"vmid": 9014, "prepared": True, "environment": environment}
    path.write_text(json.dumps({"debian-13-minimal": manifest}))
    monkeypatch.setattr(module, "Path", lambda value: path)
    if environment == "minimal":
        assert module.vm_template("debian-13-minimal") == manifest
    else:
        with pytest.raises(ValueError, match="minimal template is not installed"):
            module.vm_template("debian-13-minimal")
    path.unlink()
    with pytest.raises(ValueError, match="minimal template is not installed"):
        module.vm_template("debian-13-minimal")


def test_minimal_preparation_does_not_fetch_development_tools(tmp_path, monkeypatch):
    module = load_script("prepare-template.py")
    source = tmp_path / "vendor.qcow2"
    source.write_bytes(b"vendor fixture")
    output = tmp_path / "prepared"
    calls = []

    def run(*args):
        calls.append(args)
        if args[:2] == ("qemu-img", "convert"):
            Path(args[-1]).write_bytes(b"prepared fixture")

    def capture(args, **kwargs):
        if args[0] == "qemu-img":
            return json.dumps({"format": "qcow2", "virtual-size": 3 * 1024**3}).encode()
        return "/dev/sda3\n" if args[-1] == "inspect-os" else "ext4\n"

    def unexpected_download(*args, **kwargs):
        pytest.fail("minimal preparation must not download Node")

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module.subprocess, "check_output", capture)
    probes = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda args, **kw: probes.append(kw["env"]) or subprocess.CompletedProcess(args, 0),
    )
    monkeypatch.setitem(module.ENV, "SUPERMIN_KERNEL", "/fixture/vmlinuz")
    monkeypatch.setattr(
        module.shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(0, 0, module.MIN_FREE)
    )
    monkeypatch.setattr(module.urllib.request, "urlopen", unexpected_download)
    monkeypatch.setattr(module.urllib.request, "urlretrieve", unexpected_download)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prepare-template.py",
            "debian-13-minimal",
            str(source),
            "--sha256",
            hashlib.sha256(source.read_bytes()).hexdigest(),
            "--output-dir",
            str(output),
        ],
    )
    module.main()
    manifest = json.loads((output / "debian-13-minimal.json").read_text())
    assert manifest["prepared"] is True and manifest["environment"] == "minimal"
    assert manifest["disk_gb"] == 10 and "node_archive" not in manifest
    # libguestfs scratch files stayed next to the output and were removed after.
    assert probes and probes[0]["TMPDIR"] == str(output / ".guestfs")
    assert not (output / ".guestfs").exists()
    assert {"cloud-init", "python3", "qemu-guest-agent", "unattended-upgrades", "rsync"} <= set(
        manifest["packages"]
    )
    assert not {"docker.io", "build-essential", "python3-pip"} & set(manifest["packages"])
    resize = next(c for c in calls if c[0] == "guestfish")
    assert resize[resize.index("part-resize") + 2] == "3"
    assert resize[-1] == "/dev/sda3"


def test_new_guests_use_the_site_mirror(monkeypatch, tmp_path):
    module = load_script("node-agent.py")
    site = tmp_path / "site.json"
    monkeypatch.setattr(module, "SITE", site)
    files = {}
    read_text = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **k: (
            "# reporter" if str(path).endswith("guest-report.py") else read_text(path, *a, **k)
        ),
    )
    monkeypatch.setattr(module, "write", lambda path, data, mode: files.update({path: data}))
    vm = {
        "name": "m",
        "vmid": 10100,
        "tenant_n": 1,
        "host": 10,
        "mac": "02:ca:01:00:00:01",
        "ip": "10.200.1.10",
        "ssh_keys": ["ssh-ed25519 AAAA fixture"],
        "readiness_token": "t",
    }

    def user_data(image):
        module.cloud_init(dict(vm, image=image), prepared=True, environment="minimal")
        return json.loads(
            files["/var/lib/vz/snippets/carrel-10100-user.json"].removeprefix("#cloud-config\n")
        )

    # Without apt_mirrors the image's own sources stay.
    site.write_text("{}")
    assert "apt" not in user_data("debian-13-minimal") and "apt" not in user_data("ubuntu-24.04")
    site.write_text(
        json.dumps(
            {
                "apt_mirrors": {
                    "debian": "https://debian.cs.nycu.edu.tw/debian",
                    "ubuntu": "https://ubuntu.cs.nycu.edu.tw/ubuntu",
                }
            }
        )
    )
    debian = user_data("debian-13-minimal")["apt"]
    assert debian["primary"][0]["uri"] == "https://debian.cs.nycu.edu.tw/debian"
    assert debian["security"][0]["uri"] == "https://deb.debian.org/debian-security"
    ubuntu = user_data("ubuntu-24.04")
    assert (
        ubuntu["apt"]["primary"][0]["uri"] == "https://ubuntu.cs.nycu.edu.tw/ubuntu"
        and "bootcmd" not in ubuntu
    )
    assert module.mirror_command("tenant:talos") is None
    site.write_text(json.dumps({"apt_mirrors": {"debian": "https://x; rm -rf /"}}))
    with pytest.raises(ValueError):
        module.mirror_command("debian-13")


def test_preparation_stops_without_space(tmp_path, monkeypatch):
    module = load_script("prepare-template.py")
    monkeypatch.setattr(module.shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(10, 9, 1024**3))
    with pytest.raises(SystemExit, match="1024 MiB free"):
        module.workspace(tmp_path)


def test_unreadable_kernel_names_the_fix(monkeypatch):
    module = load_script("prepare-template.py")
    monkeypatch.delitem(module.ENV, "SUPERMIN_KERNEL", raising=False)
    monkeypatch.setattr(module.glob, "glob", lambda pattern: ["/boot/vmlinuz-fixture"])
    monkeypatch.setattr(module.os, "access", lambda path, mode: False)
    with pytest.raises(SystemExit, match="SUPERMIN_KERNEL"):
        module.check_kernel()


def test_network_falls_back_to_slirp(tmp_path, monkeypatch):
    module = load_script("prepare-template.py")
    paths = []

    def probe(args, **kw):
        paths.append(kw["env"]["PATH"])
        return subprocess.CompletedProcess(args, 0 if len(paths) == 2 else 1)

    monkeypatch.setattr(module.subprocess, "run", probe)
    monkeypatch.setattr(module, "ENV", {"PATH": "/usr/bin"})
    module.check_network(tmp_path / "image.qcow2", tmp_path)
    shim = tmp_path / "bin" / "passt"
    assert paths == ["/usr/bin", str(tmp_path / "bin") + ":/usr/bin"]
    assert shim.read_text() == "#!/bin/sh\nexit 127\n" and shim.stat().st_mode & 0o111
