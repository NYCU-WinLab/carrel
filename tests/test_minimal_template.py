"""Current node/template behavior; the Python control plane is a frozen reference."""

import hashlib
import importlib.util
import json
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
    assert {"cloud-init", "python3", "qemu-guest-agent", "unattended-upgrades", "rsync"} <= set(
        manifest["packages"]
    )
    assert not {"docker.io", "build-essential", "python3-pip"} & set(manifest["packages"])
    resize = next(c for c in calls if c[0] == "guestfish")
    assert resize[resize.index("part-resize") + 2] == "3"
    assert resize[-1] == "/dev/sda3"
