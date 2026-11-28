"""scripts/install.sh in dry-run mode, with Proxmox commands stubbed (#569)."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = {
    "site": "stg",
    "storage": "tank",
    "nodes": [{"name": "n1", "address": "10.9.0.1"}, {"name": "n2", "address": "10.9.0.2"}],
    "exit_nodes": ["n1"],
}


def install(tmp_path, node, *args, storage_type="zfspool", dry_run=True):
    bin = tmp_path / "bin"
    bin.mkdir(exist_ok=True)
    stubs = {
        "hostname": f"echo {node}",
        "pveversion": "true",
        "qm": "true",
        "pct": "true",
        "pvesh": f"echo '{json.dumps({'type': storage_type})}'",
        "pvecm": "true",
    }
    if not dry_run:
        stubs["id"] = "echo 0"
    for name, body in stubs.items():
        (bin / name).write_text(f"#!/bin/sh\n{body}\n")
        (bin / name).chmod(0o755)
    site = tmp_path / "cluster.json"
    site.write_text(json.dumps(SITE))
    key = tmp_path / "admin.pub"
    key.write_text("ssh-ed25519 AAAA test\n")
    argv = [str(a).replace("KEY", str(key)) for a in args]
    env = dict(os.environ, PATH=f"{bin}:{os.environ['PATH']}")
    if dry_run:
        env["CARREL_DRY_RUN"] = "1"
    return subprocess.run(
        ["bash", str(ROOT / "scripts/install.sh"), "--site", str(site), *argv],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_first_exit_node_runs_network_then_bootstrap(tmp_path):
    r = install(tmp_path, "n1", "--admin-key", "KEY")
    assert r.returncode == 0, r.stderr
    lines = [l for l in r.stdout.splitlines() if l.startswith("+ ")]
    network = next(i for i, l in enumerate(lines) if "install-network.py" in l)
    bootstrap = next(i for i, l in enumerate(lines) if "bootstrap-platform.py --admin-key" in l)
    assert network < bootstrap
    assert not any("pvecm" in l for l in lines)


def test_first_exit_node_needs_an_admin_key(tmp_path):
    r = install(tmp_path, "n1")
    assert r.returncode != 0 and "--admin-key" in r.stderr


def test_another_node_joins_and_skips_bootstrap(tmp_path):
    r = install(tmp_path, "n2", "--join", "n1")
    assert r.returncode == 0, r.stderr
    assert "+ pvecm add n1 --use_ssh 1" in r.stdout
    assert "bootstrap-platform.py" not in "".join(l for l in r.stdout.splitlines() if l.startswith("+ "))
    assert "run scripts/bootstrap-platform.py --firewall" in r.stdout
    assert "on every other node" in r.stdout and "install.sh --site" in r.stdout


def test_a_join_that_leaves_no_cluster_stops_the_install(tmp_path):
    # pvecm add exits 0 when ssh-copy-id fails; the stub does the same.
    r = install(tmp_path, "n2", "--join", "n1", dry_run=False)
    assert r.returncode != 0 and "did not join the cluster" in r.stderr
    assert "install-network.py" not in r.stdout + r.stderr


def test_install_sh_checks_root_keys_are_the_cluster_file():
    # Run for real it would need /root; the check itself is pinned here.
    s = (ROOT / "scripts/install.sh").read_text()
    assert "readlink -f /root/.ssh/authorized_keys) != /etc/pve/priv/authorized_keys" in s


def test_another_node_outside_a_cluster_needs_join(tmp_path):
    r = install(tmp_path, "n2")
    assert r.returncode != 0 and "--join" in r.stderr


def test_guest_storage_must_be_zfs(tmp_path):
    r = install(tmp_path, "n1", "--admin-key", "KEY", storage_type="lvmthin")
    assert r.returncode != 0 and "ZFS pool" in r.stderr


def test_a_host_outside_the_site_file_is_refused(tmp_path):
    r = install(tmp_path, "n9", "--admin-key", "KEY")
    assert r.returncode != 0 and "not in the site file" in r.stderr


def test_templates_are_built_with_a_prepared_dir(tmp_path):
    r = install(
        tmp_path,
        "n2",
        "--join",
        "n1",
        "--prepared-dir",
        "/srv/img",
        "--image",
        "debian-13-minimal",
        "--vmid-base",
        "9030",
    )
    assert (
        "+ python3 " in r.stdout
        and "build-templates.py --prepared-dir /srv/img --image debian-13-minimal --vmid-base 9030"
        in r.stdout
    )
