"""Guest storage follows node.json (PLAN 8.2): a ZFS pool."""

import importlib.util
import json
from pathlib import Path

import pytest

STORAGE_CFG = """dir: local
\tpath /var/lib/vz
\tcontent iso,vztmpl,backup

zfspool: local-zfs
\tpool rpool/data
\tsparse
\tcontent images,rootdir

lvmthin: local-lvm
\tthinpool data
\tvgname pve
\tcontent rootdir,images
"""


def load_script(name):
    path = Path(__file__).parents[1] / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_storage_definition_reads_each_pool_and_refuses_directories():
    module = load_script("node-agent.py")
    assert module.storage_definition("local-zfs", STORAGE_CFG) == {
        "type": "zfspool",
        "pool": "rpool/data",
        "sparse": "",
        "content": "images,rootdir",
    }
    for storage in ("local", "local-lvm", "missing"):
        with pytest.raises(ValueError, match="ZFS pool"):
            module.storage_definition(storage, STORAGE_CFG)


def test_storage_id_is_required_and_validated(monkeypatch, tmp_path):
    module = load_script("node-agent.py")
    monkeypatch.setattr(module, "CONFIG", tmp_path / "node.json")
    (tmp_path / "node.json").write_text("{}")
    with pytest.raises(ValueError, match="storage id"):
        module.storage_id()
    (tmp_path / "node.json").write_text(json.dumps({"storage": "local-zfs"}))
    assert module.storage_id() == "local-zfs"
    (tmp_path / "node.json").write_text(json.dumps({"storage": "../etc"}))
    with pytest.raises(ValueError, match="storage id"):
        module.storage_id()


def test_zfs_usage_counts_only_owned_volumes_per_tenant(monkeypatch):
    module = load_script("node-agent.py")
    rows = (
        "rpool/data\t1000\t0\n"
        "rpool/data/base-9014-disk-0\t900\t0\n"
        "rpool/data/vm-10100-disk-0\t300\t50\n"
        "rpool/data/vm-10100-cloudinit\t4\t0\n"
        "rpool/data/subvol-10101-disk-0\t200\t0\n"
        "rpool/data/vm-10200-disk-0\t700\t70\n"
        "rpool/data/vm-99999-disk-0\t5000\t5000"
    )
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args) or rows)
    machines = [
        {"vmid": 10100, "tenant_n": 1},
        {"vmid": 10101, "tenant_n": 1},
        {"vmid": 10200, "tenant_n": 2},
        {"vmid": 10300, "tenant_n": 3},
    ]
    result = {r["tenant_n"]: r for r in module.zfs_usage(machines, "rpool/data")}
    assert calls[0][-1] == "rpool/data"
    assert (result[1]["unique_total_bytes"], result[1]["retained_snapshot_bytes"]) == (554, 50)
    assert (result[2]["unique_total_bytes"], result[2]["retained_snapshot_bytes"]) == (770, 70)
    assert (result[3]["unique_total_bytes"], result[3]["retained_snapshot_bytes"]) == (0, 0)


def test_ct_template_pins_match_across_scripts():
    agent = load_script("node-agent.py").CT_TEMPLATES
    assert load_script("build-templates.py").CT_TEMPLATES == agent
    assert load_script("bootstrap-platform.py").DEBIAN_CT == agent["debian-13"]


def test_ct_templates_come_from_the_site_storage_and_must_match_the_pin(monkeypatch, tmp_path):
    module = load_script("node-agent.py")
    cfg = tmp_path / "storage.cfg"
    cfg.write_text(STORAGE_CFG + f"\nnfs: shared\n\tpath {tmp_path}/nfs\n\tcontent vztmpl,iso\n")
    monkeypatch.setattr(module, "STORAGE_CONFIG", cfg)
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    name, digest = module.CT_TEMPLATES["debian-13"]
    # Without a site file, or without the key: local.
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: digest + "  " + str(args[1]))
    assert module.ct_template("debian-13") == f"local:vztmpl/{name}"
    (tmp_path / "site.json").write_text(json.dumps({"content_storage": {"vztmpl": "shared"}}))
    seen = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: seen.append(args) or digest + "  x")
    assert module.ct_template("debian-13") == f"shared:vztmpl/{name}"
    assert seen == [("sha512sum", tmp_path / "nfs" / "template" / "cache" / name)]
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: "0" * 128 + "  x")
    with pytest.raises(ValueError, match="checksum"):
        module.ct_template("debian-13")

    def unreachable(*args, **kwargs):
        raise module.subprocess.TimeoutExpired(args, 60)

    monkeypatch.setattr(module, "run", unreachable)
    with pytest.raises(module.StorageUnavailable):
        module.ct_template("debian-13")
    (tmp_path / "site.json").write_text(json.dumps({"content_storage": {"vztmpl": "local-zfs"}}))
    with pytest.raises(ValueError, match="directory storage"):
        module.ct_template("debian-13")
