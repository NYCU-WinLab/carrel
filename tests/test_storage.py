"""Guest storage follows node.json (PLAN 8.2): LVM-thin on the R640 node, ZFS on B09 nodes."""

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
    assert module.storage_definition("local-lvm", STORAGE_CFG)["vgname"] == "pve"
    for storage in ("local", "missing"):
        with pytest.raises(ValueError, match="LVM-thin or ZFS"):
            module.storage_definition(storage, STORAGE_CFG)


def test_storage_id_defaults_to_local_lvm_and_validates(monkeypatch, tmp_path):
    module = load_script("node-agent.py")
    monkeypatch.setattr(module, "CONFIG", tmp_path / "node.json")
    assert module.storage_id() == "local-lvm"
    (tmp_path / "node.json").write_text(json.dumps({"storage": "local-zfs"}))
    assert module.storage_id() == "local-zfs"
    (tmp_path / "node.json").write_text(json.dumps({"storage": "../etc"}))
    with pytest.raises(ValueError, match="storage id"):
        module.storage_id()


def test_zfs_pool_usage_comes_from_storage_status_without_metadata():
    module = load_script("node-agent.py")
    usage = module.pool_usage({"type": "zfspool", "pool": "rpool/data"}, {"total": 400, "used": 100})
    assert usage == {"data_fraction": 0.25, "metadata_fraction": 0}


def test_lvm_pool_usage_reads_the_configured_thin_pool(monkeypatch):
    module = load_script("node-agent.py")
    calls = []
    report = {"report": [{"lv": [{"lv_name": "data", "data_percent": "50.0", "metadata_percent": "2.0"}]}]}
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args) or json.dumps(report))
    usage = module.pool_usage({"type": "lvmthin", "vgname": "vg-b", "thinpool": "tp"}, {})
    assert usage == {"data_fraction": 0.5, "metadata_fraction": 0.02}
    assert calls[0][-1] == "vg-b/tp"


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


def test_thin_usage_escapes_device_mapper_names(monkeypatch):
    module = load_script("thin-usage.py")
    calls = []

    def run(*args):
        calls.append(args)
        return json.dumps({"report": [{"lv": []}]}) if args[0] == "lvs" else ""

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module, "account", lambda xml, volumes, machines: [])
    assert module.collect([], "vg-b", "thin-pool") == []
    assert ("dmsetup", "message", "/dev/mapper/vg--b-thin--pool-tpool", "0", "reserve_metadata_snap") in calls
    assert calls[-1][2] == "/dev/mapper/vg--b-thin--pool-tpool"
