"""Node agent behavior in a cluster (PLAN 15.15): VMIDs are unique across nodes."""

import importlib.util
from pathlib import Path

import pytest


def load_script(name):
    path = Path(__file__).parents[1] / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MACHINE = {
    "tenant_n": 1,
    "vmid": 10100,
    "host": 10,
    "name": "web",
    "kind": "vm",
    "ip": "10.200.1.10",
    "mac": "02:ca:01:00:00:01",
    "image": "debian-13-minimal",
}


@pytest.mark.parametrize("kind", ["qemu-server", "lxc"])
def test_create_refuses_a_vmid_held_by_another_node(monkeypatch, tmp_path, kind):
    module = load_script("node-agent.py")
    other = tmp_path / "nodes" / "carrel02" / kind
    other.mkdir(parents=True)
    (other / "10100.conf").write_text("name: someone-else\n")
    monkeypatch.setattr(module, "PVE_NODES", tmp_path / "nodes")
    monkeypatch.setattr(module, "STATE", tmp_path)
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(module, "api", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match="another node"):
        module.create(dict(MACHINE))
    assert not calls
    assert not (tmp_path / "create-10100.json").exists()
