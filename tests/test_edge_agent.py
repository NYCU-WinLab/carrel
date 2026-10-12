import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "edge-agent.py"


def load():
    spec = importlib.util.spec_from_file_location("edge_agent", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Edge:
    """Fakes CT 200 (gateway) and CT 207 (proxy) for edge-agent's proxy()."""

    def __init__(self, module, monkeypatch):
        self.files = {}
        self.calls = []
        self.fail_validate = False
        monkeypatch.setattr(module, "run", self.run)
        monkeypatch.setattr(module, "push", self.push)

    def run(self, *args):
        self.calls.append(args)
        if args[:4] == ("pct", "exec", "200", "--") and args[4] == "cat":
            return self.files.get(args[5], "")
        if args[:4] == ("pct", "exec", "207", "--") and args[4] == "cat":
            return self.files.get(args[5], "")
        if args[:2] == ("pct", "push"):
            self.files[args[4]] = Path(args[3]).read_text()
            return ""
        if "validate" in args and args[2] == "200" and self.fail_validate:
            raise subprocess.CalledProcessError(1, args)
        return ""

    def push(self, vmid, local, remote):
        self.files[remote] = Path(local).read_text()

    def reloads(self):
        return [c for c in self.calls if c[:3] == ("pct", "exec", "200") and c[-2:] == ("reload", "caddy")]


STATE = {"domains": [], "certificates": []}


def test_gateway_validate_loads_the_caddy_environment(tmp_path, monkeypatch):
    module = load()
    edge = Edge(module, monkeypatch)
    module.proxy(STATE, tmp_path)
    validate = next(c for c in edge.calls if "validate" in c and c[2] == "200")
    assert "EnvironmentFile=/home/user/gateway/.env" in validate
    assert edge.reloads()
    assert not (tmp_path / "frontend.unloaded").exists()


def test_retry_reloads_after_a_failed_validate(tmp_path, monkeypatch):
    module = load()
    edge = Edge(module, monkeypatch)
    edge.fail_validate = True
    with pytest.raises(subprocess.CalledProcessError):
        module.proxy(STATE, tmp_path)
    assert not edge.reloads()

    # The frontend file is already written, so only the marker forces the reload.
    edge.fail_validate = False
    module.proxy(STATE, tmp_path)
    assert len(edge.reloads()) == 1
    assert not (tmp_path / "frontend.unloaded").exists()


def test_unchanged_frontend_does_not_reload(tmp_path, monkeypatch):
    module = load()
    edge = Edge(module, monkeypatch)
    module.proxy(STATE, tmp_path)
    module.proxy(STATE, tmp_path)
    assert len(edge.reloads()) == 1
