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
        self.fail_push = None
        self.fail_proxy_reload = False
        monkeypatch.setattr(module, "run", self.run)
        monkeypatch.setattr(module, "push", self.push)
        monkeypatch.setattr(module.subprocess, "run", self.read)

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
        if args[2] == "207" and args[-2:] == ("reload", "caddy") and self.fail_proxy_reload:
            raise subprocess.CalledProcessError(1, args)
        return ""

    def read(self, args, **_):
        content = self.files.get(args[-1])
        return subprocess.CompletedProcess(args, 1 if content is None else 0, content or "", "")

    def push(self, vmid, local, remote):
        if remote == self.fail_push:
            raise subprocess.CalledProcessError(1, ["pct", "push"])
        self.files[remote] = Path(local).read_text()

    def reloads(self, ct="200"):
        return [c for c in self.calls if c[:3] == ("pct", "exec", ct) and c[-2:] == ("reload", "caddy")]


STATE = {"domains": [], "certificates": []}
CERTS = "/etc/caddy/carrel-certs/alice"
TENANT = {
    "domains": [{"state": "ready", "slug": "alice", "sub": "app", "name": "app.alice.winlab.tw"}],
    "certificates": [{"slug": "alice", "fullchain": "CHAIN", "privkey": "KEY"}],
}


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


def test_retry_repushes_a_half_pushed_certificate_and_reloads(tmp_path, monkeypatch):
    module = load()
    edge = Edge(module, monkeypatch)
    edge.fail_push = CERTS + "/privkey.pem"
    with pytest.raises(subprocess.CalledProcessError):
        module.proxy(TENANT, tmp_path)
    assert edge.files[CERTS + "/fullchain.pem"] == "CHAIN"

    edge.fail_push = None
    module.proxy(TENANT, tmp_path)
    assert edge.files[CERTS + "/privkey.pem"] == "KEY"
    assert len(edge.reloads()) == 1


def test_unchanged_certificates_do_not_reload(tmp_path, monkeypatch):
    module = load()
    edge = Edge(module, monkeypatch)
    module.proxy(TENANT, tmp_path)
    module.proxy(TENANT, tmp_path)
    assert len(edge.reloads()) == 1
    assert len(edge.reloads("207")) == 1


def test_proxy_retry_reloads_after_a_failed_reload(tmp_path, monkeypatch):
    module = load()
    edge = Edge(module, monkeypatch)
    edge.fail_proxy_reload = True
    with pytest.raises(subprocess.CalledProcessError):
        module.proxy(STATE, tmp_path)

    edge.fail_proxy_reload = False
    module.proxy(STATE, tmp_path)
    assert len(edge.reloads("207")) == 2
    assert not (tmp_path / "proxy.unloaded").exists()


def test_carrel_host_sends_only_control_paths_to_carrel(tmp_path, monkeypatch):
    module = load()
    edge = Edge(module, monkeypatch)
    module.proxy(TENANT, tmp_path)
    conf = edge.files["/etc/caddy/Caddyfile"]
    start = conf.index(" handle @carrel {")
    end = conf.index("\n }\n", start)
    block = conf[start:end]
    control = "  @control path /mcp /mcp/* /oauth/* /.well-known/* /healthz /status /internal/* /apps/*"
    assert control in block
    # Control routes are matched first; the page takes whatever is left of
    # carrel.winlab.tw, and tenant domains stay outside the carrel host.
    assert (
        block.index("10.200.0.3:8080")
        < block.index("  handle {")
        < block.index("reverse_proxy " + module.SITE)
    )
    assert "@tenants" not in block
    assert conf.index("handle @tenants") > end
