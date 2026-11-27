"""The snapshot plugin's token: 3 privileges on /vms, and files the plugin can read (#663)."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location(
        "configure_snapshot_plugin", ROOT / "scripts" / "configure-snapshot-plugin.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def node(monkeypatch, tmp_path):
    m = load()
    pve = tmp_path / "pve"
    (pve / "priv").mkdir(parents=True)
    (pve / "nodes" / "pve").mkdir(parents=True)
    (pve / "local").symlink_to("nodes/pve")
    (pve / "pve-root-ca.pem").write_text("CA\n")
    monkeypatch.setattr(m, "SECRET", pve / "priv" / "carrel-snapshot.json")
    monkeypatch.setattr(m, "LOCAL", pve / "local")
    monkeypatch.setattr(m, "CLUSTER_CA", pve / "pve-root-ca.pem")
    monkeypatch.setattr(m, "PLUGIN_ENV", tmp_path / "plugins")
    monkeypatch.setattr(m, "ENV", tmp_path / "plugins" / "snapshot.env")
    monkeypatch.setattr(m, "CA", tmp_path / "plugins" / "snapshot-ca.pem")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    state = {"tokens": [], "roles": {}, "acl": [], "calls": [], "secrets": 0}

    def pveum(*args, optional=False):
        state["calls"].append(args)
        if args[:3] == ("user", "token", "list"):
            return json.dumps([{"tokenid": t} for t in state["tokens"]])
        if args[:3] == ("user", "token", "add"):
            state["tokens"].append(args[4])
            state["secrets"] += 1
            return json.dumps({"value": f"secret-{state['secrets']}"})
        if args[:3] == ("user", "token", "remove"):
            state["tokens"].remove(args[4])
        if args[:2] == ("role", "list"):
            return json.dumps([{"roleid": r} for r in state["roles"]])
        if args[:2] in (("role", "add"), ("role", "modify")):
            state["roles"][args[2]] = args[4]
        if args[:2] == ("role", "delete"):
            state["roles"].pop(args[2], None)
        if args[:2] == ("acl", "modify"):
            state["acl"].append({"path": args[2], "ugid": args[4], "roleid": args[6]})
        if args[:2] == ("acl", "delete"):
            state["acl"] = [a for a in state["acl"] if a["ugid"] != args[4]]
        if args[:2] == ("acl", "list"):
            return json.dumps(state["acl"])
        return ""

    monkeypatch.setattr(m, "pveum", pveum)
    return m, state, tmp_path


def test_the_token_holds_only_the_snapshot_privileges(node, monkeypatch, capsys):
    m, state, tmp = node
    monkeypatch.setattr("sys.argv", ["configure-snapshot-plugin.py"])
    m.main()
    out = json.loads(capsys.readouterr().out)
    assert out["snapshot_token"] == "created" and out["node"] == "pve"
    assert "secret" not in json.dumps(out)
    assert state["roles"] == {"CarrelSnapshot": "VM.Audit VM.Snapshot VM.Snapshot.Rollback"}
    assert state["acl"] == [{"path": "/vms", "ugid": "root@pam!carrel-snapshot", "roleid": "CarrelSnapshot"}]
    assert (
        "user",
        "token",
        "add",
        "root@pam",
        "carrel-snapshot",
        "--privsep",
        "1",
        "--expire",
        "0",
        "--output-format",
        "json",
    ) in state["calls"]
    env = tmp / "plugins" / "snapshot.env"
    assert env.stat().st_mode & 0o777 == 0o600
    assert 'CARREL_PVE_NODE="pve"' in env.read_text()
    assert 'CARREL_PVE_TOKEN="PVEAPIToken=root@pam!carrel-snapshot=secret-1"' in env.read_text()
    ca = tmp / "plugins" / "snapshot-ca.pem"
    assert ca.read_text() == "CA\n" and ca.stat().st_mode & 0o777 == 0o644


def test_a_second_run_keeps_the_token_and_one_without_its_secret_replaces_it(node, monkeypatch, capsys):
    m, state, tmp = node
    monkeypatch.setattr("sys.argv", ["configure-snapshot-plugin.py"])
    m.main()
    m.main()
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["snapshot_token"] == "preserved"
    assert state["secrets"] == 1
    m.SECRET.unlink()
    m.main()
    assert json.loads(capsys.readouterr().out)["snapshot_token"] == "created"
    assert state["secrets"] == 2 and state["tokens"] == ["carrel-snapshot"]
    assert "secret-2" in (tmp / "plugins" / "snapshot.env").read_text()


def test_remove_leaves_nothing(node, monkeypatch, capsys):
    m, state, _ = node
    monkeypatch.setattr("sys.argv", ["configure-snapshot-plugin.py"])
    m.main()
    monkeypatch.setattr("sys.argv", ["configure-snapshot-plugin.py", "--remove"])
    m.main()
    assert state["tokens"] == [] and state["roles"] == {} and state["acl"] == []
    assert not m.SECRET.exists() and not m.ENV.exists() and not m.CA.exists()
