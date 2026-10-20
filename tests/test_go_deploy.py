"""Validate generated upgrade/rollback programs without reaching any live host."""

import ast
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_upgrade_payloads_compile_and_keep_existing_database(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/deploy-go.py"
    spec = importlib.util.spec_from_file_location("deploy_go", path)
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    for name in ("carrel", "carrel-deployd"):
        (tmp_path / name).write_bytes(b"static binary fixture")
    payloads = []

    def run(args, **kwargs):
        if "input" in kwargs:
            payloads.append(kwargs["input"])
        return SimpleNamespace(stdout="test-revision\n")

    monkeypatch.setattr(deploy, "run", run)
    monkeypatch.setattr(sys, "argv", [str(path), "--artifacts", str(tmp_path)])
    deploy.main()
    assert len(payloads) == 1
    program = payloads[0]
    compile(program, "node-upgrade", "exec")
    nested = []
    for node in ast.walk(ast.parse(program)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ct"
            and len(node.args) == 3
            and all(isinstance(arg, ast.Constant) for arg in node.args)
            and node.args[0].value == "python3"
            and node.args[1].value == "-c"
        ):
            nested.append(node.args[2].value)
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "restore" for target in node.targets
        ):
            nested.append(node.value.value)
    assert len(nested) >= 4
    for code in nested:
        compile(code, "control-upgrade", "exec")
    rollback = nested[-1]
    assert "var/lib/carrel/carrel.db" not in rollback
    assert "carrel-pve-read" not in program and "go_pve_reader" not in program
    assert "/usr/local/lib/carrel/carrel-deployd" in program
    # node-agent loads these helpers, so they ship, back up and roll back with it.
    shipped = json.loads((tmp_path / "deploy-go.json").read_text())["sha256"]
    assert {
        "node-agent.py",
        "configure-reader.py",
        "guest-report.py",
        "gateway-sync.py",
        "configure-nodes.py",
    } <= shipped.keys()
    assert "'guest-report.py':'644','gateway-sync.py':'644'" in program
    # A site file fans the programs out to every node and checks CT 100 reaches them.
    assert "if Path('/etc/carrel/site.json').exists():" in program and "configure-nodes.py" in program
    report = json.loads((tmp_path / "deploy-go.json").read_text())
    assert (
        report["version"]
        == deploy.re.search(
            r'const Version = "([^"]+)"', (path.parents[1] / "internal/carrel/value.go").read_text()
        )[1]
    )
    assert f"health.get('version')=={report['version']!r}" in program


def test_upgrade_targets_the_given_host(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/deploy-go.py"
    spec = importlib.util.spec_from_file_location("deploy_go_host", path)
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    for name in ("carrel", "carrel-deployd"):
        (tmp_path / name).write_bytes(b"static binary fixture")
    targets = []

    def run(args, **kwargs):
        if args[0] in ("ssh", "scp"):
            targets.append(args[1] if args[0] == "ssh" else args[-1])
        return SimpleNamespace(stdout="rev\n")

    monkeypatch.setattr(deploy, "run", run)
    monkeypatch.setattr(
        sys, "argv", [str(path), "--artifacts", str(tmp_path), "--host", "root@192.168.19.101"]
    )
    deploy.main()
    assert len(targets) == 3 and all(t.startswith("root@192.168.19.101") for t in targets)


def test_rollback_restores_what_configure_nodes_rewrote(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/deploy-go.py"
    spec = importlib.util.spec_from_file_location("deploy_go_rollback", path)
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    for name in ("carrel", "carrel-deployd"):
        (tmp_path / name).write_bytes(b"static binary fixture")
    payloads = []
    monkeypatch.setattr(
        deploy, "run", lambda args, **kw: payloads.append(kw.get("input")) or SimpleNamespace(stdout="rev\n")
    )
    monkeypatch.setattr(sys, "argv", [str(path), "--artifacts", str(tmp_path)])
    deploy.main()
    program = next(p for p in payloads if p)
    rollback = program.split("except BaseException:")[1]
    assert "if activated or configured:" in rollback
    for name in ("etc/carrel/config.json", "etc/carrel/ssh_config", "etc/carrel/known_hosts"):
        assert name in rollback
    assert program.index("configured=True") < program.index("configure-nodes.py')],check=True)")
    with pytest.raises(SystemExit):
        monkeypatch.setattr(sys, "argv", [str(path), "--artifacts", str(tmp_path), "--host=-J.x"])
        deploy.main()
