"""Validate generated upgrade/rollback programs without reaching any live host."""

import ast
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


def test_upgrade_payloads_compile_and_keep_existing_database(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/deploy-go.py"
    spec = importlib.util.spec_from_file_location("deploy_go", path)
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    for name in ("carrel", "carrel-pve-read", "carrel-deployd"):
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
    assert "/usr/local/lib/carrel/carrel-pve-read" in program
    assert "/usr/local/lib/carrel/carrel-deployd" in program
