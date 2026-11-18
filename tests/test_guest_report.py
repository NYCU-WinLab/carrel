"""The guest reporter keeps /etc/ssh/principals/user in step with Carrel (machine_access)."""

import importlib.util
from pathlib import Path

import pytest


def load(tmp_path):
    path = Path(__file__).parents[1] / "scripts" / "guest-report.py"
    spec = importlib.util.spec_from_file_location("guest_report", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.PRINCIPALS = tmp_path / "user"
    return module


def test_it_writes_the_list_carrel_answers(tmp_path):
    module = load(tmp_path)
    module.PRINCIPALS.write_text("alice\n")
    module.apply_principals(["alice", "bob", "project:demo"])
    assert module.PRINCIPALS.read_text() == "alice\nbob\nproject:demo\n"
    assert module.current_principals() == ["alice", "bob", "project:demo"]
    assert module.PRINCIPALS.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize(
    "bad",
    [None, "alice", [], ["alice\nroot"], ["svc:carrel"], ["Alice"], ["../root"], [1], ["a"] * 52],
)
def test_it_keeps_the_file_on_anything_else(tmp_path, bad):
    module = load(tmp_path)
    module.PRINCIPALS.write_text("alice\n")
    module.apply_principals(bad)
    assert module.PRINCIPALS.read_text() == "alice\n"


def test_without_the_ca_files_it_writes_nothing(tmp_path):
    module = load(tmp_path)
    module.PRINCIPALS = tmp_path / "missing" / "user"
    module.apply_principals(["alice"])
    assert not module.PRINCIPALS.exists()
    assert module.current_principals() is None
