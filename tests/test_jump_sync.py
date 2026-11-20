"""jump-sync.py refuses a write older than the one it holds (issue #371)."""

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KEY = (
    'restrict,port-forwarding,command="/usr/sbin/nologin",permitopen="10.200.1.10:22" '
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==\n"
)
CERTS = {"ca": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==", "principals": {"alice": ["10.200.1.10:22"]}}


@pytest.fixture
def module(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("jump_sync", ROOT / "scripts" / "jump-sync.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "KEYS", tmp_path / "keys")
    monkeypatch.setattr(mod, "CERTS", tmp_path / "certs.json")
    monkeypatch.setattr(mod, "STATE", tmp_path / "state")
    return mod


def run(monkeypatch, module, request):
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(json.dumps(request).encode())})())
    return module.main()


def sync(monkeypatch, module, text, **gen):
    return run(monkeypatch, module, {"op": "sync", "authorized": text, **gen})


def test_a_higher_gen_writes_and_a_lower_one_is_refused(monkeypatch, module):
    assert sync(monkeypatch, module, "", gen=5)["changed"] is True
    assert sync(monkeypatch, module, KEY, gen=6)["changed"] is True
    assert module.KEYS.read_text() == KEY
    assert sync(monkeypatch, module, "", gen=5) == {"changed": False, "stale": True}
    assert module.KEYS.read_text() == KEY
    assert sync(monkeypatch, module, "", gen=6)["changed"] is True


def test_a_missing_gen_still_writes(monkeypatch, module):
    sync(monkeypatch, module, KEY, gen=9)
    assert sync(monkeypatch, module, "")["changed"] is True
    assert module.KEYS.read_text() == ""


def test_certs_keep_their_own_generation(monkeypatch, module):
    other = {**CERTS, "principals": {"bob": ["10.200.2.10:22"]}}
    assert run(monkeypatch, module, {"op": "certs", "certs": CERTS, "gen": 3})["changed"] is True
    before = module.CERTS.read_text()
    assert run(monkeypatch, module, {"op": "certs", "certs": other, "gen": 2}) == {"changed": False, "stale": True}
    assert run(monkeypatch, module, {"op": "certs", "certs": None, "gen": 1}) == {"changed": False, "stale": True}
    assert module.CERTS.read_text() == before
    assert sync(monkeypatch, module, KEY, gen=1)["changed"] is True
    assert run(monkeypatch, module, {"op": "certs", "certs": other, "gen": 4})["changed"] is True


def test_a_bad_gen_is_refused(monkeypatch, module):
    for bad in ("1", -1, True, 1.5):
        with pytest.raises(ValueError):
            sync(monkeypatch, module, "", gen=bad)
