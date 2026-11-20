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
    assert sync(monkeypatch, module, "", gen=5) == {"changed": False, "stale": True, "held": 6}
    assert module.KEYS.read_text() == KEY
    assert sync(monkeypatch, module, "", gen=6)["changed"] is True


def test_a_missing_gen_writes_only_before_one_is_recorded(monkeypatch, module):
    assert sync(monkeypatch, module, KEY)["changed"] is True
    sync(monkeypatch, module, KEY, gen=9)
    with pytest.raises(ValueError):
        sync(monkeypatch, module, "")
    assert module.KEYS.read_text() == KEY
    # certs keep their own file: keys.gen does not make a certs write need gen.
    assert run(monkeypatch, module, {"op": "certs", "certs": CERTS})["changed"] is True
    run(monkeypatch, module, {"op": "certs", "certs": CERTS, "gen": 1})
    with pytest.raises(ValueError):
        run(monkeypatch, module, {"op": "certs", "certs": None})
    assert module.CERTS.exists()


def test_certs_keep_their_own_generation(monkeypatch, module):
    other = {**CERTS, "principals": {"bob": ["10.200.2.10:22"]}}
    assert run(monkeypatch, module, {"op": "certs", "certs": CERTS, "gen": 3})["changed"] is True
    before = module.CERTS.read_text()
    assert run(monkeypatch, module, {"op": "certs", "certs": other, "gen": 2}) == {
        "changed": False,
        "stale": True,
        "held": 3,
    }
    assert run(monkeypatch, module, {"op": "certs", "certs": None, "gen": 1}) == {
        "changed": False,
        "stale": True,
        "held": 3,
    }
    assert module.CERTS.read_text() == before
    assert sync(monkeypatch, module, KEY, gen=1)["changed"] is True
    assert run(monkeypatch, module, {"op": "certs", "certs": other, "gen": 4})["changed"] is True


def test_a_bad_gen_is_refused(monkeypatch, module):
    for bad in ("1", -1, True, 1.5):
        with pytest.raises(ValueError):
            sync(monkeypatch, module, "", gen=bad)


def test_a_refusal_says_which_generation_is_held(monkeypatch, module):
    sync(monkeypatch, module, KEY, gen=120)
    assert sync(monkeypatch, module, "", gen=110) == {"changed": False, "stale": True, "held": 120}
    run(monkeypatch, module, {"op": "certs", "certs": CERTS, "gen": 50})
    assert run(monkeypatch, module, {"op": "certs", "certs": None, "gen": 40}) == {
        "changed": False,
        "stale": True,
        "held": 50,
    }


def test_gen_is_checked_per_operation(monkeypatch, module):
    with pytest.raises(ValueError):
        run(monkeypatch, module, {"op": "status", "gen": 5})
    for gen in (None, "1"):
        with pytest.raises(ValueError):
            sync(monkeypatch, module, "", gen=gen)
        with pytest.raises(ValueError):
            run(monkeypatch, module, {"op": "certs", "certs": None, "gen": gen})
    assert run(monkeypatch, module, {"op": "status"}) == {"sha256": None}


def test_a_damaged_generation_file_fails_the_write(monkeypatch, module):
    sync(monkeypatch, module, KEY, gen=5)
    (module.STATE / "keys.gen").write_text("junk\n")
    for gen in (1, 9):
        with pytest.raises(RuntimeError):
            sync(monkeypatch, module, "", gen=gen)
    assert module.KEYS.read_text() == KEY


def test_a_gen_from_2_to_the_53_up_is_refused_and_so_is_such_a_sidecar(monkeypatch, module):
    with pytest.raises(ValueError):
        sync(monkeypatch, module, "", gen=2**53)
    assert sync(monkeypatch, module, "", gen=2**53 - 1)["changed"] is True
    module.STATE.joinpath("keys.gen").write_text(str(2**53) + "\n")
    with pytest.raises(RuntimeError):
        sync(monkeypatch, module, KEY, gen=1)
