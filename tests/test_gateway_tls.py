"""gateway-sync.py, the infra gateway's forced command in CT 101 (PLAN 6.4).

The control plane renders the Caddyfile and checks the certificates (Go tests);
this script only writes the files, validates with Caddy and reloads.
"""

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_gateway_sync_writes_certificates_for_caddy_and_removes_stale_ones(tmp_path, monkeypatch):
    module = load("gateway-sync.py")
    monkeypatch.setattr(module, "CERTS", tmp_path / "certs")
    owners = []
    monkeypatch.setattr(
        module.shutil, "chown", lambda path, user, group: owners.append((Path(path).name, group))
    )
    (tmp_path / "certs" / "gone").mkdir(parents=True)
    digest, stale = module.certificates({"zyx1121": {"fullchain": "A", "privkey": "B"}})
    assert (tmp_path / "certs/zyx1121/privkey.pem").read_text() == "B"
    assert oct((tmp_path / "certs/zyx1121/privkey.pem").stat().st_mode & 0o777) == "0o640"
    # Stale directories wait until Caddy accepted the new routes.
    assert stale == [tmp_path / "certs" / "gone"] and (tmp_path / "certs/gone").exists()
    assert ("privkey.pem.carrel-next", "caddy") in owners
    assert digest != module.certificates({"zyx1121": {"fullchain": "A", "privkey": "C"}})[0]
    for bad in (
        {"../x": {"fullchain": "A", "privkey": "B"}},
        {"zyx1121": {"fullchain": "A"}},
        {"origin": {"fullchain": "A", "privkey": "B"}, "_x": {}},
    ):
        with pytest.raises(ValueError):
            module.certificates(bad)


def test_gateway_sync_accepts_certificates_only_as_an_extra_key():
    module = load("gateway-sync.py")
    with pytest.raises(ValueError):
        module.apply({"hosts": "", "caddy": "", "path": "/etc/shadow"})
    with pytest.raises(ValueError):
        module.apply(json.loads('{"hosts": "", "caddy": 1}'))


def test_the_forced_command_answers_sync_and_status_only(tmp_path, monkeypatch, capsys):
    module = load("gateway-sync.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    applied = []
    monkeypatch.setattr(module, "apply", lambda state: applied.append(state) or {"changed": []})

    def call(request):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))
        return module.main()

    assert call({"op": "sync", "hosts": "", "caddy": ""}) == {"changed": []}
    assert applied == [{"hosts": "", "caddy": ""}]
    (tmp_path / "caddy.sha256").write_text("abc")
    assert call({"op": "status"}) == {"hosts": None, "caddy": "abc"}
    for bad in ({"hosts": "", "caddy": ""}, {"op": "reload"}, {"op": "status", "path": "/etc/shadow"}, []):
        with pytest.raises((ValueError, AttributeError)):
            call(bad)
