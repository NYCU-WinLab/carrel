"""The off-site backup target accepts one bounded gzip archive and keeps 14."""

import base64
import gzip
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "backup-target.py"


def load(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("backup_target", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "BASE", tmp_path / "backups")
    return module


def send(module, monkeypatch, capsys, request):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))
    module.main()
    return json.loads(capsys.readouterr().out)


def test_stores_one_archive_a_day_and_keeps_fourteen(tmp_path, monkeypatch, capsys):
    module = load(tmp_path, monkeypatch)
    module.BASE.mkdir(mode=0o700)
    for day in range(1, 17):
        (module.BASE / f"control-2026-09-{day:02d}.tar.gz").write_bytes(b"old")
    archive = gzip.compress(b"tar")
    result = send(
        module, monkeypatch, capsys, {"op": "backup", "archive": base64.b64encode(archive).decode()}
    )
    assert result["ok"] and result["result"]["bytes"] == len(archive)
    kept = sorted(p.name for p in module.BASE.glob("control-*.tar.gz"))
    assert len(kept) == 14 and kept[-1] == result["result"]["file"]
    assert (module.BASE / kept[-1]).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "request_body",
    [
        {"op": "reconcile", "state": {}},
        {"op": "backup", "archive": base64.b64encode(b"not gzip").decode()},
        {"op": "backup", "archive": "!!"},
    ],
)
def test_refuses_anything_but_a_gzip_backup(tmp_path, monkeypatch, request_body):
    module = load(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request_body).encode())))
    with pytest.raises((ValueError, base64.binascii.Error)):
        module.main()
    assert not list((tmp_path / "backups").glob("control-*"))
