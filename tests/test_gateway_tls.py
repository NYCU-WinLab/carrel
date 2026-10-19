"""The infra gateway terminates TLS on a site with a public address (PLAN 15.15)."""

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pem(tmp_path, name, *hosts, days=30):
    key, crt = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
    san = ",".join("DNS:" + h for h in hosts)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            key,
            "-out",
            crt,
            "-days",
            str(days),
            "-subj",
            "/CN=" + hosts[0],
            "-addext",
            "subjectAltName=" + san,
        ],
        check=True,
        capture_output=True,
    )
    return {"fullchain": crt.read_text(), "privkey": key.read_text()}


def state(tmp_path):
    return {
        "tenants": [{"n": 3, "slug": "zyx1121"}],
        "machines": [{"vmid": 10300, "tenant_n": 3, "name": "book", "ip": "10.200.3.10"}],
        "domains": [
            {
                "id": 7,
                "vmid": 10300,
                "sub": "book",
                "name": "book.zyx1121.winlab.tw",
                "target_port": 3000,
                "state": "ready",
            }
        ],
        "certificates": [{"slug": "zyx1121", **pem(tmp_path, "wild", "*.zyx1121.winlab.tw")}],
        "origin": "carrel.winlab.tw",
        "origin_certificate": pem(tmp_path, "origin", "carrel.winlab.tw"),
    }


def real_run(module):
    # node-agent's run: a non-zero exit raises CommandFailure.
    def run(*args, **kwargs):
        p = subprocess.run([str(a) for a in args], capture_output=True, text=True, check=False)
        if p.returncode:
            raise module.CommandFailure(p.stderr)
        return p.stdout.strip()

    return run


def test_gateway_serves_the_origin_and_tenant_wildcards_over_tls(tmp_path, monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "run", real_run(module))
    caddy, certificates = module.gateway_tls(state(tmp_path), {3: "zyx1121"})
    assert set(certificates) == {"origin", "zyx1121"}
    assert "http:// {\n redir https://{host}{uri} 308\n}" in caddy
    origin = caddy.split("https://carrel.winlab.tw {")[1].split("\n}\n")[0]
    assert (
        "tls /etc/caddy/carrel-certs/origin/fullchain.pem /etc/caddy/carrel-certs/origin/privkey.pem"
        in origin
    )
    assert "@control path /mcp /mcp/* /oauth/* /.well-known/* /healthz /status /internal/* /apps/*" in origin
    assert "reverse_proxy 10.200.0.3:8080" in origin and "root * /srv/carrel-site" in origin
    tenant = caddy.split("https://*.zyx1121.winlab.tw {")[1]
    assert "@d7 host book.zyx1121.winlab.tw" in tenant and "reverse_proxy 10.200.3.10:3000" in tenant
    assert "respond 404" in tenant


def test_gateway_refuses_a_certificate_for_another_name(tmp_path, monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "run", real_run(module))
    s = state(tmp_path)
    s["certificates"] = [{"slug": "zyx1121", **pem(tmp_path, "other", "*.bensonho.winlab.tw")}]
    with pytest.raises(ValueError, match="does not cover"):
        module.gateway_tls(s, {3: "zyx1121"})


def test_gateway_refuses_a_key_from_another_certificate(tmp_path, monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "run", real_run(module))
    s = state(tmp_path)
    s["certificates"][0]["privkey"] = pem(tmp_path, "spare", "*.zyx1121.winlab.tw")["privkey"]
    with pytest.raises(ValueError, match="mismatch"):
        module.gateway_tls(s, {3: "zyx1121"})


def test_gateway_requires_a_certificate_for_every_published_tenant(tmp_path, monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "run", real_run(module))
    s = state(tmp_path)
    s["certificates"] = []
    with pytest.raises(ValueError, match="missing domain certificate"):
        module.gateway_tls(s, {3: "zyx1121"})


def test_gateway_without_an_origin_certificate_serves_tenants_only(tmp_path, monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "run", real_run(module))
    s = state(tmp_path)
    del s["origin_certificate"]
    caddy, certificates = module.gateway_tls(s, {3: "zyx1121"})
    assert "carrel.winlab.tw" not in caddy and set(certificates) == {"zyx1121"}


def test_gateway_sync_writes_certificates_for_caddy_and_removes_stale_ones(tmp_path, monkeypatch):
    module = load("gateway-sync.py")
    monkeypatch.setattr(module, "CERTS", tmp_path / "certs")
    owners = []
    monkeypatch.setattr(
        module.shutil, "chown", lambda path, user, group: owners.append((Path(path).name, group))
    )
    (tmp_path / "certs" / "gone").mkdir(parents=True)
    digest = module.certificates({"zyx1121": {"fullchain": "A", "privkey": "B"}})
    assert (tmp_path / "certs/zyx1121/privkey.pem").read_text() == "B"
    assert oct((tmp_path / "certs/zyx1121/privkey.pem").stat().st_mode & 0o777) == "0o640"
    assert not (tmp_path / "certs/gone").exists()
    assert ("privkey.pem.carrel-next", "caddy") in owners
    assert digest != module.certificates({"zyx1121": {"fullchain": "A", "privkey": "C"}})
    for bad in ({"../x": {"fullchain": "A", "privkey": "B"}}, {"zyx1121": {"fullchain": "A"}}):
        with pytest.raises(ValueError):
            module.certificates(bad)


def test_gateway_sync_accepts_certificates_only_as_an_extra_key():
    module = load("gateway-sync.py")
    with pytest.raises(ValueError):
        module.apply({"hosts": "", "caddy": "", "path": "/etc/shadow"})
    with pytest.raises(ValueError):
        module.apply(json.loads('{"hosts": "", "caddy": 1}'))
