#!/usr/bin/env python3
"""Apply only the tenant gateway's DNS hosts, routes and TLS files in one CT entry."""

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

HOSTS = Path("/etc/carrel-hosts")
CADDY = Path("/etc/caddy/Caddyfile")
STATE = Path("/var/lib/carrel-gateway")
CERTS = Path("/etc/caddy/carrel-certs")


def run(*args):
    subprocess.run(args, check=True, capture_output=True, text=True, timeout=60)


def write(path, content):
    pending = path.with_name(path.name + ".carrel-next")
    pending.write_text(content)
    pending.chmod(0o644)
    pending.replace(path)


def certificates(bundles):
    """Write each PEM pair readable by Caddy only; return a digest of the set.

    Names are fixed directories (a tenant slug or "origin"); stale ones go.
    """
    if not isinstance(bundles, dict):
        raise ValueError("expected certificate bundles")
    CERTS.mkdir(mode=0o750, parents=True, exist_ok=True)
    shutil.chown(CERTS, "root", "caddy")
    digest = hashlib.sha256()
    for name in sorted(bundles):
        pair = bundles[name]
        if not re.fullmatch(r"origin|[a-z][a-z0-9-]{0,31}", name) or set(pair) != {"fullchain", "privkey"}:
            raise ValueError("invalid certificate bundle")
        directory = CERTS / name
        directory.mkdir(mode=0o750, exist_ok=True)
        shutil.chown(directory, "root", "caddy")
        for file in ("fullchain", "privkey"):
            path = directory / (file + ".pem")
            if not path.exists() or path.read_text() != pair[file]:
                pending = path.with_name(path.name + ".carrel-next")
                pending.write_text(pair[file])
                pending.chmod(0o640)
                shutil.chown(pending, "root", "caddy")
                pending.replace(path)
            digest.update((name + file + pair[file]).encode())
    for stale in CERTS.iterdir():
        if stale.is_dir() and stale.name not in bundles:
            shutil.rmtree(stale)
    return digest.hexdigest()


def apply(state):
    # No caller-controlled paths, command names, services or validation flags.
    keys = set(state)
    if keys not in ({"hosts", "caddy"}, {"hosts", "caddy", "certificates"}) or any(
        not isinstance(state[k], str) for k in ("hosts", "caddy")
    ):
        raise ValueError("expected hosts and caddy text")
    STATE.mkdir(parents=True, exist_ok=True)
    changes = []
    # Caddy validates the files the routes name, so they land first; a new
    # certificate alone changes the receipt and reloads Caddy.
    cert_digest = certificates(state["certificates"]) if "certificates" in state else ""
    for name, path, service in [("hosts", HOSTS, "carrel-dns"), ("caddy", CADDY, "caddy")]:
        content = state[name]
        digest = hashlib.sha256((content + (cert_digest if name == "caddy" else "")).encode()).hexdigest()
        receipt = STATE / (name + ".sha256")
        changed = not path.exists() or path.read_text() != content
        applied = receipt.exists() and receipt.read_text() == digest
        if changed or not applied:
            if name == "caddy":
                pending = path.with_name(path.name + ".carrel-validate")
                try:
                    pending.write_text(content)
                    pending.chmod(0o644)
                    run(
                        "/usr/local/bin/caddy", "validate", "--adapter", "caddyfile", "--config", str(pending)
                    )
                finally:
                    pending.unlink(missing_ok=True)
            write(path, content)
            run("systemctl", "restart" if name == "hosts" else "reload-or-restart", service)
            # A failed apply must be retried even when the file already changed.
            write(receipt, digest)
            changes.append(name)
        else:
            # Recover stopped services without rewriting or reloading healthy ones.
            run("systemctl", "start", service)
    return {"changed": changes}


if __name__ == "__main__":
    raw = sys.stdin.buffer.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("gateway configuration too large")
    print(json.dumps(apply(json.loads(raw))))
