#!/usr/bin/env python3
"""Apply only the tenant gateway's DNS hosts, routes and TLS files in one CT entry."""

import hashlib
import json
import os
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


def private_directory(path):
    path.mkdir(mode=0o750, parents=True, exist_ok=True)
    path.chmod(0o750)
    shutil.chown(path, "root", "caddy")


def certificates(bundles):
    """Write each PEM pair readable by Caddy only.

    Names are fixed directories: a tenant slug, or "_origin" for carrel's own
    name, which no slug can match. Returns a digest of the set and the stale
    directories, which go only after Caddy accepted the new routes.
    """
    if not isinstance(bundles, dict):
        raise ValueError("expected certificate bundles")
    private_directory(CERTS)
    digest = hashlib.sha256()
    for name in sorted(bundles):
        pair = bundles[name]
        if not re.fullmatch(r"_origin|[a-z][a-z0-9-]{0,31}", name) or set(pair) != {"fullchain", "privkey"}:
            raise ValueError("invalid certificate bundle")
        private_directory(CERTS / name)
        for file in ("fullchain", "privkey"):
            path = CERTS / name / (file + ".pem")
            if not path.exists() or path.read_text() != pair[file]:
                pending = path.with_name(path.name + ".carrel-next")
                pending.unlink(missing_ok=True)
                # Created 0640 from the start: a key is never world-readable.
                with os.fdopen(os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640), "w") as stream:
                    stream.write(pair[file])
                shutil.chown(pending, "root", "caddy")
                pending.replace(path)
            digest.update((name + file + pair[file]).encode())
    stale = [p for p in CERTS.iterdir() if p.is_dir() and p.name not in bundles]
    return digest.hexdigest(), stale


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
    cert_digest, stale = certificates(state["certificates"]) if "certificates" in state else ("", [])
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
    for directory in stale:
        shutil.rmtree(directory)
    return {"changed": changes}


if __name__ == "__main__":
    raw = sys.stdin.buffer.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("gateway configuration too large")
    print(json.dumps(apply(json.loads(raw))))
