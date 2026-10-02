#!/usr/bin/env python3
"""Apply only the tenant gateway's DNS hosts and HTTP routes in one CT entry."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

HOSTS = Path("/etc/carrel-hosts")
CADDY = Path("/etc/caddy/Caddyfile")
STATE = Path("/var/lib/carrel-gateway")


def run(*args):
    subprocess.run(args, check=True, capture_output=True, text=True, timeout=60)


def write(path, content):
    pending = path.with_name(path.name + ".carrel-next")
    pending.write_text(content)
    pending.chmod(0o644)
    pending.replace(path)


def apply(state):
    # No caller-controlled paths, command names, services or validation flags.
    if set(state) != {"hosts", "caddy"} or any(not isinstance(v, str) for v in state.values()):
        raise ValueError("expected hosts and caddy text")
    STATE.mkdir(parents=True, exist_ok=True)
    changes = []
    for name, path, service in [("hosts", HOSTS, "carrel-dns"), ("caddy", CADDY, "caddy")]:
        content = state[name]
        digest = hashlib.sha256(content.encode()).hexdigest()
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
