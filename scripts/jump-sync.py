#!/usr/bin/env python3
"""The SSH jump host's forced command: install the jump user's authorized keys.

Runs in CT 102 for the control plane's key (configure-nodes.py installs it). One
JSON request on stdin: {"op": "sync", "authorized": text} or {"op": "status"}.
Every line must forward only to port 22 of tenant machines (issue #98).
"""

import fcntl
import hashlib
import json
from pathlib import Path
import re
import sys

KEYS = Path("/etc/carrel-jump/jump")
STATE = Path("/var/lib/carrel-jump")
TARGET = r'permitopen="10\.200\.(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])\.(?:[1-9]\d|10\d):22"'
LINE = re.compile(
    r'restrict,port-forwarding,command="/usr/sbin/nologin",' + TARGET + "(?:," + TARGET + ")*"
    r" (?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,3}",
    re.ASCII,
)


def check(text):
    if not isinstance(text, str) or len(text) > 16_000_000 or (text and not text.endswith("\n")):
        raise ValueError("expected authorized keys text")
    # sshd splits on newlines only; so does this check.
    for line in text[:-1].split("\n") if text else []:
        if not LINE.fullmatch(line):
            raise ValueError("refusing an authorized keys line")
    return text


def write(path, content):
    pending = path.with_name(path.name + ".carrel-next")
    pending.write_text(content)
    pending.chmod(0o644)
    pending.replace(path)


def main():
    raw = sys.stdin.buffer.read(16_000_101)
    if len(raw) > 16_000_100:
        raise ValueError("request too large")
    request = json.loads(raw)
    op = request.pop("op", None) if isinstance(request, dict) else None
    STATE.mkdir(parents=True, exist_ok=True)
    if op == "status" and not request:
        return {"sha256": hashlib.sha256(KEYS.read_bytes()).hexdigest() if KEYS.exists() else None}
    if op != "sync" or set(request) != {"authorized"}:
        raise ValueError("unknown operation")
    text = check(request["authorized"])
    with open(STATE / "lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        KEYS.parent.mkdir(mode=0o755, exist_ok=True)
        changed = not KEYS.exists() or KEYS.read_text() != text
        if changed:
            write(KEYS, text)
    return {"changed": changed, "sha256": hashlib.sha256(text.encode()).hexdigest(), "keys": text.count("\n")}


if __name__ == "__main__":
    try:
        print(json.dumps({"ok": True, "result": main()}))
    except Exception as e:  # noqa: BLE001 (the forced command answers every failure in JSON)
        code = "invalid_request" if isinstance(e, ValueError) else "adapter_internal"
        print(json.dumps({"ok": False, "error_code": code, "error": "Jump sync failed"}))
        sys.exit(1)
