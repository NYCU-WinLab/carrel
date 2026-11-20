#!/usr/bin/env python3
"""The SSH jump host's forced command: install the jump user's authorized keys.

Runs in CT 102 for the control plane's key (configure-nodes.py installs it). One
JSON request on stdin: {"op": "sync", "authorized": text}, {"op": "certs",
"certs": {"ca": key, "principals": {name: [address:22, ...]}} or null} or
{"op": "status"}. Every line must forward only to tenant machines: port 22
(issue #98), or a port a machine without SSH declares (issue #94), which its
firewall admits.
Both requests take an optional integer "gen"; a write older than the last one accepted
for that file is refused with {"changed": false, "stale": true}. The certificate map lets jump-cert.py forward a lab
certificate to port 22 of the machines whose principals file names one of
its principals.
"""

import fcntl
import hashlib
import json
import os
import re
import sys
from pathlib import Path

KEYS = Path("/etc/carrel-jump/jump")
CERTS = Path("/etc/carrel-jump/certs.json")
STATE = Path("/var/lib/carrel-jump")
ADDRESS = r"10\.200\.(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])\.(?:[1-9]\d|10\d)"
TARGET = r'permitopen="10\.200\.(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])\.(?:[1-9]\d|10\d):(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d\d|655[0-2]\d|6553[0-5])"'
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


# The lab CA's public key, with no comment; a principal as Carrel writes it in
# a machine's principals file; port 22 of a tenant machine.
CA = re.compile(r"(?:ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,2}", re.ASCII)
PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}|project:[a-z0-9][a-z0-9-]{0,62}", re.ASCII)
SSH_TARGET = re.compile(ADDRESS + ":22", re.ASCII)


def check_certs(certs):
    if not isinstance(certs, dict) or set(certs) != {"ca", "principals"}:
        raise ValueError("expected a certificate map")
    ca, principals = certs["ca"], certs["principals"]
    if not isinstance(ca, str) or not CA.fullmatch(ca) or not isinstance(principals, dict):
        raise ValueError("expected a certificate map")
    for name, targets in principals.items():
        if not PRINCIPAL.fullmatch(name) or not isinstance(targets, list) or not targets:
            raise ValueError("refusing a principal")
        if not all(isinstance(t, str) and SSH_TARGET.fullmatch(t) for t in targets):
            raise ValueError("refusing a certificate target")
    return json.dumps({"ca": ca, "principals": principals}, sort_keys=True) + "\n"


def write(path, content):
    pending = path.with_name(path.name + ".carrel-next")
    pending.write_text(content)
    pending.chmod(0o644)
    pending.replace(path)


def stale(name, gen):
    """True when a write older than the last accepted one; else records gen. Call under the lock."""
    if gen is None:
        return False
    path = STATE / name
    try:
        held = int(path.read_text())
    except (FileNotFoundError, ValueError):
        held = None
    if held is not None and gen < held:
        return True
    if held != gen:
        write(path, str(gen) + "\n")
    return False


def main():
    raw = sys.stdin.buffer.read(16_000_101)
    if len(raw) > 16_000_100:
        raise ValueError("request too large")
    request = json.loads(raw)
    op = request.pop("op", None) if isinstance(request, dict) else None
    gen = request.pop("gen", None) if isinstance(request, dict) else None
    if gen is not None and (type(gen) is not int or gen < 0):
        raise ValueError("expected an integer generation")
    STATE.mkdir(parents=True, exist_ok=True)
    if op == "status" and not request:
        return {"sha256": hashlib.sha256(KEYS.read_bytes()).hexdigest() if KEYS.exists() else None}
    if op == "certs" and set(request) == {"certs"}:
        # null: the site has no CA any more, so no certificate passes.
        text = None if request["certs"] is None else check_certs(request["certs"])
        with open(STATE / "lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if stale("certs.gen", gen):
                return {"changed": False, "stale": True}
            if text is None:
                changed = CERTS.exists()
                CERTS.unlink(missing_ok=True)
                return {"changed": changed, "principals": 0}
            CERTS.parent.mkdir(mode=0o755, exist_ok=True)
            changed = not CERTS.exists() or CERTS.read_text() != text
            if changed:
                write(CERTS, text)
            else:
                # The age is the proof a control plane still keeps the map.
                os.utime(CERTS)
        return {"changed": changed, "sha256": hashlib.sha256(text.encode()).hexdigest(), "principals": len(request["certs"]["principals"])}
    if op != "sync" or set(request) != {"authorized"}:
        raise ValueError("unknown operation")
    text = check(request["authorized"])
    with open(STATE / "lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if stale("keys.gen", gen):
            return {"changed": False, "stale": True}
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
