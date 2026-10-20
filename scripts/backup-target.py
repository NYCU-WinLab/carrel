#!/usr/bin/env python3
"""Off-site store for the control plane's nightly backup, as an SSH forced command.

It runs on a host outside the cluster (today spawner, the old PVE) and accepts one
request: a gzip archive under 10 MB, kept as control-<date>.tar.gz, 14 days.
"""

import base64
import fcntl
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

BASE = Path("/var/lib/carrel-backups")
KEEP = 14


def store(archive):
    if not 1 <= len(archive) <= 10_000_000 or not archive.startswith(b"\x1f\x8b"):
        raise ValueError("invalid backup archive")
    name = datetime.now(UTC).strftime("control-%Y-%m-%d.tar.gz")
    pending = BASE / "pending"
    pending.write_bytes(archive)
    pending.chmod(0o600)
    pending.replace(BASE / name)
    for old in sorted(BASE.glob("control-*.tar.gz"))[:-KEEP]:
        old.unlink()
    return {"file": name, "bytes": len(archive)}


def main():
    BASE.mkdir(mode=0o700, exist_ok=True)
    with (BASE / "lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        raw = sys.stdin.buffer.read(14_000_001)
        if len(raw) > 14_000_000:
            raise ValueError("oversized request")
        req = json.loads(raw)
        if req.get("op") != "backup":
            raise ValueError("unknown operation")
        result = store(base64.b64decode(req["archive"], validate=True))
        print(json.dumps({"ok": True, "result": result}))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(1)
