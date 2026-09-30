"""Consistent daily control-plane backup to the independent ingress host."""

import asyncio
import base64
import json
import os
import sqlite3
import tarfile
import tempfile
from pathlib import Path

from .backend import Backend


async def main():
    os.umask(0o077)
    config = json.loads(Path("/etc/carrel/config.json").read_text())
    with tempfile.TemporaryDirectory(dir="/var/lib/carrel") as temp:
        database = Path(temp) / "carrel.db"
        with sqlite3.connect(config["database"]) as source, sqlite3.connect(database) as target:
            source.backup(target)
            if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Database integrity check failed")
        archive = Path(temp) / "control.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(database, arcname="carrel.db")
            for name in ["config.json", "node_key", "node_key.pub", "ssh_config", "known_hosts"]:
                tar.add("/etc/carrel/" + name, arcname="etc/carrel/" + name)
            certificates = Path(config.get("certificate_dir", "/var/lib/carrel/certificates"))
            if certificates.exists():
                tar.add(certificates, arcname="certificates")
        content = archive.read_bytes()
        if len(content) > 10_000_000:
            raise RuntimeError("Backup exceeds bounded transfer size; operator action required")
        result = await Backend().call(
            {"op": "backup", "archive": base64.b64encode(content).decode()}, "carrel-edge"
        )
        print(json.dumps({"event": "backup_complete", **result}))


if __name__ == "__main__":
    asyncio.run(main())
