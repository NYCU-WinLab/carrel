"""Provision the root-only credential for the two fixed Go PVE read modes.

Run on the PVE node. The credential never leaves this host and is never printed.
PVE 9.1 requires Datastore.Allocate to return all storage volumes through HTTPS;
PVEAuditor by itself can silently return an empty, incomplete volume inventory.
"""

import argparse
import json
import os
import socket
import subprocess
from pathlib import Path

CONFIG = Path("/etc/carrel/pve-read.json")
TOKEN = "carrel-go-reader"
ROLE = "CarrelReadStorage"
TOKEN_ID = "root@pam!" + TOKEN


def command(*args, optional=False):
    result = subprocess.run(args, text=True, capture_output=True, check=not optional)
    return result.stdout


def remove():
    command("pveum", "acl", "delete", "/", "--tokens", TOKEN_ID, "--roles", "PVEAuditor", optional=True)
    command(
        "pveum", "acl", "delete", "/storage/local-lvm", "--tokens", TOKEN_ID, "--roles", ROLE, optional=True
    )
    command("pveum", "user", "token", "remove", "root@pam", TOKEN, optional=True)
    command("pveum", "role", "delete", ROLE, optional=True)
    tokens = json.loads(command("pveum", "user", "token", "list", "root@pam", "--output-format", "json"))
    roles = json.loads(command("pveum", "role", "list", "--output-format", "json"))
    acls = json.loads(command("pveum", "acl", "list", "--output-format", "json"))
    if (
        any(t["tokenid"] == TOKEN for t in tokens)
        or any(r["roleid"] == ROLE for r in roles)
        or any(a.get("ugid") == TOKEN_ID for a in acls)
    ):
        raise RuntimeError("Reader credential cleanup incomplete; retain the owned config for retry")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run on the PVE node as root")
    if CONFIG.exists():
        config = json.loads(CONFIG.read_text())
        if config.get("token_id") != TOKEN_ID or config.get("role_name") != ROLE:
            raise SystemExit("Refusing a reader credential owned outside this installer")
        if args.remove:
            remove()
            CONFIG.unlink()
            print(json.dumps({"reader_credential_removed": True}))
        else:
            print(json.dumps({"reader_credential": "preserved", "path": str(CONFIG)}))
        return
    if args.remove:
        raise SystemExit("No owned reader configuration; refusing unbound credential removal")
    roles = json.loads(command("pveum", "role", "list", "--output-format", "json"))
    tokens = json.loads(command("pveum", "user", "token", "list", "root@pam", "--output-format", "json"))
    if any(r["roleid"] == ROLE for r in roles) or any(t["tokenid"] == TOKEN for t in tokens):
        raise SystemExit("Reader role or token already exists without its credential file")
    try:
        command("pveum", "role", "add", ROLE, "--privs", "Datastore.Audit Datastore.Allocate")
        token = json.loads(
            command(
                "pveum",
                "user",
                "token",
                "add",
                "root@pam",
                TOKEN,
                "--privsep",
                "1",
                "--expire",
                "0",
                "--output-format",
                "json",
            )
        )
        command("pveum", "acl", "modify", "/", "--tokens", TOKEN_ID, "--roles", "PVEAuditor")
        command("pveum", "acl", "modify", "/storage/local-lvm", "--tokens", TOKEN_ID, "--roles", ROLE)
        node = socket.gethostname().split(".")[0]
        config = {
            "base": f"https://{node}:8006",
            "node": node,
            "ca": "/etc/pve/pve-root-ca.pem",
            "authorization": "PVEAPIToken=" + TOKEN_ID + "=" + token["value"],
            "token_id": TOKEN_ID,
            "role_name": ROLE,
        }
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(os.open(CONFIG, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as stream:
            json.dump(config, stream)
    except BaseException:
        remove()
        raise
    print(
        json.dumps(
            {
                "reader_credential": "created",
                "path": str(CONFIG),
                "mode": "0600",
                "roles": {"/": "PVEAuditor", "/storage/local-lvm": ROLE},
            }
        )
    )


if __name__ == "__main__":
    main()
