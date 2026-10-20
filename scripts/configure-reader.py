"""Provision the read-only PVE API token that node-agent uses on every node.

Run as root on any node of the cluster. The token file lives in /etc/pve/priv, which
the cluster shares and only root can read, so every node gets it at once. The
token is never printed. PVE needs Datastore.Allocate on the guest storage to list
all of its volumes; PVEAuditor by itself silently returns an incomplete list.
"""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

READER = Path("/etc/pve/priv/carrel-reader.json")
NODE_CONFIG = Path("/etc/carrel/node.json")
TOKEN = "carrel-reader"
TOKEN_ID = "root@pam!" + TOKEN
ROLE = "CarrelReadStorage"


def pveum(*args, optional=False):
    result = subprocess.run(["pveum", *args], text=True, capture_output=True, check=not optional)
    return result.stdout


def listed(*args):
    return json.loads(pveum(*args, "--output-format", "json"))


def guest_storage():
    # Guest storage id from node.json (PLAN 8.2).
    storage = json.loads(NODE_CONFIG.read_text()).get("storage")
    if not isinstance(storage, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,62}", storage):
        raise SystemExit("Invalid storage id in node.json")
    return storage


def remove(storage):
    pveum("acl", "delete", "/", "--tokens", TOKEN_ID, "--roles", "PVEAuditor", optional=True)
    pveum("acl", "delete", "/storage/" + storage, "--tokens", TOKEN_ID, "--roles", ROLE, optional=True)
    pveum("user", "token", "remove", "root@pam", TOKEN, optional=True)
    pveum("role", "delete", ROLE, optional=True)
    READER.unlink(missing_ok=True)
    if (
        any(t["tokenid"] == TOKEN for t in listed("user", "token", "list", "root@pam"))
        or any(r["roleid"] == ROLE for r in listed("role", "list"))
        or any(a.get("ugid") == TOKEN_ID for a in listed("acl", "list"))
    ):
        raise SystemExit("Reader token cleanup incomplete; run --remove again")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run on a PVE node as root")
    storage = guest_storage()
    if args.remove:
        remove(storage)
        print(json.dumps({"reader_token": "removed"}))
        return
    token_exists = any(t["tokenid"] == TOKEN for t in listed("user", "token", "list", "root@pam"))
    if READER.exists() and token_exists:
        state = "preserved"
    else:
        # A token without its file has a secret nobody can read again: replace it.
        if token_exists:
            pveum("user", "token", "remove", "root@pam", TOKEN)
        token = json.loads(pveum("user", "token", "add", "root@pam", TOKEN, "--privsep", "1", "--expire", "0",
                                 "--output-format", "json"))
        text = json.dumps({"token_id": TOKEN_ID, "authorization": f"PVEAPIToken={TOKEN_ID}={token['value']}"})
        pending = READER.with_name(READER.name + ".tmp")
        pending.write_text(text)
        os.replace(pending, READER)
        state = "created"
    if not any(r["roleid"] == ROLE for r in listed("role", "list")):
        pveum("role", "add", ROLE, "--privs", "Datastore.Audit Datastore.Allocate")
    pveum("acl", "modify", "/", "--tokens", TOKEN_ID, "--roles", "PVEAuditor")
    pveum("acl", "modify", "/storage/" + storage, "--tokens", TOKEN_ID, "--roles", ROLE)
    print(json.dumps({"reader_token": state, "path": str(READER),
                      "roles": {"/": "PVEAuditor", "/storage/" + storage: ROLE}}))


if __name__ == "__main__":
    main()
