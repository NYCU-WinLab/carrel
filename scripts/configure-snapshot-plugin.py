"""Provision the PVE API token that the snapshot plugin uses on this node (#663).

Run as root on every node that runs the plugin. The token holds VM.Snapshot,
VM.Snapshot.Rollback and VM.Audit on /vms, and nothing else: power stays with
carrel and node-agent. Its secret lives in /etc/pve/priv, which the cluster
shares and only root can read, so every node uses the same token. The script
writes this node's environment file for the plugin, root's and mode 0600, and
copies the cluster CA where the plugin's dynamic user can read it: it cannot
read /etc/pve/pve-root-ca.pem (root:www-data 0640). The token is never printed.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

SECRET = Path("/etc/pve/priv/carrel-snapshot.json")
LOCAL = Path("/etc/pve/local")
CLUSTER_CA = Path("/etc/pve/pve-root-ca.pem")
PLUGIN_ENV = Path("/etc/carrel/plugins")
ENV = PLUGIN_ENV / "snapshot.env"
CA = PLUGIN_ENV / "snapshot-ca.pem"
TOKEN = "carrel-snapshot"
TOKEN_ID = "root@pam!" + TOKEN
ROLE = "CarrelSnapshot"
PRIVS = "VM.Audit VM.Snapshot VM.Snapshot.Rollback"


def pveum(*args, optional=False):
    result = subprocess.run(["pveum", *args], text=True, capture_output=True, check=not optional)
    return result.stdout


def listed(*args):
    return json.loads(pveum(*args, "--output-format", "json"))


def node_name():
    # /etc/pve/local links to nodes/<name>: the PVE node name, which can
    # differ from the host name.
    name = os.readlink(LOCAL).rstrip("/").rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", name):
        raise SystemExit("Unexpected PVE node name in /etc/pve/local")
    return name


def write(path, text, mode):
    pending = path.with_name(path.name + ".tmp")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(pending, mode)
    os.replace(pending, path)


def remove():
    pveum("acl", "delete", "/vms", "--tokens", TOKEN_ID, "--roles", ROLE, optional=True)
    pveum("user", "token", "remove", "root@pam", TOKEN, optional=True)
    pveum("role", "delete", ROLE, optional=True)
    for path in (SECRET, ENV, CA):
        path.unlink(missing_ok=True)
    if (
        any(t["tokenid"] == TOKEN for t in listed("user", "token", "list", "root@pam"))
        or any(r["roleid"] == ROLE for r in listed("role", "list"))
        or any(a.get("ugid") == TOKEN_ID for a in listed("acl", "list"))
    ):
        raise SystemExit("Snapshot token cleanup incomplete; run --remove again")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove", action="store_true", help="remove the token, its role and this node's files")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run on a PVE node as root")
    if args.remove:
        remove()
        print(json.dumps({"snapshot_token": "removed"}))
        return
    node = node_name()
    token_exists = any(t["tokenid"] == TOKEN for t in listed("user", "token", "list", "root@pam"))
    if SECRET.exists() and token_exists:
        state = "preserved"
    else:
        # A token without its file has a secret nobody can read again: replace it.
        if token_exists:
            pveum("user", "token", "remove", "root@pam", TOKEN)
        token = json.loads(pveum("user", "token", "add", "root@pam", TOKEN, "--privsep", "1", "--expire", "0",
                                 "--output-format", "json"))
        write(SECRET, json.dumps({"token_id": TOKEN_ID, "authorization": f"PVEAPIToken={TOKEN_ID}={token['value']}"}), 0o600)
        state = "created"
    if any(r["roleid"] == ROLE for r in listed("role", "list")):
        pveum("role", "modify", ROLE, "--privs", PRIVS)
    else:
        pveum("role", "add", ROLE, "--privs", PRIVS)
    pveum("acl", "modify", "/vms", "--tokens", TOKEN_ID, "--roles", ROLE)
    authorization = json.loads(SECRET.read_text())["authorization"]
    PLUGIN_ENV.mkdir(mode=0o755, parents=True, exist_ok=True)
    write(ENV, "".join(f'{k}="{v}"\n' for k, v in (
        ("CARREL_PVE_URL", "https://localhost:8006"), ("CARREL_PVE_NODE", node),
        ("CARREL_PVE_CA", str(CA)), ("CARREL_PVE_TOKEN", authorization))), 0o600)
    pending = CA.with_name(CA.name + ".tmp")
    shutil.copyfile(CLUSTER_CA, pending)
    os.chmod(pending, 0o644)
    os.replace(pending, CA)
    print(json.dumps({"snapshot_token": state, "node": node, "env": str(ENV), "ca": str(CA), "roles": {"/vms": ROLE}}))


if __name__ == "__main__":
    main()
