#!/usr/bin/env python3
"""Give the control plane in CT 100 its node adapter on every site node (PLAN 15.15 gap 5).

Run as root on the first exit node, which holds CT 100, after install-network.py
and bootstrap-platform.py and after the node programs are installed there. It:

1. copies the node programs from this node to the other site nodes;
2. authorizes CT 100's node key as the node-agent forced command. In a PVE
   cluster /root/.ssh/authorized_keys is one shared file, so one line serves
   every node: CT 100 reaches this node from 10.200.0.3 and the others through
   this node's masquerade, from its management address;
3. installs the gateway's forced command in CT 101 for the same key, from
   10.200.0.3 only;
4. writes CT 100's SSH targets, pinned host keys and config.json "nodes";
5. asks every node's adapter for its inventory, and the gateway for its
   status, through CT 100.

It never prints a key or a secret, and keeps every config.json key it does not own.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess

SITE = Path("/etc/carrel/site.json")
PROGRAMS = ["node-agent.py", "guest-report.py"]
GATEWAY = {"name": "carrel-gateway", "target": "carrel-gateway", "host": "10.200.0.2"}
GATEWAY_SYNC = "/usr/local/lib/carrel/gateway-sync.py"
AUTHORIZED = Path("/root/.ssh/authorized_keys")
COMMAND = 'restrict,command="/usr/local/lib/carrel/node-agent.py"'
BEGIN, END = "# carrel nodes begin", "# carrel nodes end"


def run(*args, input=None):
    p = subprocess.run([str(a) for a in args], text=True, capture_output=True, input=input, check=False)
    if p.returncode:
        # Name the step and keep the tail of its error; inputs are never echoed.
        raise SystemExit(f"{args[0]} {args[1] if len(args) > 1 else ''} failed: {p.stderr.strip()[-400:]}")
    return p.stdout


def peer(n):
    # PVE keeps each node's host key in /etc/pve/nodes/<name>/ssh_known_hosts,
    # keyed by name; the shared known_hosts does not list every address.
    return ["-o", "BatchMode=yes", "-o", "HostKeyAlias=" + n["name"],
            "-o", f"UserKnownHostsFile=/etc/pve/nodes/{n['name']}/ssh_known_hosts"]


def ct(*args, input=None):
    return run("pct", "exec", "100", "--", *args, input=input)


def targets(site, node):
    """The first exit node keeps the alias carrel-node; the others use their names."""
    out = []
    for n in site["nodes"]:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", n["name"]):
            raise SystemExit("invalid node name in the site file")
        address = str(ipaddress.IPv4Address(n["address"]))
        if n["name"] == node:
            out.insert(0, {"name": n["name"], "target": "carrel-node", "host": "10.200.0.1", "address": address})
        else:
            out.append({"name": n["name"], "target": n["name"], "host": address, "address": address})
    return out


def authorized_line(key, exit_address):
    return f'from="10.200.0.3,{exit_address}",{COMMAND} {key}'


def merge_authorized(text, line, key):
    # Exactly one node-agent line: older ones go whatever their key or options.
    kept = [x for x in text.splitlines() if "/usr/local/lib/carrel/node-agent.py" not in x]
    return "\n".join([*kept, line]) + "\n"


def replace_file(path, text, mode):
    # Write beside the target and rename: an interrupted run never leaves the
    # cluster-wide authorized_keys empty.
    target = path.resolve()
    pending = target.with_name(target.name + ".carrel-next")
    with os.fdopen(os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as stream:
        stream.write(text)
    os.replace(pending, target)


def gateway(key):
    """Install gateway-sync.py in CT 101 as the forced command for CT 100's key."""
    run("pct", "exec", "101", "--", "install", "-d", "-m", "755", "/usr/local/lib/carrel")
    run("pct", "push", "101", GATEWAY_SYNC, GATEWAY_SYNC, "--perms", "755")
    current = run("pct", "exec", "101", "--", "sh", "-c", "cat /root/.ssh/authorized_keys 2>/dev/null || true")
    kept = [x for x in current.splitlines() if GATEWAY_SYNC not in x]
    line = f'from="10.200.0.3",restrict,command="{GATEWAY_SYNC}" {key}'
    run("pct", "exec", "101", "--", "sh", "-c",
        "umask 077 && mkdir -p /root/.ssh && cat > /root/.ssh/authorized_keys.carrel-next"
        " && mv /root/.ssh/authorized_keys.carrel-next /root/.ssh/authorized_keys",
        input="\n".join([*kept, line]) + "\n")
    return " ".join(run("pct", "exec", "101", "--", "cat", "/etc/ssh/ssh_host_ed25519_key.pub").split()[:2])


def ssh_config(existing, nodes):
    block = [BEGIN]
    for n in nodes:
        block += [f"Host {n['target']}", f"  HostName {n['host']}"]
    block.append(END)
    if BEGIN in existing and END in existing:
        head, rest = existing.split(BEGIN, 1)
        tail = rest.split(END, 1)[1]
        return head + "\n".join(block) + tail
    # Older files carry a hand-written carrel-node block; the managed block replaces it.
    lines, skip = [], False
    for line in existing.splitlines():
        if line.startswith("Host "):
            skip = line.split()[1] in {n["target"] for n in nodes}
        if not skip:
            lines.append(line)
    if not lines:
        lines = ["Host *", "  User root", "  IdentityFile /etc/carrel/node_key", "  IdentitiesOnly yes",
                 "  BatchMode yes", "  StrictHostKeyChecking yes", "  UserKnownHostsFile /etc/carrel/known_hosts",
                 "  ConnectTimeout 10"]
    return "\n".join([*lines, *block]) + "\n"


def known_hosts(existing, entries):
    hosts = {host for host, _ in entries}
    kept = [x for x in existing.splitlines() if x and x.split()[0] not in hosts]
    return "\n".join([*kept, *(f"{host} {key}" for host, key in entries)]) + "\n"


def main():
    site = json.loads(SITE.read_text())
    node = socket.gethostname().split(".")[0]
    if site["exit_nodes"][0] != node:
        raise SystemExit("run on the first exit node, which holds CT 100")
    nodes = targets(site, node)
    me = nodes[0]
    for program in [*PROGRAMS, "gateway-sync.py"]:
        if not Path("/usr/local/lib/carrel", program).exists():
            raise SystemExit(f"install the node programs here first ({program} missing)")
    # 1. Node programs on the other nodes, the same version as here.
    for n in nodes[1:]:
        run("ssh", *peer(n), "root@" + n["address"], "install -d -m 755 /usr/local/lib/carrel /var/lib/carrel")
        for program in PROGRAMS:
            run("scp", "-q", *peer(n), f"/usr/local/lib/carrel/{program}", f"root@{n['address']}:/usr/local/lib/carrel/{program}")
        run("ssh", *peer(n), "root@" + n["address"], "chmod 755 /usr/local/lib/carrel/node-agent.py")
    # 2. One forced-command line in the cluster-wide authorized_keys.
    ct("sh", "-c", 'mkdir -p /etc/carrel && { test -f /etc/carrel/node_key || ssh-keygen -q -t ed25519 -N "" -f /etc/carrel/node_key; }')
    ct("sh", "-c", "id carrel >/dev/null 2>&1 && chown carrel:carrel /etc/carrel/node_key || true; chmod 600 /etc/carrel/node_key")
    key = " ".join(ct("cat", "/etc/carrel/node_key.pub").split()[:2])
    replace_file(AUTHORIZED, merge_authorized(AUTHORIZED.read_text() if AUTHORIZED.exists() else "", authorized_line(key, me["address"]), key), 0o600)
    # 3. The gateway's forced command in CT 101.
    gateway_key = gateway(key)
    # 4. CT 100: targets, pinned host keys, the node list.
    entries = []
    for n in nodes:
        if n is me:
            host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text()
        else:
            host_key = run("ssh", *peer(n), "root@" + n["address"], "cat /etc/ssh/ssh_host_ed25519_key.pub")
        entries.append((n["host"], " ".join(host_key.split()[:2])))
    entries.append((GATEWAY["host"], gateway_key))
    current = ct("sh", "-c", "cat /etc/carrel/ssh_config 2>/dev/null || true")
    ct("sh", "-c", "umask 022 && cat > /etc/carrel/ssh_config.next && chmod 644 /etc/carrel/ssh_config.next && mv /etc/carrel/ssh_config.next /etc/carrel/ssh_config", input=ssh_config(current, [*nodes, GATEWAY]))
    current = ct("sh", "-c", "cat /etc/carrel/known_hosts 2>/dev/null || true")
    ct("sh", "-c", "umask 022 && cat > /etc/carrel/known_hosts.next && chmod 644 /etc/carrel/known_hosts.next && mv /etc/carrel/known_hosts.next /etc/carrel/known_hosts", input=known_hosts(current, entries))
    listed = json.dumps([{"name": n["name"], "target": n["target"]} for n in nodes])
    # Edited in place inside CT 100 so no other key leaves it.
    ct("python3", "-c", (
        "import json,os,sys;from pathlib import Path;p=Path('/etc/carrel/config.json');"
        "c=json.loads(p.read_text()) if p.exists() else {};c['nodes']=json.loads(sys.stdin.read());"
        "n=p.with_name('config.json.next');n.write_text(json.dumps(c,indent=2)+'\\n');"
        "s=p.stat() if p.exists() else None;"
        "s and os.chown(n,s.st_uid,s.st_gid);os.chmod(n,s.st_mode&0o777 if s else 0o640);os.replace(n,p)"
    ), input=listed)
    # 5. Every adapter answers CT 100 with its own name; the gateway answers too.
    report = {}
    for n in nodes:
        out = ct("ssh", "-F", "/etc/carrel/ssh_config", n["target"], input='{"op":"inventory"}')
        result = json.loads(out)
        if not result.get("ok") or result["result"].get("node") != n["name"]:
            raise SystemExit(f"{n['name']} did not answer through {n['target']}")
        report[n["name"]] = n["target"]
    status = json.loads(ct("ssh", "-F", "/etc/carrel/ssh_config", GATEWAY["target"], input='{"op":"status"}'))
    if not status.get("ok"):
        raise SystemExit("the gateway did not answer through carrel-gateway")
    print(json.dumps({"nodes": report, "gateway": GATEWAY["target"]}))


if __name__ == "__main__":
    main()
