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
   status, through CT 100;
6. prepares carrel-agent for the nodes the site file lists in "agent_nodes"
   (PLAN 8.6): a CA and the listener's certificate, a token per node, and the
   node's transport set to agent. Every other node keeps the SSH transport.
   With "agent_identity" (#601) each agent also gets the lab root and a place
   for its step-ca certificate, and the nodes in its "certificate_nodes" sign
   in with that certificate only.

`--agent-service` starts or stops the agent itself. install-control.py runs it
only once the new control plane is healthy, so a failed upgrade never touches
a running agent, and an agent that stops can still hand in its last answers.

It never prints a key or a secret, and keeps every config.json key it does not own.
"""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import time
from pathlib import Path

SITE = Path("/etc/carrel/site.json")
PROGRAMS = ["node-agent.py", "guest-report.py"]
# The control plane reaches the gateway, the jump host and the off-site backup
# with its service key, never with the node key, so the node key can go once
# every node uses the agent (#606, #604).
SERVICE_KEY = "/etc/carrel/service_key"
GATEWAY = {"name": "carrel-gateway", "target": "carrel-gateway", "host": "10.200.0.2", "identity": SERVICE_KEY}
GATEWAY_SYNC = "/usr/local/lib/carrel/gateway-sync.py"
JUMP = {"name": "carrel-jump", "target": "carrel-jump", "host": "10.200.0.4", "identity": SERVICE_KEY}
# The backup target is outside the cluster; its address stays in the hand-written
# part of ssh_config, and only its key is managed here.
BACKUP = {"target": "carrel-backup", "identity": SERVICE_KEY}
JUMP_SYNC = "/usr/local/lib/carrel/jump-sync.py"
JUMP_CERT = "/usr/local/lib/carrel/jump-cert.py"
# Lab certificates on the jump host, for the user ca: jump-cert.py turns a certificate's
# principals into one line naming the machines they open (certs.json, which
# jump-sync.py keeps). The script and its folder belong to root, as sshd
# requires of an AuthorizedKeysCommand. The Match block keeps the command off `jump@`,
# which would otherwise start python3 for every key before authentication; a Match
# ends with its drop-in file, so nothing read after it is scoped to ca.
JUMP_CERT_SSHD = f"""# Managed by carrel configure-nodes.py: lab certificates.
Match User ca
    AuthorizedKeysCommand {JUMP_CERT} %u %t %k
    AuthorizedKeysCommandUser nobody
"""
AUTHORIZED = Path("/root/.ssh/authorized_keys")
COMMAND = 'restrict,command="/usr/local/lib/carrel/node-agent.py"'
BEGIN, END = "# carrel nodes begin", "# carrel nodes end"

# carrel-agent (PLAN 8.6). The CA stays on the first exit node, root only; CT 100
# gets the listener's certificate and key, the node the CA to pin and its token.
AGENT_CA = Path("/etc/carrel/agent-ca")
AGENT_TOKEN = Path("/etc/carrel/agent-token")
# An operator asks for a new token by creating this file. The old token stays
# until the new one is written, so a failed deploy puts the old one back.
AGENT_ROTATE = Path("/etc/carrel/agent-token.rotate")
AGENT_JSON = Path("/etc/carrel/agent.json")
AGENT_UNIT = Path("/etc/systemd/system/carrel-agent.service")
AGENT_LISTEN = "10.200.0.3:8443"
# The first exit node reaches 10.200.0.3 from its infra address. Every other
# node reaches it through a host route via the first exit node (no NAT), so the
# control plane sees that node's own underlay address; bootstrap-platform.py
# opens port 8443 for those addresses only.
AGENT_SOURCE = "10.200.0.1"
# Tokens of the other nodes, one file each (the first node's stays in AGENT_TOKEN).
AGENT_TOKENS = Path("/etc/carrel/agent-tokens")
AGENT_TLS = "/etc/carrel/agent"
# Certificate sign-in (#601). The site file's "agent_identity" names the lab
# step-ca, its root and the carrel-agents provisioner's key id. Every agent
# node then gets the root and a place for its key and certificate, and presents
# the certificate once an operator enrols it; the nodes in
# "certificate_nodes" sign in with it only, and their token is refused.
AGENT_LAB_ROOT = Path("/etc/carrel/lab-root.pem")
AGENT_IDENTITY = Path("/etc/carrel/agent-identity")
AGENT_DOMAIN = "agent.carrel.winlab.tw"
LISTENER_LAB_ROOT = f"{AGENT_TLS}/lab-root.pem"
# A CA for 10 years, the listener's certificate for 825 days, renewed by any
# run with less than 90 days left. The agent pins the CA, so a renewal needs
# nothing on the node.
AGENT_CERTIFICATES = f"""set -e
umask 077
d={AGENT_CA}
mkdir -p $d
if ! [ -s $d/ca.key ] || ! [ -s $d/ca.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=carrel agent CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout $d/ca.key.next -out $d/ca.pem.next
  mv $d/ca.key.next $d/ca.key
  mv $d/ca.pem.next $d/ca.pem
  rm -f $d/server.pem
fi
if ! [ -s $d/server.pem ] || ! openssl x509 -in $d/server.pem -noout -checkend 7776000 >/dev/null \
    || ! openssl verify -CAfile $d/ca.pem $d/server.pem >/dev/null; then
  printf 'subjectAltName=IP:{AGENT_LISTEN.split(":")[0]}\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' > $d/server.ext
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN={AGENT_LISTEN.split(":")[0]}" \
    -keyout $d/server.key.next -out $d/server.csr
  openssl x509 -req -in $d/server.csr -CA $d/ca.pem -CAkey $d/ca.key -set_serial "0x$(openssl rand -hex 16)" \
    -days 825 -extfile $d/server.ext -out $d/server.pem.next
  mv $d/server.key.next $d/server.key
  mv $d/server.pem.next $d/server.pem
  rm -f $d/server.csr $d/server.ext
fi
"""
# SIGTERM reaches the agent alone: it takes no new job, answers the ones that
# run, then exits. Root ops run up to 4 hours (migrate, freeze), so systemd
# waits that long before it kills what is left.
AGENT_SERVICE = f"""[Unit]
Description=Carrel node agent (PLAN 8.6)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/lib/carrel/carrel-agent -config {AGENT_JSON}
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=4h30min
[Install]
WantedBy=multi-user.target
"""


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


def agent_nodes(site, nodes):
    """The names in the site file's agent_nodes, checked against the site."""
    names = site.get("agent_nodes", [])
    for name in names:
        if name not in {n["name"] for n in nodes}:
            raise SystemExit(f"agent_nodes names {name}, which is not a site node")
    return set(names)


def agent_identity(site, nodes, agents):
    """The site file's agent_identity, checked, or None.

    certificate_nodes must be agent nodes: a node on SSH has no agent to sign in."""
    identity = site.get("agent_identity")
    if not identity:
        return None
    if not isinstance(identity, dict) or set(identity) - {"ca_url", "lab_root", "provisioner", "certificate_nodes"}:
        raise SystemExit("agent_identity takes ca_url, lab_root, provisioner and certificate_nodes")
    if not re.fullmatch(r"https://[a-z0-9.-]+(:[0-9]+)?", identity.get("ca_url", "")):
        raise SystemExit("agent_identity.ca_url must be an https URL with no path, such as https://ca.winlab.tw")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", identity.get("provisioner", "")):
        raise SystemExit("agent_identity.provisioner must be the provisioner's key id")
    root = identity.get("lab_root", "")
    if not root.startswith("-----BEGIN CERTIFICATE-----") or root.count("-----BEGIN") != 1:
        raise SystemExit("agent_identity.lab_root must be the lab root certificate, in PEM")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", site.get("site", "")):
        raise SystemExit('agent_identity needs "site", a lower-case DNS label')
    if not isinstance(identity.get("certificate_nodes", []), list):
        raise SystemExit("agent_identity.certificate_nodes must be a list of node names")
    for name in identity.get("certificate_nodes", []):
        if name not in agents:
            raise SystemExit(f"agent_identity.certificate_nodes names {name}, which is not in agent_nodes")
    return identity


def agent_certificate_name(site, name):
    """The one name a node's agent certificate carries."""
    return f"{name}.{site['site']}.{AGENT_DOMAIN}"


def agent_config(site, identity, name):
    """A node's agent.json: the listener, its token, and with agent_identity its certificate."""
    out = {"control": "https://" + AGENT_LISTEN, "ca_file": str(AGENT_CA / "ca.pem"),
           "token_file": str(AGENT_TOKEN), "node": name}
    if identity:
        out.update({"cert_file": str(AGENT_IDENTITY / "agent.crt"), "key_file": str(AGENT_IDENTITY / "agent.key"),
                    "certificate_name": agent_certificate_name(site, name), "ca_url": identity["ca_url"],
                    "lab_root_file": str(AGENT_LAB_ROOT)})
    return json.dumps(out, indent=2) + "\n"


def token_files(n, first):
    """The token file and the rotate file of a node: the first node's keep their old paths."""
    if first:
        return AGENT_TOKEN, AGENT_ROTATE
    AGENT_TOKENS.mkdir(mode=0o700, exist_ok=True)
    return AGENT_TOKENS / n["name"], AGENT_TOKENS / (n["name"] + ".rotate")


def agent_token(token=None, rotate=None):
    """A node's agent token: made once, kept across runs. Returns its digest."""
    token, rotate = token or AGENT_TOKEN, rotate or AGENT_ROTATE
    if rotate.exists() or not token.exists() or not token.read_text().strip():
        replace_file(token, secrets.token_urlsafe(32), 0o600)
        rotate.unlink(missing_ok=True)
    return hashlib.sha256(token.read_text().strip().encode()).hexdigest()


def agent_digests(nodes, agents):
    """Every agent node's token digest, by name."""
    return {n["name"]: agent_token(*token_files(n, n is nodes[0])) for n in nodes if n["name"] in agents}


def agent_listener():
    """Make the CA and the listener's certificate here, then give CT 100 the certificate."""
    run("sh", "-c", AGENT_CERTIFICATES)
    ct("install", "-d", "-m", "755", AGENT_TLS)
    for name, mode in (("server.pem", "644"), ("server.key", "600")):
        run("pct", "push", "100", AGENT_CA / name, f"{AGENT_TLS}/{name}.next", "--perms", mode)
    # The service reads its key as carrel; the rename keeps a running one's files whole.
    ct("sh", "-c", f"cd {AGENT_TLS} && chown carrel:carrel server.key.next && mv server.pem.next server.pem"
       " && mv server.key.next server.key")
    return {"agent_listen": AGENT_LISTEN, "agent_cert_file": f"{AGENT_TLS}/server.pem",
            "agent_key_file": f"{AGENT_TLS}/server.key"}


def agent_service():
    """Start the agent on this node when the site file lists it, else stop it.

    --no-block: an agent finishing a long job keeps its old process until the
    job is answered, and the deploy does not wait for it."""
    site = json.loads(SITE.read_text())
    me = targets(site, socket.gethostname().split(".")[0])[0]
    agents = agent_nodes(site, targets(site, me["name"]))
    if me["name"] in agents:
        identity = agent_identity(site, targets(site, me["name"]), agents)
        if identity:
            replace_file(AGENT_LAB_ROOT, identity["lab_root"].strip() + "\n", 0o644)
            AGENT_IDENTITY.mkdir(mode=0o700, exist_ok=True)
        replace_file(AGENT_JSON, agent_config(site, identity, me["name"]), 0o644)
        replace_file(AGENT_UNIT, AGENT_SERVICE, 0o644)
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "carrel-agent.service")
        # A new binary or token takes effect.
        run("systemctl", "restart", "--no-block", "carrel-agent.service")
        return "started"
    if AGENT_UNIT.exists():
        run("systemctl", "disable", "--now", "--no-block", "carrel-agent.service")
        return "stopped"
    return "absent"


def peer_unit(me, n):
    """The agent unit of another node, with the route to the listener through the first node."""
    route = f"ExecStartPre=/usr/sbin/ip route replace 10.200.0.3/32 via {me['address']} src {n['address']}\n"
    return AGENT_SERVICE.replace("ExecStart=", route + "ExecStart=", 1)


def peer_write(n, path, text, mode):
    run("ssh", *peer(n), "root@" + n["address"],
        f"umask 077 && mkdir -p {Path(path).parent} && cat > {path}.carrel-next && chmod {mode} {path}.carrel-next"
        f" && mv {path}.carrel-next {path}", input=text)


def agent_peers():
    """Start the agent on each other node the site file lists, stop it on the rest.

    Returns each node's state: pushed, removed or absent (never "started", which
    install-control.py reads as this node's agent)."""
    site = json.loads(SITE.read_text())
    nodes = targets(site, socket.gethostname().split(".")[0])
    agents = agent_nodes(site, nodes)
    identity = agent_identity(site, nodes, agents)
    out = {}
    for n in nodes[1:]:
        ssh = ("ssh", *peer(n), "root@" + n["address"])
        if n["name"] in agents:
            token, _ = token_files(n, False)
            peer_write(n, AGENT_TOKEN, token.read_text(), "600")
            peer_write(n, AGENT_CA / "ca.pem", (AGENT_CA / "ca.pem").read_text(), "644")
            if identity:
                peer_write(n, AGENT_LAB_ROOT, identity["lab_root"].strip() + "\n", "644")
                run(*ssh, f"install -d -m 700 {AGENT_IDENTITY}")
            peer_write(n, AGENT_JSON, agent_config(site, identity, n["name"]), "644")
            peer_write(n, AGENT_UNIT, peer_unit(nodes[0], n), "644")
            run(*ssh, "systemctl daemon-reload && systemctl enable carrel-agent.service"
                " && systemctl restart --no-block carrel-agent.service")
            out[n["name"]] = "pushed"
        elif run(*ssh, f"test -e {AGENT_UNIT} && echo yes || true").strip():
            run(*ssh, "systemctl disable --now --no-block carrel-agent.service")
            out[n["name"]] = "removed"
        else:
            out[n["name"]] = "absent"
    return out


def peers_connected(since, wait=60):
    """The other agent nodes whose agent logged agent_connected after since, within wait seconds.

    Returns the names that never did: their jobs wait on an agent that cannot
    reach the listener (for example an infra firewall without the 8443 rule)."""
    site = json.loads(SITE.read_text())
    nodes = targets(site, socket.gethostname().split(".")[0])
    agents = agent_nodes(site, nodes)
    pending = [n for n in nodes[1:] if n["name"] in agents]
    for _ in range(wait):
        for n in list(pending):
            # A stalled peer costs at most 10 s a round and does not block the others.
            try:
                log = subprocess.run(["ssh", "-o", "ConnectTimeout=5", *peer(n), "root@" + n["address"],
                                      f"journalctl -u carrel-agent --since @{int(since)} -o cat"],
                                     text=True, capture_output=True, check=False, timeout=10).stdout
            except subprocess.TimeoutExpired:
                log = ""
            if '"agent_connected"' in (log or ""):
                pending.remove(n)
        if not pending:
            break
        time.sleep(1)
    return [n["name"] for n in pending]


def node_entries(nodes, agents, digests, certificates=None):
    """config.json "nodes": an agent node carries its transport, token digest and source.

    A node in certificates (name: certificate name) carries the name its
    certificate must have instead of a token digest: its token is refused."""
    certificates = certificates or {}
    out = []
    for n in nodes:
        entry = {"name": n["name"], "target": n["target"]}
        if n["name"] in agents:
            entry.update({"transport": "agent", "agent_source": AGENT_SOURCE if n["target"] == "carrel-node" else n["address"]})
            if n["name"] in certificates:
                entry["agent_certificate"] = certificates[n["name"]]
            else:
                entry["agent_token_sha256"] = digests[n["name"]]
        out.append(entry)
    return out


def listener_identity(site, identity):
    """CT 100's half of agent_identity: the lab root on disk, and the config keys (None removes one)."""
    if not identity:
        return {"agent_client_ca_file": None, "agent_provisioner": None}, {}
    ct("sh", "-c", f"umask 022 && cat > {LISTENER_LAB_ROOT}.next && mv {LISTENER_LAB_ROOT}.next {LISTENER_LAB_ROOT}",
       input=identity["lab_root"].strip() + "\n")
    names = {name: agent_certificate_name(site, name) for name in identity.get("certificate_nodes", [])}
    return {"agent_client_ca_file": LISTENER_LAB_ROOT, "agent_provisioner": identity["provisioner"]}, names


def gateway(*keys):
    """Install gateway-sync.py in CT 101 as the forced command for CT 100's keys.

    The service key, and the node key until it goes (#604): a failed deploy
    puts back an older ssh_config that offers only the node key.
    """
    run("pct", "exec", "101", "--", "install", "-d", "-m", "755", "/usr/local/lib/carrel")
    run("pct", "push", "101", GATEWAY_SYNC, GATEWAY_SYNC, "--perms", "755")
    current = run("pct", "exec", "101", "--", "sh", "-c", "cat /root/.ssh/authorized_keys 2>/dev/null || true")
    kept = [x for x in current.splitlines() if GATEWAY_SYNC not in x]
    lines = [f'from="10.200.0.3",restrict,command="{GATEWAY_SYNC}" {key}' for key in keys]
    run("pct", "exec", "101", "--", "sh", "-c",
        "umask 077 && mkdir -p /root/.ssh && cat > /root/.ssh/authorized_keys.carrel-next"
        " && mv /root/.ssh/authorized_keys.carrel-next /root/.ssh/authorized_keys",
        input="\n".join([*kept, *lines]) + "\n")
    # Keys only: CT 101 holds every tenant's private keys. Restart, not
    # reload: ssh.socket holds port 22, and a reloaded sshd binds it itself.
    run("pct", "exec", "101", "--", "sh", "-c",
        "umask 022 && cat > /etc/ssh/sshd_config.d/carrel.conf && systemctl try-restart ssh.service",
        input="PasswordAuthentication no\nKbdInteractiveAuthentication no\n")
    return " ".join(run("pct", "exec", "101", "--", "cat", "/etc/ssh/ssh_host_ed25519_key.pub").split()[:2])


JUMP_CERT_SSHD_PATH = "/etc/ssh/sshd_config.d/carrel-jump-certs.conf"


def jump_cert_apply(f):
    # sshd -t before the restart, so a bad file never takes the jump host down.
    # A failed staging step leaves the live drop-in alone. Once the new file is
    # in place, a failed check or restart brings back the .prev made in this
    # run (any older one goes first), so `ca` keeps its lab certificates.
    # A failed check leaves the running sshd alone; only a failed restart
    # restarts again, and only after the restore worked and sshd -t passes on
    # the restored file. That restart is a real restart: the failed one may have
    # stopped the unit, and try-restart does nothing to a stopped unit.
    # A failed restore stops here and reports, without calling systemd.
    # Restart, not reload: ssh.socket holds port 22 (PLAN 15.15).
    restore = f"{{ if [ -e {f}.prev ]; then mv {f}.prev {f}; else rm -f {f}; fi; }}"
    return (
        f"umask 022 && rm -f {f}.prev && cat > {f}.next && {{ ! [ -e {f} ] || cp -p {f} {f}.prev; }}"
        f" && mv {f}.next {f} || {{ rm -f {f}.next {f}.prev; exit 1; }}\n"
        f"if ! sshd -t; then {restore} || echo 'rollback failed: {f} is in an unknown state' >&2; exit 1; fi\n"
        f"if systemctl try-restart ssh.service; then rm -f {f}.prev; exit 0; fi\n"
        f"{restore} || {{ echo 'rollback failed: {f} is in an unknown state' >&2; exit 1; }}\n"
        "sshd -t && { systemctl reset-failed ssh.service; systemctl restart ssh.service; }; exit 1\n"
    )


def jump(*keys):
    """Install jump-sync.py in CT 102 as the forced command for CT 100's keys (issue #98), as gateway() does."""
    run("pct", "exec", "102", "--", "install", "-d", "-m", "755", "/usr/local/lib/carrel")
    run("pct", "push", "102", JUMP_SYNC, JUMP_SYNC, "--perms", "755")
    run("pct", "push", "102", JUMP_CERT, JUMP_CERT, "--perms", "755")
    run("pct", "exec", "102", "--", "chown", "root:root", JUMP_SYNC, JUMP_CERT)
    # The certificate user: no keys file, so it takes only lab certificates.
    run("pct", "exec", "102", "--", "sh", "-c",
        "id ca >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent ca")
    run("pct", "exec", "102", "--", "sh", "-c", jump_cert_apply(JUMP_CERT_SSHD_PATH), input=JUMP_CERT_SSHD)
    current = run("pct", "exec", "102", "--", "sh", "-c", "cat /root/.ssh/authorized_keys 2>/dev/null || true")
    kept = [x for x in current.splitlines() if JUMP_SYNC not in x]
    lines = [f'from="10.200.0.3",restrict,command="{JUMP_SYNC}" {key}' for key in keys]
    run("pct", "exec", "102", "--", "sh", "-c",
        "umask 077 && mkdir -p /root/.ssh && cat > /root/.ssh/authorized_keys.carrel-next"
        " && mv /root/.ssh/authorized_keys.carrel-next /root/.ssh/authorized_keys",
        input="\n".join([*kept, *lines]) + "\n")
    return " ".join(run("pct", "exec", "102", "--", "cat", "/etc/ssh/ssh_host_ed25519_key.pub").split()[:2])


# Every node takes SSH keys only (issue #56): no passwords, root by key.
NODE_SSHD = """# Managed by carrel configure-nodes.py (issue #56).
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
"""
NODE_SSHD_PATH = "/etc/ssh/sshd_config.d/10-carrel-keys.conf"
# Lab SSH certificates for root on every node: the site file's "node_ssh_ca"
# names the user CA key and the certificate principals (member names, or
# svc:<portal service>) that may log in. Keys keep working beside them.
NODE_CA_KEY = "/etc/ssh/carrel-user-ca.pub"
NODE_PRINCIPALS = "/etc/ssh/carrel-principals"
CA_KEY = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|rsa-sha2-(256|512)|ssh-rsa) [A-Za-z0-9+/]+={0,2}")
PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}|svc:[a-z0-9][a-z0-9-]{0,62}")


def node_ssh_ca(site):
    """The CA key and root's principals, or None when the site sets none."""
    ca = site.get("node_ssh_ca")
    if not ca:
        return None
    if not isinstance(ca, dict):
        raise SystemExit("node_ssh_ca must be an object with key and principals")
    key = " ".join(str(ca.get("key", "")).split()[:2])
    principals = ca.get("principals")
    if not CA_KEY.fullmatch(key):
        raise SystemExit("node_ssh_ca.key must be one SSH public key")
    if not isinstance(principals, list) or not principals or not all(
            isinstance(p, str) and PRINCIPAL.fullmatch(p) for p in principals):
        raise SystemExit("node_ssh_ca.principals must list member names or svc:<service> names")
    return key, sorted(set(principals))


def node_sshd_apply(site, drop_in=NODE_SSHD_PATH, ca_key=None, principals_dir=None):
    """The drop-in for stdin and the script that applies it with the CA files.

    The script keeps the drop-in, the CA key and the principals directory as
    they were; when a write, sshd -t, the reload or the check after it fails,
    it puts all 3 back and reloads, so a failed run leaves the policy that
    let operators in. Every value is checked above, so quoting is enough."""
    ca_key = ca_key or NODE_CA_KEY
    principals_dir = principals_dir or NODE_PRINCIPALS
    ca = node_ssh_ca(site)
    conf = NODE_SSHD
    check = "sshd -T | grep -qx 'passwordauthentication no'"
    if ca is None:
        write = f"rm -rf {ca_key} {principals_dir}"
    else:
        key, principals = ca
        conf += f"TrustedUserCAKeys {ca_key}\nAuthorizedPrincipalsFile {principals_dir}/%u\n"
        write = (f"printf '%s\\n' {shlex.quote(key)} > {ca_key}"
                 f" && rm -rf {principals_dir} && mkdir -p {principals_dir}"
                 f" && printf '%s\\n' {' '.join(map(shlex.quote, principals))} > {principals_dir}/root")
        # sshd takes the first value of an option, so an earlier drop-in
        # would win: check that this one is in force.
        check += f" && sshd -T | grep -qx 'trustedusercakeys {ca_key}'"
    return conf, f"""umask 022
set -u
D={drop_in} K={ca_key} P={principals_dir}
rm -rf "$D.prev" "$K.prev" "$P.prev" "$D.next"
cat > "$D.next" || exit 1
{{ ! test -e "$D" || cp -p "$D" "$D.prev"; }} && {{ ! test -e "$K" || cp -p "$K" "$K.prev"; }} && {{ ! test -e "$P" || cp -a "$P" "$P.prev"; }} || exit 1
restore() {{
  for f in "$D" "$K" "$P"; do rm -rf "$f"; if test -e "$f.prev"; then mv "$f.prev" "$f"; fi; done
  rm -f "$D.next"
  sshd -t && systemctl reload ssh.service
  exit 1
}}
{{ {write}; }} || restore
mv "$D.next" "$D" || restore
sshd -t || restore
systemctl reload ssh.service || restore
{check} || restore
rm -rf "$D.prev" "$K.prev" "$P.prev"
"""


def node_sshd(n, local, site=None):
    conf, script = node_sshd_apply(site or {})
    if local:
        run("sh", "-c", script, input=conf)
    else:
        run("ssh", *peer(n), "root@" + n["address"], script, input=conf)


# No cross-tenant page merging (issue #397): ksmtuned stays off and masked, KSM stays at 0.
# disable of an absent unit fails and is ignored; mask works on absent and masked units alike.
KSM_OFF = (
    "{ systemctl disable --now ksmtuned.service || true; }"
    " && systemctl mask ksmtuned.service"
    " && { ! test -e /sys/kernel/mm/ksm/run || echo 0 > /sys/kernel/mm/ksm/run; }"
)


def ksm_off(n, local):
    if local:
        run("sh", "-c", KSM_OFF)
    else:
        run("ssh", *peer(n), "root@" + n["address"], KSM_OFF)


def ssh_config(existing, nodes):
    block = [BEGIN]
    for n in nodes:
        block.append(f"Host {n['target']}")
        if n.get("host"):
            block.append(f"  HostName {n['host']}")
        if n.get("identity"):
            # ssh offers the node key of "Host *" first, then this one; once
            # the node key goes (#604), this one is left.
            block.append(f"  IdentityFile {n['identity']}")
    block.append(END)
    if BEGIN in existing and END in existing:
        head, rest = existing.split(BEGIN, 1)
        tail = rest.split(END, 1)[1]
        return head + "\n".join(block) + tail
    # Older files carry a hand-written carrel-node block; the managed block replaces it.
    lines, skip = [], False
    for line in existing.splitlines():
        if line.startswith("Host "):
            skip = line.split()[1] in {n["target"] for n in nodes if n.get("host")}
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
    # A wrong CA setting stops the run before anything changes.
    if node_ssh_ca(site) and not site.get("ssh_keys_only"):
        raise SystemExit("node_ssh_ca needs ssh_keys_only, which writes the node sshd drop-in")
    nodes = targets(site, node)
    me = nodes[0]
    agents = agent_nodes(site, nodes)
    identity = agent_identity(site, nodes, agents)
    if identity:
        # A root openssl cannot read, or one that has expired, would lock out
        # every certificate node.
        run("openssl", "x509", "-noout", "-checkend", "0", input=identity["lab_root"])
    if agents and not Path("/usr/local/lib/carrel/carrel-agent").exists():
        raise SystemExit("install the node programs here first (carrel-agent missing)")
    infra = [GATEWAY, JUMP] if site.get("ssh_jump") else [GATEWAY]
    for program in [*PROGRAMS, "gateway-sync.py", *(["jump-sync.py", "jump-cert.py"] if site.get("ssh_jump") else [])]:
        if not Path("/usr/local/lib/carrel", program).exists():
            raise SystemExit(f"install the node programs here first ({program} missing)")
    # 1. Node programs on the other nodes, the same version as here.
    for n in nodes[1:]:
        run("ssh", *peer(n), "root@" + n["address"], "install -d -m 755 /usr/local/lib/carrel /var/lib/carrel")
        for program in PROGRAMS + (["release.json"] if Path("/usr/local/lib/carrel/release.json").exists() else []):
            run("scp", "-q", *peer(n), f"/usr/local/lib/carrel/{program}", f"root@{n['address']}:/usr/local/lib/carrel/{program}")
        run("ssh", *peer(n), "root@" + n["address"], "chmod 755 /usr/local/lib/carrel/node-agent.py")
    for n in nodes[1:]:
        if n["name"] in agents:
            run("scp", "-q", *peer(n), "/usr/local/lib/carrel/carrel-agent", f"root@{n['address']}:/usr/local/lib/carrel/carrel-agent.carrel-next")
            run("ssh", *peer(n), "root@" + n["address"], "chmod 755 /usr/local/lib/carrel/carrel-agent.carrel-next"
                " && mv /usr/local/lib/carrel/carrel-agent.carrel-next /usr/local/lib/carrel/carrel-agent")
    # 2. One forced-command line in the cluster-wide authorized_keys.
    ct("sh", "-c", 'mkdir -p /etc/carrel && { test -f /etc/carrel/node_key || ssh-keygen -q -t ed25519 -N "" -f /etc/carrel/node_key; }')
    ct("sh", "-c", "id carrel >/dev/null 2>&1 && chown carrel:carrel /etc/carrel/node_key || true; chmod 600 /etc/carrel/node_key")
    key = " ".join(ct("cat", "/etc/carrel/node_key.pub").split()[:2])
    ct("sh", "-c", f'{{ test -f {SERVICE_KEY} || ssh-keygen -q -t ed25519 -N "" -C carrel-service -f {SERVICE_KEY}; }}')
    ct("sh", "-c", f"id carrel >/dev/null 2>&1 && chown carrel:carrel {SERVICE_KEY} || true; chmod 600 {SERVICE_KEY}")
    service = " ".join(ct("cat", SERVICE_KEY + ".pub").split()[:2])
    replace_file(AUTHORIZED, merge_authorized(AUTHORIZED.read_text() if AUTHORIZED.exists() else "", authorized_line(key, me["address"]), key), 0o600)
    # The service key goes into ssh_config before CT 101 and CT 102 take it.
    current = ct("sh", "-c", "cat /etc/carrel/ssh_config 2>/dev/null || true")
    ct("sh", "-c", "umask 022 && cat > /etc/carrel/ssh_config.next && chmod 644 /etc/carrel/ssh_config.next && mv /etc/carrel/ssh_config.next /etc/carrel/ssh_config", input=ssh_config(current, [*nodes, *infra, BACKUP]))
    # 3. The gateway's forced command in CT 101.
    gateway_key = gateway(service, key)
    jump_key = jump(service, key) if site.get("ssh_jump") else None
    # 4. CT 100: targets, pinned host keys, the node list.
    entries = []
    for n in nodes:
        if n is me:
            host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text()
        else:
            host_key = run("ssh", *peer(n), "root@" + n["address"], "cat /etc/ssh/ssh_host_ed25519_key.pub")
        entries.append((n["host"], " ".join(host_key.split()[:2])))
    entries.append((GATEWAY["host"], gateway_key))
    if jump_key:
        entries.append((JUMP["host"], jump_key))
    current = ct("sh", "-c", "cat /etc/carrel/known_hosts 2>/dev/null || true")
    ct("sh", "-c", "umask 022 && cat > /etc/carrel/known_hosts.next && chmod 644 /etc/carrel/known_hosts.next && mv /etc/carrel/known_hosts.next /etc/carrel/known_hosts", input=known_hosts(current, entries))
    # The agent listener's keys are in config.json only while a node uses it.
    listener = agent_listener() if agents else {k: None for k in ("agent_listen", "agent_cert_file", "agent_key_file")}
    client, certificates = listener_identity(site, agent_identity(site, nodes, agents) if agents else None)
    listed = json.dumps({"nodes": node_entries(nodes, agents, agent_digests(nodes, agents), certificates), **listener, **client})
    # Edited in place inside CT 100 so no other key leaves it.
    ct("python3", "-c", (
        "import json,os,sys;from pathlib import Path;p=Path('/etc/carrel/config.json');"
        "c=json.loads(p.read_text()) if p.exists() else {};u=json.loads(sys.stdin.read());"
        "[c.pop(k,None) if v is None else c.__setitem__(k,v) for k,v in u.items()];"
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
    if jump_key:
        status = json.loads(ct("ssh", "-F", "/etc/carrel/ssh_config", JUMP["target"], input='{"op":"status"}'))
        if not status.get("ok"):
            raise SystemExit("the jump host did not answer through carrel-jump")
    # 6. ksmtuned off on every node; a second run changes nothing.
    for n in nodes:
        ksm_off(n, n is me)
    # 7. Keys only on every node, last: everything above already answered by
    # key. The site turns it on once nobody logs in to a node by password.
    if site.get("ssh_keys_only"):
        for n in nodes:
            node_sshd(n, n is me, site)
        for n in nodes:
            # A new login by key still works after the reload, here too.
            run("ssh", *peer(n), "root@" + n["address"], "true")
    print(json.dumps({"nodes": report, "gateway": GATEWAY["target"], "agent_nodes": sorted(agents),
                      **({"jump": JUMP["target"]} if jump_key else {})}))


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["--agent-service"]:
        print(json.dumps({"agent": agent_service(), "peers": agent_peers()}))
    elif sys.argv[1:2] == ["--agent-check"] and len(sys.argv) == 3:
        missing = peers_connected(int(sys.argv[2]))
        print(json.dumps({"not_connected": missing}))
        sys.exit(1 if missing else 0)
    else:
        main()
