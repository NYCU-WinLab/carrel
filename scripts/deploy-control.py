#!/usr/bin/env python3
"""Local deployment driver; secrets travel on SSH stdin/protected files, never argv."""

import json
import os
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, data=None, capture=False):
    p = subprocess.run(args, input=data, text=True, capture_output=capture, check=True)
    return p.stdout if capture else None


def ssh(host, cmd, data=None, capture=False):
    return run(["ssh", "-o", "ControlPath=none", host, cmd], data, capture)


def push_ct(host, vmid, dest, content, mode=0o644):
    # The caller controls destination, never a member's input.
    program = (
        """import sys,subprocess,pathlib
p=pathlib.Path('/var/lib/carrel-transfer')
p.write_bytes(sys.stdin.buffer.read());p.chmod(0o600)
subprocess.run(['pct','push',VMID,str(p),DEST,'--perms',MODE],check=True)
p.unlink()
""".replace("VMID", repr(str(vmid)))
        .replace("DEST", repr(dest))
        .replace("MODE", repr(f"{mode:o}"))
    )
    # Feed the payload separately through stdin; code is fixed administrator text.
    import shlex

    ssh(host, "python3 -c " + shlex.quote(program), content)


def main():
    (ROOT / ".runtime").mkdir(exist_ok=True, mode=0o700)
    run(
        [
            "uv",
            "export",
            "--locked",
            "--no-dev",
            "--no-emit-project",
            "--output-file",
            ".runtime/requirements.txt",
        ],
        capture=True,
    )

    def source_only(member):
        # Native macOS tar otherwise adds AppleDouble resource-fork files,
        # which can then leak into the built wheel as extra Python files.
        if any(p.startswith(".") or p == "__pycache__" for p in Path(member.name).parts):
            return None
        return member

    with tarfile.open(ROOT / ".runtime/control.tar.gz", "w:gz") as archive:
        for name in ("pyproject.toml", "uv.lock", "src"):
            archive.add(ROOT / name, arcname=name, filter=source_only)
        archive.add(ROOT / ".runtime/requirements.txt", arcname="requirements.txt")
    run(["scp", str(ROOT / ".runtime/control.tar.gz"), "carrel01:/var/lib/carrel/control.tar.gz"])
    ssh(
        "carrel01",
        "pct push 100 /var/lib/carrel/control.tar.gz /tmp/control.tar.gz && pct exec 100 -- sh -ec 'mkdir -p /opt/carrel /etc/carrel /var/lib/carrel; rm -rf /opt/carrel/src; tar -xzf /tmp/control.tar.gz -C /opt/carrel; id carrel >/dev/null 2>&1 || useradd --system --home /var/lib/carrel --shell /usr/sbin/nologin carrel; chown carrel:carrel /var/lib/carrel; python3 -m venv /opt/carrel/venv; /opt/carrel/venv/bin/pip install --disable-pip-version-check --require-hashes -r /opt/carrel/requirements.txt; /opt/carrel/venv/bin/pip install --disable-pip-version-check --no-deps /opt/carrel'",
        capture=True,
    )
    ssh(
        "carrel01",
        "pct exec 100 -- sh -c 'test -f /etc/carrel/node_key || ssh-keygen -q -t ed25519 -N \"\" -f /etc/carrel/node_key; chown carrel:carrel /etc/carrel/node_key; chmod 600 /etc/carrel/node_key'",
    )
    key = ssh("carrel01", "pct exec 100 -- cat /etc/carrel/node_key.pub", capture=True).strip()
    node_key = ssh("carrel01", "cat /etc/ssh/ssh_host_ed25519_key.pub", capture=True).split()
    edge_key = ssh("pve", "cat /etc/ssh/ssh_host_ed25519_key.pub", capture=True).split()
    known = (
        "10.200.0.1 " + " ".join(node_key[:2]) + "\n[140.113.194.229]:1121 " + " ".join(edge_key[:2]) + "\n"
    )
    push_ct("carrel01", 100, "/etc/carrel/known_hosts", known)
    push_ct(
        "carrel01",
        100,
        "/etc/carrel/ssh_config",
        """Host *
  User root
  IdentityFile /etc/carrel/node_key
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking yes
  UserKnownHostsFile /etc/carrel/known_hosts
  ConnectTimeout 10
Host carrel-node
  HostName 10.200.0.1
Host carrel-edge
  HostName 140.113.194.229
  Port 1121
""",
    )
    import shlex

    for host, adapter, prefix in [("carrel01", "node", 'from="10.200.0.3",'), ("pve", "edge", "")]:
        run(
            [
                "scp",
                str(ROOT / f"scripts/{adapter}-agent.py"),
                host + ":/root/carrel-" + adapter + "-agent.py",
            ]
        )
        ssh(
            host,
            f"install -D -m 755 /root/carrel-{adapter}-agent.py /usr/local/lib/carrel/{adapter}-agent.py",
        )
        line = prefix + f'restrict,command="/usr/local/lib/carrel/{adapter}-agent.py" ' + key + "\n"
        program = "from pathlib import Path; import sys; p=Path('/root/.ssh/authorized_keys'); s=p.read_text(); line=sys.stdin.read(); p.write_text(s if line.strip() in s else s+'\\n'+line)"
        ssh(host, "python3 -c " + shlex.quote(program), line)
    for helper in ("guest-report.py", "thin-usage.py"):
        run(["scp", str(ROOT / "scripts" / helper), "carrel01:/usr/local/lib/carrel/" + helper])
    # Read the pre-existing gateway token without emitting its value.
    env = ssh("pve", "pct exec 200 -- cat /home/user/gateway/.env", capture=True)
    token = next(
        line.split("=", 1)[1].strip().strip('"').strip("'")
        for line in env.splitlines()
        if line.startswith("CF_API_TOKEN=")
    )
    import urllib.request

    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/zones?name=winlab.tw",
        headers={"Authorization": "Bearer " + token},
    )
    zones = json.load(urllib.request.urlopen(req))["result"]
    assert len(zones) == 1
    config = {
        "origin": "https://carrel.winlab.tw",
        "issuer": "https://auth.winlab.tw/realms/winlab",
        "database": "/var/lib/carrel/carrel.db",
        "cloudflare_token": token,
        "cloudflare_zone": zones[0]["id"],
        "hosted_redirects": ["https://chatgpt.com/connector_platform/oauth/callback"],
    }
    push_ct("carrel01", 100, "/etc/carrel/config.json", json.dumps(config), 0o640)
    ssh("carrel01", "pct exec 100 -- chown root:carrel /etc/carrel/config.json")
    push_ct(
        "carrel01",
        100,
        "/etc/systemd/system/carrel.service",
        """[Unit]
Description=Carrel MCP control plane
After=network-online.target
Wants=network-online.target
[Service]
User=carrel
Group=carrel
WorkingDirectory=/opt/carrel
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/carrel/venv/bin/python -m carrel.server
KillMode=mixed
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/carrel
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
""",
    )
    ssh(
        "carrel01",
        "pct exec 100 -- systemctl daemon-reload && pct exec 100 -- systemctl enable carrel && pct exec 100 -- systemctl restart carrel",
    )
    # A simple external proxy; no Keycloak or Cloudflare secrets on CT 207.
    edge_ready = ssh("pve", "test ! -f /var/lib/carrel-edge/desired.json || echo ready", capture=True).strip()
    if not edge_ready:
        push_ct(
            "pve",
            207,
            "/etc/caddy/Caddyfile",
            """{
 admin localhost:2019
 auto_https off
}
:80 {
 @carrel host carrel.winlab.tw
 handle @carrel {
  reverse_proxy 10.200.0.3:8080 {
   flush_interval -1
   stream_close_delay 5m
  }
 }
 handle {
  respond 404
 }
}
""",
        )
    ssh(
        "pve",
        "pct exec 207 -- /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile && pct exec 207 -- systemctl reload caddy",
    )
    node_ready = ssh("carrel01", "test ! -f /var/lib/carrel/desired.json || echo ready", capture=True).strip()
    if not node_ready:
        push_ct("carrel01", 101, "/etc/caddy/Caddyfile", "{\n auto_https off\n}\n:80 {\n respond 404\n}\n")
    push_ct(
        "carrel01",
        101,
        "/etc/carrel-dns.conf",
        """port=53
listen-address=10.200.0.2
bind-dynamic
no-resolv
server=1.1.1.1
server=1.0.0.1
domain-needed
bogus-priv
local=/internal/
addn-hosts=/etc/carrel-hosts
""",
    )
    ssh("carrel01", "pct exec 101 -- touch /etc/carrel-hosts")
    push_ct(
        "carrel01",
        101,
        "/etc/systemd/system/carrel-dns.service",
        """[Unit]
Description=Carrel internal resolver
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
[Service]
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/carrel-dns.conf
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
""",
    )
    ssh(
        "carrel01",
        "pct exec 101 -- systemctl daemon-reload && pct exec 101 -- systemctl enable --now carrel-dns && pct exec 101 -- systemctl reload caddy",
    )
    push_ct(
        "carrel01",
        100,
        "/etc/systemd/system/carrel-backup.service",
        """[Unit]
Description=Consistent Carrel database and configuration backup
After=network-online.target
[Service]
Type=oneshot
User=carrel
Group=carrel
UMask=0077
ExecStart=/opt/carrel/venv/bin/python -m carrel.backup
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/carrel
""",
    )
    push_ct(
        "carrel01",
        100,
        "/etc/systemd/system/carrel-backup.timer",
        """[Unit]
Description=Daily independent-host Carrel control backup
[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
""",
    )
    ssh(
        "carrel01",
        "pct exec 100 -- systemctl daemon-reload && pct exec 100 -- systemctl enable --now carrel-backup.timer",
    )
    print("Control plane and external proxy deployed; no secrets printed.")


if __name__ == "__main__":
    os.chdir(ROOT)
    main()
