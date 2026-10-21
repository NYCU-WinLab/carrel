#!/usr/bin/env python3
"""Install or upgrade the control plane from a staged release, as root.

deploy-go.py copies a release to a stage directory on the first exit node and runs
`install-control.py host --stage DIR --version V` there. The host part installs the
node programs, then copies this script into CT 100 and runs its `ct` commands
there. A first install needs only /etc/carrel/config.json written in CT 100
(sites/<site>/config.example.json lists the keys); every later run keeps the
database, configuration, OAuth state and certificates.

A failed health check restores the previous binary, units and node programs. Older
databases are never restored here: that is a disaster-recovery decision.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

CT = "100"
LIB = Path("/usr/local/lib/carrel")
# On the node.
NODE_JSON = Path("/etc/carrel/node.json")
TEMPLATES = Path("/etc/carrel/templates.json")
HELPERS = {"guest-report.py": "644", "gateway-sync.py": "644", "jump-sync.py": "644"}
TERMINAL = ("succeeded", "failed", "rolled_back", "cleanup_failed")
KEEP = 5
DATABASE = Path("/var/lib/carrel/carrel.db")
# Inside CT 100.
ETC = Path("/etc/carrel")
UNIT_DIR = Path("/etc/systemd/system")
BINARY = Path("/usr/local/bin/carrel")
UNITS = {
    "carrel.service": """[Unit]
Description=Carrel MCP control plane
After=network-online.target
Wants=network-online.target
[Service]
User=carrel
Group=carrel
WorkingDirectory=/var/lib/carrel
ExecStart=/usr/local/bin/carrel
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
    "carrel-backup.service": """[Unit]
Description=Consistent Carrel database and configuration backup
After=network-online.target
[Service]
Type=oneshot
User=carrel
Group=carrel
UMask=0077
ExecStart=/usr/local/bin/carrel -backup
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/carrel
""",
    "carrel-backup.timer": """[Unit]
Description=Daily off-site Carrel control backup
[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
""",
}
# What a failed upgrade puts back in CT 100, from the archive taken before it.
CONFIGURED = ["etc/carrel/config.json", "etc/carrel/ssh_config", "etc/carrel/known_hosts"]
ACTIVATED = [*(f"etc/systemd/system/{name}" for name in UNITS), "usr/local/bin/carrel"]


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, text=True, **kwargs)


def capture(*args):
    return run(*args, capture_output=True).stdout


# --- inside CT 100 ---------------------------------------------------------


def ct_setup():
    """Create the service account and directories a first install needs."""
    if not Path("/etc/carrel/config.json").exists():
        raise SystemExit("Write /etc/carrel/config.json in CT 100 first (see sites/<site>/config.example.json)")
    if subprocess.run(["id", "carrel"], capture_output=True, check=False).returncode:
        run("useradd", "--system", "--home-dir", "/var/lib/carrel", "--shell", "/usr/sbin/nologin", "carrel")
    run("install", "-d", "-o", "carrel", "-g", "carrel", "-m", "700", "/var/lib/carrel")
    run("install", "-d", "-m", "755", "/etc/carrel", "/usr/local/lib/carrel")
    run("install", "-d", "-m", "700", "/opt/carrel/rollback")
    run("chown", "root:carrel", "/etc/carrel/config.json")
    os.chmod("/etc/carrel/config.json", 0o640)


def ct_preflight():
    import sqlite3

    if not DATABASE.exists():
        print(json.dumps({"active_operations": 0, "first_install": True}))
        return
    db = sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)
    rows = db.execute("SELECT data FROM objects WHERE kind='operations'").fetchall()
    active = [json.loads(v)["id"] for (v,) in rows if json.loads(v)["state"] not in TERMINAL]
    if active:
        raise SystemExit("Active operations; retry deployment after completion")
    clients = db.execute("SELECT count(*) FROM oauth WHERE kind='client'").fetchone()[0]
    print(json.dumps({"active_operations": 0, "oauth_clients": clients}))


def ct_backup(stamp):
    import sqlite3

    root = Path("/opt/carrel/rollback")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    archive_path = root / f"go-{stamp}.tar.gz"
    copy = root / f"go-{stamp}.db"
    with tarfile.open(archive_path, "w:gz") as archive:
        for name in ["/etc/carrel", *(f"/etc/systemd/system/{u}" for u in UNITS), "/var/lib/carrel/certificates",
                     "/usr/local/bin/carrel"]:
            if Path(name).exists():
                archive.add(name, arcname=name.lstrip("/"))
        if DATABASE.exists():
            source, target = sqlite3.connect(DATABASE), sqlite3.connect(copy)
            source.backup(target)
            target.close()
            source.close()
            archive.add(copy, arcname="var/lib/carrel/carrel.db")
            copy.unlink()
    os.chmod(archive_path, 0o600)
    # This archive and the 4 newest others stay; the nightly off-site backup
    # keeps the history.
    for old in sorted(p for p in root.glob("go-*.tar.gz") if p != archive_path)[: -(KEEP - 1)]:
        old.unlink()
    print(json.dumps({"control_backup": str(archive_path)}))


def ct_activate():
    """Write the units, switch the binary and record the installed templates."""
    for name, text in UNITS.items():
        (UNIT_DIR / name).write_text(text)
    os.replace(str(BINARY) + ".next", BINARY)
    manifest = ETC / "templates.next.json"
    path = ETC / "config.json"
    config = json.loads(path.read_text())
    environment = config.setdefault("vm_environment", {})
    keys = ("environment", "packages", "built_at", "node_archive", "node_sha256", "sha256")
    for image, entry in json.loads(manifest.read_text()).items():
        environment[image] = {k: entry[k] for k in keys if k in entry}
    pending = path.with_name("config.json.next")
    pending.unlink(missing_ok=True)
    # Created 0600: the configuration holds secrets.
    with os.fdopen(os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(json.dumps(config, indent=2) + "\n")
    stat = path.stat()
    os.chown(pending, stat.st_uid, stat.st_gid)
    os.chmod(pending, stat.st_mode & 0o777)
    os.replace(pending, path)
    manifest.unlink()


def ct_restore(stamp, names):
    with tarfile.open(f"/opt/carrel/rollback/go-{stamp}.tar.gz") as archive:
        present = set(archive.getnames())
        for name in names:
            if name in present:
                archive.extract(name, "/", filter="data")
    Path("/etc/carrel/templates.next.json").unlink(missing_ok=True)


# --- on the first exit node -----------------------------------------------


def ct(*args):
    run("pct", "exec", CT, "--", *args)


def ct_command(*args):
    ct("python3", "/usr/local/lib/carrel/install-control.py", "ct", *args)


def push(source, target, mode):
    run("pct", "push", CT, source, target, "--perms", mode)


def templates_for(stage, node, storage):
    """Merge a staged templates.json into the node's map and check every template."""
    templates = json.loads(TEMPLATES.read_text()) if TEMPLATES.exists() else {}
    if (stage / "templates.json").exists():
        templates.update(json.loads((stage / "templates.json").read_text()))
    minimal = templates.get("debian-13-minimal", {})
    if minimal.get("prepared") is not True or minimal.get("environment") != "minimal":
        raise SystemExit("Install the prepared Debian minimal template before deploying")
    for entry in templates.values():
        vmid = entry["vmid"]
        if not isinstance(vmid, int) or not 9000 <= vmid <= 9999:
            raise SystemExit("Invalid template VMID")
        cfg = json.loads(capture("pvesh", "get", f"/nodes/{node}/qemu/{vmid}/config", "--output-format", "json"))
        if cfg.get("template") != 1 or not cfg.get("scsi0", "").startswith(storage + ":base-"):
            raise SystemExit(f"Template {vmid} is not an immutable template on {storage} of this node")
    return templates


def origin_host():
    # Only the origin leaves CT 100; the configuration also holds secrets.
    code = "import json,urllib.parse;print(urllib.parse.urlsplit(json.load(open('/etc/carrel/config.json'))['origin']).hostname)"
    return capture("pct", "exec", CT, "--", "python3", "-c", code).strip()


def healthy(version, host_name):
    for _ in range(30):
        try:
            request = urllib.request.Request("http://10.200.0.3:8080/healthz", headers={"Host": host_name})
            health = json.load(urllib.request.urlopen(request, timeout=2))
            if health.get("version") == version:
                return health
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise SystemExit("Health check failed: the new version did not answer")


def host(stage, version):
    stamp = stage.name.removeprefix("go-upgrade-")
    for name, expected in json.loads((stage / "hashes.json").read_text()).items():
        if hashlib.sha256((stage / name).read_bytes()).hexdigest() != expected:
            raise SystemExit("Transfer checksum mismatch: " + name)
    # The binary itself names its version (issue #56): a checkout and a build
    # that disagree stop here, before anything changes.
    built = json.loads(capture(stage / "carrel", "-version"))["version"]
    if built != version:
        raise SystemExit(f"The binary is version {built}, the checkout {version}")
    node = socket.gethostname().split(".")[0]
    storage = json.loads(NODE_JSON.read_text())["storage"]
    templates = templates_for(stage, node, storage)
    run("python3", stage / "configure-reader.py")
    run("install", "-d", "-m", "755", LIB)
    ct("install", "-d", "-m", "755", "/usr/local/lib/carrel")
    push(stage / "install-control.py", "/usr/local/lib/carrel/install-control.py", "755")
    ct_command("setup")
    host_name = origin_host()
    ct_command("preflight")
    # A first install has no units yet; stopping them is then a no-op.
    for unit in ("carrel-backup.timer", "carrel-backup.service", "carrel"):
        subprocess.run(["pct", "exec", CT, "--", "systemctl", "stop", unit], capture_output=True, check=False)
    before = {"node-agent.py": LIB / "node-agent.py", "templates.json": TEMPLATES,
              **{h: LIB / h for h in HELPERS}}
    configured = activated = False
    try:
        ct_command("preflight")
        ct_command("backup", stamp)
        for name, path in before.items():
            if path.exists():
                shutil.copy2(path, stage / ("before-" + name))
        merged = stage / "templates.merged.json"
        merged.write_text(json.dumps(templates, indent=2) + "\n")
        run("install", "-m", "600", merged, TEMPLATES)
        push(merged, "/etc/carrel/templates.next.json", "600")
        for name, mode in {**HELPERS, "node-agent.py": "755"}.items():
            run("install", "-m", mode, stage / name, str(LIB / name) + ".next")
            os.replace(str(LIB / name) + ".next", LIB / name)
        # Same programs on every site node; CT 100 must reach each adapter.
        configured = True
        run("python3", stage / "configure-nodes.py")
        push(stage / "carrel", "/usr/local/bin/carrel.next", "755")
        # Served to tenant machines at /apps/v1/carrel-deployd (PLAN 7.9).
        push(stage / "carrel-deployd", "/usr/local/lib/carrel/carrel-deployd", "755")
        # The fetch container's downloader (PLAN 7.8), when the site has one.
        if Path("/etc/pve/lxc/103.conf").exists():
            # Beside the running binary, then renamed: a download in progress keeps its copy.
            run("pct", "push", "103", stage / "carrel-fetch", "/usr/local/bin/carrel-fetch.next", "--perms", "755")
            run("pct", "exec", "103", "--", "mv", "/usr/local/bin/carrel-fetch.next", "/usr/local/bin/carrel-fetch")
        activated = True
        ct_command("activate")
        ct("systemctl", "daemon-reload")
        ct("systemctl", "enable", "--now", "carrel")
        health = healthy(version, host_name)
        ct("systemctl", "is-active", "carrel")
        print(json.dumps({"health": health, "node_backup": str(stage),
                          "control_backup": f"/opt/carrel/rollback/go-{stamp}.tar.gz"}))
    except BaseException:
        # Every step runs even if one fails: the service must come back.
        subprocess.run(["pct", "exec", CT, "--", "systemctl", "stop", "carrel"], check=False)
        if configured or activated:
            names = json.dumps(CONFIGURED + (ACTIVATED if activated else []))
            subprocess.run(["pct", "exec", CT, "--", "python3", "/usr/local/lib/carrel/install-control.py", "ct",
                            "restore", stamp, names], check=False)
        for name, path in before.items():
            saved = stage / ("before-" + name)
            if saved.exists():
                shutil.copy2(saved, path)
        subprocess.run(["pct", "exec", CT, "--", "systemctl", "daemon-reload"], check=False)
        subprocess.run(["pct", "exec", CT, "--", "systemctl", "start", "carrel"], check=False)
        raise
    finally:
        # Absent only when a first install failed before its units existed.
        subprocess.run(["pct", "exec", CT, "--", "systemctl", "enable", "--now", "carrel-backup.timer"], check=False)
    for old in sorted(p for p in stage.parent.glob("go-upgrade-*") if p != stage)[: -(KEEP - 1)]:
        shutil.rmtree(old)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="where", required=True)
    h = sub.add_parser("host")
    h.add_argument("--stage", type=Path, required=True)
    h.add_argument("--version", required=True)
    c = sub.add_parser("ct")
    c.add_argument("command", choices=["setup", "preflight", "backup", "activate", "restore"])
    c.add_argument("args", nargs="*")
    a = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run as root")
    if a.where == "host":
        host(a.stage, a.version)
    elif a.command == "backup":
        ct_backup(a.args[0])
    elif a.command == "restore":
        ct_restore(a.args[0], json.loads(a.args[1]))
    else:
        {"setup": ct_setup, "preflight": ct_preflight, "activate": ct_activate}[a.command]()


if __name__ == "__main__":
    sys.exit(main())
