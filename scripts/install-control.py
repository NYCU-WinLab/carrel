#!/usr/bin/env python3
"""Install or upgrade the control plane from a staged release, as root.

deploy-go.py copies a release to a stage directory on the first exit node and runs
`install-control.py host --stage DIR --version V` there. The host part installs the
node programs, then copies this script into CT 100 and runs its `ct` commands
there. A first install needs only /etc/carrel/config.json written in CT 100
(sites/<site>/config.example.json lists the keys); every later run keeps the
database, configuration, OAuth state and certificates.

A failed health check restores the previous binary, units and node programs, never the
database. `install-control.py rollback` does the same on request for the last deploy,
and with --database also restores the copy made before the schema migration (#768).
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
SITE = Path("/etc/carrel/site.json")
# jump-sync.py's generation records in CT 102 (issue #388).
JUMP_GENS = ["/var/lib/carrel-jump/keys.gen", "/var/lib/carrel-jump/certs.gen"]
TEMPLATES = Path("/etc/carrel/templates.json")
HELPERS = {"guest-report.py": "644", "gateway-sync.py": "644", "jump-sync.py": "644", "jump-cert.py": "644"}
# Node programs that run: node-agent.py behind SSH, carrel-agent on a node whose
# transport is agent (PLAN 8.6; configure-nodes.py starts it).
EXECUTABLES = {"node-agent.py": "755", "carrel-agent": "755"}
# configure-nodes.py makes it once; a run that rotates it and then fails puts
# the old one back with the old digest in config.json.
AGENT_TOKEN = Path("/etc/carrel/agent-token")
TERMINAL = ("succeeded", "failed", "rolled_back", "cleanup_failed")
KEEP = 5
DATABASE = Path("/var/lib/carrel/carrel.db")
ROLLBACK = Path("/opt/carrel/rollback")
# On the node: where deploy-go.py stages a release.
DEPLOYS = Path("/var/lib/carrel")
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
CONFIGURED = ["etc/carrel/config.json", "etc/carrel/ssh_config", "etc/carrel/known_hosts", "etc/carrel/agent/lab-root.pem"]
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
    with tarfile.open(ROLLBACK / f"go-{stamp}.tar.gz") as archive:
        present = set(archive.getnames())
        for name in names:
            if name in present:
                archive.extract(name, "/", filter="data")
    Path("/etc/carrel/templates.next.json").unlink(missing_ok=True)


def archived_version(stamp):
    """PRAGMA user_version of the database inside a deploy's archive: what the release before it reads."""
    import sqlite3
    import tempfile

    with tarfile.open(ROLLBACK / f"go-{stamp}.tar.gz") as archive:
        try:
            member = archive.getmember("var/lib/carrel/carrel.db")
        except KeyError:
            return None
        with tempfile.TemporaryDirectory(dir=ROLLBACK) as work:
            target = Path(work) / "carrel.db"
            with archive.extractfile(member) as source, open(target, "wb") as out:
                shutil.copyfileobj(source, out)
            db = sqlite3.connect(target)
            try:
                return db.execute("PRAGMA user_version").fetchone()[0]
            finally:
                db.close()


def schema_copy(version):
    """The newest copy carrel made before it migrated from this schema version."""
    copies = sorted(DATABASE.parent.glob(f"{DATABASE.name}.schema-{version}-*"))
    return copies[-1] if copies else None


def ct_schema(stamp):
    """Print the current schema, the one the previous release reads and the copy that could restore it."""
    import sqlite3

    current = None
    if DATABASE.exists():
        db = sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)
        current = db.execute("PRAGMA user_version").fetchone()[0]
        db.close()
    previous = archived_version(stamp)
    copy = schema_copy(previous) if previous is not None else None
    print(json.dumps({"current": current, "previous": previous, "copy": str(copy) if copy else None,
                      "copy_time": copy.stat().st_mtime if copy else None,
                      "copy_intact": intact(copy, previous) if copy else False}))


def intact(copy, version):
    """True when the copy passes SQLite's integrity check and is at this schema version."""
    import sqlite3

    check = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
    try:
        problems = check.execute("PRAGMA integrity_check").fetchall()
        found = check.execute("PRAGMA user_version").fetchone()[0]
    except sqlite3.DatabaseError:
        return False
    finally:
        check.close()
    return problems == [("ok",)] and found == version


def ct_restore_database(version):
    """Put the pre-migration copy in place of the database. carrel must be stopped."""
    copy = schema_copy(int(version))
    if copy is None:
        raise SystemExit(f"No {DATABASE}.schema-{version}-* copy to restore")
    if not intact(copy, int(version)):
        raise SystemExit(f"{copy} is not an intact schema {version} database")
    # Beside the database, then renamed. The copy stays: it is the way back.
    # Created 0600 and never through a link: the directory belongs to carrel.
    pending = DATABASE.with_name(DATABASE.name + ".restore")
    pending.unlink(missing_ok=True)
    stat = DATABASE.parent.stat()
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out, open(copy, "rb") as source:
        shutil.copyfileobj(source, out)
        os.fchown(out.fileno(), stat.st_uid, stat.st_gid)
    for suffix in ("-wal", "-shm"):
        Path(str(DATABASE) + suffix).unlink(missing_ok=True)
    os.replace(pending, DATABASE)
    print(json.dumps({"database_restored": str(copy)}))


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


def jump_site():
    try:
        return bool(json.loads(SITE.read_text()).get("ssh_jump"))
    except (OSError, ValueError):
        # Unknown: clearing records that may not exist costs nothing.
        return True


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


def agent_connected(since, wait=60):
    """True once the agent logs a claim the control plane took, after since."""
    for _ in range(wait):
        log = subprocess.run(["journalctl", "-u", "carrel-agent", "--since", f"@{since}", "-o", "cat"],
                             capture_output=True, text=True, check=False)
        if '"agent_connected"' in (log.stdout or ""):
            return True
        time.sleep(1)
    return False


def saved_paths():
    """The node files a deploy saves as stage/before-<name> and a rollback puts back."""
    return {"templates.json": TEMPLATES, "release.json": LIB / "release.json", "agent-token": AGENT_TOKEN,
            **{h: LIB / h for h in [*HELPERS, *EXECUTABLES]}}


def undo(stage, stamp, before, had_release, configured, activated, database=None):
    """Put the previous release back: units, binary, configuration and node programs.

    database is a schema version whose pre-migration copy replaces the database while
    carrel is stopped. Every step runs even if one fails: the service must come back."""
    # Every step runs even if one fails: the service must come back.
    subprocess.run(["pct", "exec", CT, "--", "systemctl", "stop", "carrel"], check=False)
    if configured or activated:
        names = json.dumps(CONFIGURED + (ACTIVATED if activated else []))
        subprocess.run(["pct", "exec", CT, "--", "python3", "/usr/local/lib/carrel/install-control.py", "ct",
                        "restore", stamp, names], check=False)
    for name, path in before.items():
        saved = stage / ("before-" + name)
        try:
            if saved.exists():
                # Beside the target, then renamed: a running carrel-agent
                # keeps its file busy (ETXTBSY) against a copy in place.
                # Created 0600, so the token is never readable on the way.
                pending = Path(str(path) + ".restore")
                pending.unlink(missing_ok=True)
                with os.fdopen(os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
                    stream.write(saved.read_bytes())
                shutil.copystat(saved, pending)
                os.replace(pending, path)
            elif name == "release.json" and not had_release and path.exists():
                # An install before #555 had no release record: none is truer than the new one.
                path.unlink()
        except OSError as error:
            print(f"WARNING: could not restore {path}: {error}", file=sys.stderr)
    # The restored binary may send no "gen", which jump-sync.py refuses once a
    # generation is recorded; carrel is stopped, so no write races this.
    if (configured or activated) and jump_site():
        cleared = subprocess.run(["pct", "exec", "102", "--", "rm", "-f", *JUMP_GENS], check=False)
        if cleared.returncode:
            print("WARNING: could not remove the jump generations; until they are removed, jump sync and "
                  "certs writes (including revokes) are refused if the restored carrel predates gen. "
                  "Run in CT 102: rm -f " + " ".join(JUMP_GENS), file=sys.stderr)
    subprocess.run(["pct", "exec", CT, "--", "systemctl", "daemon-reload"], check=False)
    try:
        if database is not None:
            # No backup may read the database while it is swapped, and carrel must be down.
            for unit in ("carrel-backup.timer", "carrel-backup.service"):
                subprocess.run(["pct", "exec", CT, "--", "systemctl", "stop", unit], check=False)
            if subprocess.run(["pct", "exec", CT, "--", "systemctl", "is-active", "--quiet", "carrel"],
                              check=False).returncode == 0:
                raise SystemExit("carrel did not stop: the database was not restored")
            ct_command("restore-database", str(database))
    finally:
        subprocess.run(["pct", "exec", CT, "--", "systemctl", "start", "carrel"], check=False)


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
    before = saved_paths()
    # Read before anything can fail: only a record this run created may be removed.
    had_release = (LIB / "release.json").exists()
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
        for name, mode in {**HELPERS, **EXECUTABLES}.items():
            run("install", "-m", mode, stage / name, str(LIB / name) + ".next")
            os.replace(str(LIB / name) + ".next", LIB / name)
        # The release the node programs came from, which node-agent reports in
        # its inventory so node_list shows a node left on another version (#555).
        release = stage / "release.json"
        release.write_text(json.dumps({"version": version, "sha256": json.loads((stage / "hashes.json").read_text())}) + "\n")
        run("install", "-m", "644", release, LIB / "release.json")
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
        undo(stage, stamp, before, had_release, configured, activated)
        raise
    finally:
        # Absent only when a first install failed before its units existed.
        subprocess.run(["pct", "exec", CT, "--", "systemctl", "enable", "--now", "carrel-backup.timer"], check=False)
    # The node's agent starts or stops only now, against a healthy control
    # plane: a failed upgrade above never touched it.
    agents(stage)
    for old in sorted(p for p in stage.parent.glob("go-upgrade-*") if p != stage)[: -(KEEP - 1)]:
        shutil.rmtree(old)


def agents(stage):
    """Start or stop carrel-agent on every agent node and check each one reaches the control plane."""
    since = int(time.time())
    agent = subprocess.run(["python3", str(stage / "configure-nodes.py"), "--agent-service"], check=False,
                           capture_output=True, text=True)
    try:
        report = json.loads(agent.stdout or "{}")
    except ValueError:
        report = {}
    if agent.returncode and "agent" not in report:
        raise SystemExit("carrel-agent was not started or stopped "
                         f"({(agent.stderr or '').strip()[-400:]}); run "
                         f"python3 {stage}/configure-nodes.py --agent-service on this node")
    if '"started"' in (agent.stdout or "") and not agent_connected(since):
        # The control plane is up, but this node's jobs wait for its agent.
        raise SystemExit("carrel-agent did not reach the control plane within 60 s: see journalctl -u "
                         "carrel-agent. To go back to SSH, remove this node from agent_nodes and deploy again.")
    # The other nodes' agents reach the listener only through the infra firewall's
    # 8443 rule: a node that never connects must fail the deploy, not wait silently.
    peers = report.get("peers") or {}
    if "pushed" in peers.values():
        check = subprocess.run(["python3", str(stage / "configure-nodes.py"), "--agent-check", str(since)],
                               check=False, capture_output=True, text=True)
        if check.returncode:
            raise SystemExit(f"carrel-agent on another node did not reach the control plane within 60 s "
                             f"({(check.stdout or '').strip()}): see journalctl -u carrel-agent on that node. "
                             "Run bootstrap-platform.py --firewall on the first exit node. A node in "
                             "agent_identity.certificate_nodes also needs a valid certificate: enrol it, or "
                             "remove it from certificate_nodes. Or remove the node from agent_nodes and deploy again.")
    if report.get("plugins_error"):
        raise SystemExit(f"The plugins were not installed ({report['plugins_error']}): fix the site file's "
                         "plugins and deploy again. The control plane and the agents are up.")


def rollback(stage, with_database):
    """Go back one release: the last deploy's saved binary, units and node programs, and the database on request."""
    stamp = stage.name.removeprefix("go-upgrade-")
    if not stage.is_dir() or not any(stage.glob("before-*")):
        raise SystemExit(f"{stage} holds no saved node files: nothing to roll back to")
    # The copy in CT 100 is the one the last deploy left, which may predate these commands.
    push(Path(__file__).resolve(), "/usr/local/lib/carrel/install-control.py", "755")
    state = json.loads(capture("pct", "exec", CT, "--", "python3", "/usr/local/lib/carrel/install-control.py", "ct",
                               "schema", stamp))
    current, previous = state["current"], state["previous"]
    migrated = current is not None and previous is not None and current > previous
    if migrated and not with_database:
        raise SystemExit(f"The database has schema {current}; the previous release reads up to {previous}. "
                         "It would refuse to start. Run again with --database to restore the copy made before the "
                         "migration, which loses every write since the upgrade.")
    if with_database and not migrated:
        raise SystemExit(f"The database is at schema {current} and the previous release read {previous}: the last "
                         "deploy migrated nothing, so there is no copy to restore. Run without --database.")
    restore = None
    if with_database:
        if not state["copy"]:
            raise SystemExit(f"No pre-migration copy {DATABASE}.schema-{previous}-* in CT {CT}")
        if not state.get("copy_intact"):
            raise SystemExit(f"{state['copy']} in CT {CT} is not an intact schema {previous} database: nothing changed")
        when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(state["copy_time"]))
        print(f"LOST: every write to the database since {when}, when {state['copy']} was made. "
              f"The database goes back to schema {previous}; that copy stays.")
        restore = previous
    release = json.loads((stage / "before-release.json").read_text()) if (stage / "before-release.json").exists() else {}
    try:
        undo(stage, stamp, saved_paths(), (stage / "before-release.json").exists(), True, True, restore)
    finally:
        subprocess.run(["pct", "exec", CT, "--", "systemctl", "enable", "--now", "carrel-backup.timer"], check=False)
    # The same node step a deploy runs, now from the restored programs: the other
    # nodes get them and release.json, and config.json gets the node list and
    # agent token digests again. carrel reads config.json at start, so it restarts.
    run("python3", stage / "configure-nodes.py")
    ct("systemctl", "restart", "carrel")
    if release.get("version"):
        healthy(release["version"], origin_host())
    ct("systemctl", "is-active", "carrel")
    # Every agent restarts on the restored carrel-agent, as after a deploy.
    agents(stage)
    print(json.dumps({"rolled_back": str(stage), "database": bool(with_database), "version": release.get("version")}))


def latest_stage():
    stages = sorted(DEPLOYS.glob("go-upgrade-*"))
    if not stages:
        raise SystemExit(f"No {DEPLOYS}/go-upgrade-* directory: nothing to roll back")
    return stages[-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="where", required=True)
    h = sub.add_parser("host")
    h.add_argument("--stage", type=Path, required=True)
    h.add_argument("--version", required=True)
    r = sub.add_parser("rollback", help="restore the release before the last deploy")
    r.add_argument("--stage", type=Path, help="the deploy to undo (default: the newest go-upgrade-*)")
    r.add_argument("--database", action="store_true",
                   help="also restore the copy made before the schema migration; loses every write since")
    c = sub.add_parser("ct")
    c.add_argument("command", choices=["setup", "preflight", "backup", "activate", "restore", "schema",
                                       "restore-database"])
    c.add_argument("args", nargs="*")
    a = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run as root")
    if a.where == "host":
        host(a.stage, a.version)
    elif a.where == "rollback":
        rollback(a.stage or latest_stage(), a.database)
    elif a.command == "schema":
        ct_schema(a.args[0])
    elif a.command == "restore-database":
        ct_restore_database(a.args[0])
    elif a.command == "backup":
        ct_backup(a.args[0])
    elif a.command == "restore":
        ct_restore(a.args[0], json.loads(a.args[1]))
    else:
        {"setup": ct_setup, "preflight": ct_preflight, "activate": ct_activate}[a.command]()


if __name__ == "__main__":
    sys.exit(main())
