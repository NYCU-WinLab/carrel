"""deploy-go.py stages a release; install-control.py installs it. No live host is reached."""

import hashlib
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_deploy_stages_the_release_and_runs_the_installer_on_the_host(tmp_path, monkeypatch):
    deploy = load("deploy-go.py")
    for name in ("carrel", "carrel-agent", "carrel-deployd", "carrel-fetch"):
        (tmp_path / name).write_bytes(b"static binary fixture")
    calls = []
    monkeypatch.setattr(
        deploy, "run", lambda args, **kw: calls.append(args) or SimpleNamespace(stdout="rev\n")
    )
    monkeypatch.setattr(
        sys, "argv", ["deploy-go.py", "--host", "root@192.168.19.101", "--artifacts", str(tmp_path)]
    )
    deploy.main()
    copied = next(c for c in calls if c[0] == "scp")
    names = {Path(p).name for p in copied[1:-1]}
    assert {
        "carrel",
        "carrel-agent",
        "carrel-deployd",
        "carrel-fetch",
        "install-control.py",
        "node-agent.py",
        "configure-nodes.py",
        "configure-reader.py",
        "guest-report.py",
        "gateway-sync.py",
        "jump-sync.py",
        "jump-cert.py",
        "hashes.json",
    } == names
    assert copied[-1].startswith("root@192.168.19.101:/var/lib/carrel/go-upgrade-")
    command = next(c for c in calls if c[0] == "ssh" and "install-control.py" in c[2])
    assert command[:2] == ["ssh", "root@192.168.19.101"] and "install-control.py host --stage" in command[2]
    report = json.loads((tmp_path / "deploy-go.json").read_text())
    assert f"--version {report['version']}" in command[2]
    hashes = json.loads((tmp_path / "hashes.json").read_text())
    assert (
        hashes["node-agent.py"] == hashlib.sha256((ROOT / "scripts/node-agent.py").read_bytes()).hexdigest()
    )


def test_deploy_needs_an_explicit_host(tmp_path, monkeypatch):
    deploy = load("deploy-go.py")
    for argv in (
        ["--artifacts", str(tmp_path)],
        ["--host", "root@carrel01"],
        ["--host", "root@carrel01", "--artifacts", str(tmp_path), "--release", "v0.11.0"],
        ["--host", "-oProxyCommand=x", "--artifacts", str(tmp_path)],
    ):
        monkeypatch.setattr(sys, "argv", ["deploy-go.py", *argv])
        with pytest.raises(SystemExit):
            deploy.main()


def release_archive(work, tag, extra=None, sums=None):
    """Write what `gh release download` would leave in work: the archive and SHA256SUMS."""
    import io
    import tarfile

    name = f"carrel-{tag}-linux-amd64"
    archive = work / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        files = {f"{name}/REVISION": b"abc123\n"}
        files.update(
            {
                f"{name}/dist/{b}": b"release binary"
                for b in ("carrel", "carrel-agent", "carrel-deployd", "carrel-fetch")
            }
        )
        files.update({f"{name}/scripts/{s.name}": s.read_bytes() for s in (ROOT / "scripts").glob("*.py")})
        files.update(extra or {})
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    digest = sums or hashlib.sha256(archive.read_bytes()).hexdigest()
    (work / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")


def deploy_release(tmp_path, monkeypatch, **archive):
    deploy = load("deploy-go.py")
    calls = []

    def run(args, **kw):
        calls.append(args)
        if args[:3] == ["gh", "release", "download"]:
            release_archive(Path(args[args.index("-D") + 1]), args[3], **archive)
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(deploy, "run", run)
    monkeypatch.setattr(deploy.tempfile, "mkdtemp", lambda prefix: str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["deploy-go.py", "--host", "root@carrel01", "--release", "v0.11.0"])
    deploy.main()
    return calls


def test_a_release_deploy_installs_the_checked_archive(tmp_path, monkeypatch):
    calls = deploy_release(tmp_path, monkeypatch)
    command = next(c for c in calls if c[0] == "ssh" and "install-control.py host" in c[2])
    assert "--version 0.11.0" in command[2]
    report = json.loads((tmp_path / "carrel-v0.11.0-linux-amd64/dist/deploy-go.json").read_text())
    assert report["release"] is True and report["revision"] == "abc123"
    copied = next(c for c in calls if c[0] == "scp")
    assert all("carrel-v0.11.0-linux-amd64" in p for p in copied[1:-1])


def test_a_release_archive_that_does_not_match_its_checksum_is_refused(tmp_path, monkeypatch):
    with pytest.raises(SystemExit, match="SHA256SUMS"):
        deploy_release(tmp_path, monkeypatch, sums="0" * 64)


def test_a_release_archive_with_a_path_outside_its_folder_is_refused(tmp_path, monkeypatch):
    with pytest.raises(SystemExit, match="Unexpected path"):
        deploy_release(tmp_path, monkeypatch, extra={"carrel-v0.11.0-linux-amd64/../evil": b"x"})


def test_a_release_must_be_a_version_tag(tmp_path, monkeypatch):
    deploy = load("deploy-go.py")
    monkeypatch.setattr(sys, "argv", ["deploy-go.py", "--host", "root@carrel01", "--release", "main"])
    with pytest.raises(SystemExit):
        deploy.main()


class Node:
    """Records what install-control's host part runs, and can fail one step."""

    def __init__(self, module, monkeypatch, tmp_path, fail_on=None, jump=False, clear_fails=False):
        self.calls, self.fail_on = [], fail_on
        self.lib = tmp_path / "lib"
        self.lib.mkdir()
        for name in ("node-agent.py", "guest-report.py", "gateway-sync.py", "jump-sync.py", "jump-cert.py"):
            (self.lib / name).write_text("old " + name)
        monkeypatch.setattr(module, "LIB", self.lib)
        monkeypatch.setattr(module, "run", self.run)
        monkeypatch.setattr(
            module, "capture", lambda *a: '{"version": "1.0.0"}' if a[-1] == "-version" else "carrel.test\n"
        )
        monkeypatch.setattr(
            module.subprocess, "run", lambda args, **kw: self.subprocess_run(args, clear_fails)
        )
        monkeypatch.setattr(module, "templates_for", lambda stage, node, storage: {"debian-13-minimal": {}})
        monkeypatch.setattr(module, "healthy", lambda version, host: {"version": version})
        (tmp_path / "node.json").write_text('{"storage": "local-zfs"}')
        monkeypatch.setattr(module, "NODE_JSON", tmp_path / "node.json")
        (tmp_path / "site.json").write_text(json.dumps({"ssh_jump": jump}))
        monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
        monkeypatch.setattr(module, "TEMPLATES", tmp_path / "templates.json")

    def subprocess_run(self, args, clear_fails):
        self.calls.append(tuple(args))
        failed = clear_fails and tuple(args[:5]) == ("pct", "exec", "102", "--", "rm")
        return SimpleNamespace(returncode=1 if failed else 0)

    def run(self, *args, **kwargs):
        args = tuple(str(a) for a in args)
        self.calls.append(args)
        if self.fail_on and self.fail_on(args):
            raise RuntimeError("step failed")
        if args[:2] == ("install", "-m"):
            Path(args[4]).write_bytes(Path(args[3]).read_bytes())

    def ct(self):
        return [c[6:] for c in self.calls if c[:5] == ("pct", "exec", "100", "--", "python3")]


def staged(tmp_path, tamper=False):
    stage = tmp_path / "go-upgrade-20261020-000000"
    stage.mkdir()
    hashes = {}
    for name in (
        "carrel",
        "carrel-agent",
        "carrel-deployd",
        "carrel-fetch",
        "install-control.py",
        "node-agent.py",
        "configure-reader.py",
        "configure-nodes.py",
        "guest-report.py",
        "gateway-sync.py",
        "jump-sync.py",
        "jump-cert.py",
    ):
        (stage / name).write_text("new " + name)
        hashes[name] = hashlib.sha256(("new " + name).encode()).hexdigest()
    if tamper:
        hashes["node-agent.py"] = "0" * 64
    (stage / "hashes.json").write_text(json.dumps(hashes))
    return stage


def test_a_tampered_transfer_stops_before_anything_changes(tmp_path, monkeypatch):
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path)
    with pytest.raises(SystemExit, match="checksum"):
        module.host(staged(tmp_path, tamper=True), "1.0.0")
    assert node.calls == []


def test_an_upgrade_records_its_release_for_the_node_programs(tmp_path, monkeypatch):
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path)
    module.host(staged(tmp_path), "1.0.0")
    release = json.loads((node.lib / "release.json").read_text())
    assert release["version"] == "1.0.0"
    assert release["sha256"]["node-agent.py"] == hashlib.sha256(b"new node-agent.py").hexdigest()


def test_a_failed_upgrade_puts_the_previous_release_record_back(tmp_path, monkeypatch):
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path, fail_on=lambda a: "configure-nodes.py" in a[-1])
    (node.lib / "release.json").write_text('{"version": "0.9.0"}')
    with pytest.raises(RuntimeError):
        module.host(staged(tmp_path), "1.0.0")
    assert json.loads((node.lib / "release.json").read_text())["version"] == "0.9.0"


def test_a_failed_first_recorded_upgrade_leaves_no_release_record(tmp_path, monkeypatch):
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path, fail_on=lambda a: "configure-nodes.py" in a[-1])
    with pytest.raises(RuntimeError):
        module.host(staged(tmp_path), "1.0.0")
    assert not (node.lib / "release.json").exists()


def test_a_failed_backup_keeps_the_existing_release_record(tmp_path, monkeypatch):
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path, fail_on=lambda a: a[-2:-1] == ("backup",))
    (node.lib / "release.json").write_text('{"version": "0.9.0"}')
    with pytest.raises(RuntimeError):
        module.host(staged(tmp_path), "1.0.0")
    assert json.loads((node.lib / "release.json").read_text())["version"] == "0.9.0"


def test_an_upgrade_backs_up_then_installs_then_activates(tmp_path, monkeypatch):
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path)
    for day in range(1, 8):
        (tmp_path / f"go-upgrade-2026100{day}-000000").mkdir()
    module.host(staged(tmp_path), "1.0.0")
    kept = sorted(p.name for p in tmp_path.glob("go-upgrade-*"))
    assert len(kept) == module.KEEP and kept[-1] == "go-upgrade-20261020-000000"
    assert [c[1] for c in node.ct()] == ["setup", "preflight", "preflight", "backup", "activate"]
    assert (node.lib / "node-agent.py").read_text() == "new node-agent.py"
    order = [c for c in node.calls if "configure-nodes.py" in " ".join(c) or c[-1] == "activate"]
    assert "configure-nodes.py" in " ".join(order[0]) and order[1][-1] == "activate"


@pytest.mark.parametrize(
    "step,restored",
    [
        ("configure-nodes.py", "CONFIGURED"),
        ("activate", "ACTIVATED"),
    ],
)
def test_a_failed_upgrade_puts_the_previous_release_back(tmp_path, monkeypatch, step, restored):
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path, fail_on=lambda args: args[-1].endswith(step))
    with pytest.raises(RuntimeError):
        module.host(staged(tmp_path), "1.0.0")
    restore = next(c for c in node.calls if c[6:8] == ("ct", "restore"))
    names = json.loads(restore[9])
    assert set(module.CONFIGURED) <= set(names)
    assert (set(module.ACTIVATED) <= set(names)) is (restored == "ACTIVATED")
    assert (node.lib / "node-agent.py").read_text() == "old node-agent.py"
    assert ("pct", "exec", "100", "--", "systemctl", "start", "carrel") in node.calls


@pytest.mark.parametrize("jump", [True, False])
def test_a_rollback_clears_the_jump_generations(tmp_path, monkeypatch, jump):
    """The restored binary may predate "gen"; jump-sync.py must accept its writes (issue #388)."""
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path, fail_on=lambda args: args[-1] == "activate", jump=jump)
    with pytest.raises(RuntimeError):
        module.host(staged(tmp_path), "1.0.0")
    clear = ("pct", "exec", "102", "--", "rm", "-f", *module.JUMP_GENS)
    assert (clear in node.calls) is jump
    if jump:
        stopped = ("pct", "exec", "100", "--", "systemctl", "stop", "carrel")
        stop = max(i for i, c in enumerate(node.calls) if c == stopped)
        start = node.calls.index(("pct", "exec", "100", "--", "systemctl", "start", "carrel"))
        assert stop < node.calls.index(clear) < start


def test_a_rollback_that_cannot_clear_the_jump_generations_warns_and_starts_carrel(
    tmp_path, monkeypatch, capsys
):
    module = load("install-control.py")
    node = Node(
        module,
        monkeypatch,
        tmp_path,
        fail_on=lambda args: args[-1] == "activate",
        jump=True,
        clear_fails=True,
    )
    with pytest.raises(RuntimeError):
        module.host(staged(tmp_path), "1.0.0")
    err = capsys.readouterr().err
    assert "rm -f /var/lib/carrel-jump/keys.gen /var/lib/carrel-jump/certs.gen" in err
    assert ("pct", "exec", "100", "--", "systemctl", "start", "carrel") in node.calls


def test_a_rollback_that_clears_the_jump_generations_does_not_warn(tmp_path, monkeypatch, capsys):
    module = load("install-control.py")
    Node(module, monkeypatch, tmp_path, fail_on=lambda args: args[-1] == "activate", jump=True)
    with pytest.raises(RuntimeError):
        module.host(staged(tmp_path), "1.0.0")
    assert "WARNING" not in capsys.readouterr().err


def test_a_successful_upgrade_keeps_the_jump_generations(tmp_path, monkeypatch):
    module = load("install-control.py")
    node = Node(module, monkeypatch, tmp_path, jump=True)
    module.host(staged(tmp_path), "1.0.0")
    assert not any(c[:3] == ("pct", "exec", "102") for c in node.calls)


def test_activation_writes_the_units_and_records_the_templates(tmp_path, monkeypatch):
    module = load("install-control.py")
    etc, units, binary = tmp_path / "etc", tmp_path / "units", tmp_path / "bin"
    for d in (etc, units, binary):
        d.mkdir()
    (etc / "config.json").write_text(json.dumps({"origin": "https://carrel.test"}))
    (etc / "templates.next.json").write_text(
        json.dumps({"debian-13-minimal": {"vmid": 9014, "environment": "minimal"}})
    )
    (binary / "carrel.next").write_text("new")
    monkeypatch.setattr(module, "ETC", etc)
    monkeypatch.setattr(module, "UNIT_DIR", units)
    monkeypatch.setattr(module, "BINARY", binary / "carrel")
    module.ct_activate()
    service = (units / "carrel.service").read_text()
    assert "ExecStart=/usr/local/bin/carrel\n" in service and "PYTHON" not in service
    assert (units / "carrel-backup.timer").exists()
    assert json.loads((etc / "config.json").read_text())["vm_environment"] == {
        "debian-13-minimal": {"environment": "minimal"}
    }
    assert not (etc / "templates.next.json").exists() and (binary / "carrel").read_text() == "new"


def test_preflight_refuses_active_operations_and_allows_a_first_install(tmp_path, monkeypatch, capsys):
    module = load("install-control.py")
    monkeypatch.setattr(module, "DATABASE", tmp_path / "carrel.db")
    module.ct_preflight()
    assert json.loads(capsys.readouterr().out)["first_install"]
    db = sqlite3.connect(tmp_path / "carrel.db")
    db.execute("CREATE TABLE objects(kind TEXT, id TEXT, tenant INTEGER, data TEXT)")
    db.execute("CREATE TABLE oauth(kind TEXT, id TEXT, data TEXT, expires INTEGER)")
    db.execute(
        "INSERT INTO objects VALUES('operations','a',1,?)", (json.dumps({"id": "a", "state": "succeeded"}),)
    )
    db.commit()
    module.ct_preflight()
    assert json.loads(capsys.readouterr().out)["active_operations"] == 0
    db.execute(
        "INSERT INTO objects VALUES('operations','b',1,?)", (json.dumps({"id": "b", "state": "running"}),)
    )
    db.commit()
    with pytest.raises(SystemExit, match="Active operations"):
        module.ct_preflight()


def test_a_binary_of_another_version_stops_the_install(monkeypatch, tmp_path):
    module = load("install-control.py")
    (tmp_path / "hashes.json").write_text("{}")
    asked = []
    monkeypatch.setattr(module, "capture", lambda *a: asked.append(a) or '{"version": "0.9.0"}')
    # Nothing else on the host runs before the check (issue #56).
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("ran " + str(a)))
    with pytest.raises(SystemExit, match="0.9.0"):
        module.host(tmp_path, "0.10.0")
    assert asked == [(tmp_path / "carrel", "-version")]
