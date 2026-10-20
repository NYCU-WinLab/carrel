"""CT 100 reaches the node adapter on every site node (PLAN 15.15 gap 5)."""

import hashlib
import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = json.loads((ROOT / "sites/b09/cluster.json").read_text())
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIControlPlaneKey"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_first_exit_node_keeps_the_carrel_node_alias():
    nodes = load("configure-nodes.py").targets(SITE, "carrel01")
    assert nodes[0] == {
        "name": "carrel01",
        "target": "carrel-node",
        "host": "10.200.0.1",
        "address": "192.168.19.101",
    }
    assert [n["target"] for n in nodes[1:]] == ["carrel02", "carrel03", "carrel04"]
    assert nodes[2]["host"] == "192.168.19.103"


def test_one_authorized_line_serves_every_node_and_replaces_older_ones():
    module = load("configure-nodes.py")
    line = module.authorized_line(KEY, "192.168.19.101")
    assert (
        line
        == f'from="10.200.0.3,192.168.19.101",restrict,command="/usr/local/lib/carrel/node-agent.py" {KEY}'
    )
    existing = "\n".join(
        [
            "ssh-rsa AAAA root@carrel02",
            f'from="10.200.0.3",restrict,command="/usr/local/lib/carrel/node-agent.py" {KEY}',
        ]
    )
    merged = module.merge_authorized(existing, line, KEY).splitlines()
    assert merged == ["ssh-rsa AAAA root@carrel02", line]
    other = 'restrict,command="/usr/local/lib/carrel/node-agent.py",from="10.200.0.3" ssh-ed25519 OLDKEY'
    assert module.merge_authorized(other + "\n" + "\n".join(merged), line, KEY).splitlines() == merged
    assert module.merge_authorized("\n".join(merged), line, KEY).splitlines() == merged


def test_ssh_config_replaces_the_hand_written_node_block_and_keeps_other_hosts():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    legacy = "Host *\n  User root\nHost carrel-node\n  HostName 10.200.0.1\nHost carrel-backup\n  HostName 140.113.194.229\n  Port 1121\n"
    first = module.ssh_config(legacy, nodes)
    assert (
        first.count("Host carrel-node\n") == 1
        and "Host carrel-backup\n  HostName 140.113.194.229\n  Port 1121" in first
    )
    assert "Host carrel04\n  HostName 192.168.19.104" in first
    assert module.ssh_config(first, nodes) == first
    fresh = module.ssh_config("", nodes)
    assert fresh.startswith("Host *\n  User root\n  IdentityFile /etc/carrel/node_key")


def test_known_hosts_pins_each_node_and_keeps_other_hosts():
    module = load("configure-nodes.py")
    existing = "10.200.0.1 ssh-ed25519 OLD\n[140.113.194.229]:1121 ssh-ed25519 BACKUP\n"
    merged = module.known_hosts(
        existing, [("10.200.0.1", "ssh-ed25519 NEW"), ("192.168.19.102", "ssh-ed25519 TWO")]
    )
    assert merged.splitlines() == [
        "[140.113.194.229]:1121 ssh-ed25519 BACKUP",
        "10.200.0.1 ssh-ed25519 NEW",
        "192.168.19.102 ssh-ed25519 TWO",
    ]


def test_infra_firewall_lets_the_control_plane_reach_peer_ssh():
    module = load("bootstrap-platform.py")
    assert module.peer_ssh(SITE, "carrel01") == [
        'iifname "vmbr98" ip saddr 10.200.0.3 ip daddr { 192.168.19.102, 192.168.19.103, 192.168.19.104 } tcp dport 22 accept'
    ]


def test_authorized_keys_are_replaced_by_rename(tmp_path):
    module = load("configure-nodes.py")
    target = tmp_path / "authorized_keys"
    target.write_text("old\n")
    link = tmp_path / "link"
    link.symlink_to(target)
    module.replace_file(link, "new\n", 0o600)
    assert target.read_text() == "new\n" and link.is_symlink()
    assert (
        oct(target.stat().st_mode & 0o777) == "0o600"
        and not (tmp_path / "authorized_keys.carrel-next").exists()
    )


def test_a_node_name_cannot_inject_ssh_options():
    import pytest

    site = {**SITE, "nodes": [*SITE["nodes"], {"name": "x\n  ProxyCommand sh", "address": "192.168.19.105"}]}
    with pytest.raises(SystemExit):
        load("configure-nodes.py").targets(site, "carrel01")


def test_bootstrap_runs_only_on_the_first_exit_node_of_the_site(monkeypatch, tmp_path):
    module = load("bootstrap-platform.py")
    (tmp_path / "site.json").write_text(json.dumps(SITE))
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: "carrel02")
    monkeypatch.setattr(sys, "argv", ["bootstrap-platform.py", "--admin-key", "k"])
    try:
        module.main()
    except AssertionError as e:
        assert "first exit node" in str(e)
    else:
        raise AssertionError("bootstrap ran on a node that is not the first exit node")


def test_infra_containers_match_the_infra_bridge_mtu(monkeypatch):
    module = load("bootstrap-platform.py")
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args))
    real = Path
    # No existing CT config and no cached template; everything else is real.
    monkeypatch.setattr(
        module,
        "Path",
        lambda p: (
            real("/nonexistent") / str(p).lstrip("/")
            if str(p).startswith(("/etc/pve", "/var/lib/vz"))
            else real(p)
        ),
    )
    module.ct(101, "carrel-gateway", "10.200.0.2", "vmbr98", "10.200.0.1", 512, "k", "local-zfs")
    net = next(a[a.index("--net0") + 1] for a in calls if "--net0" in a)
    assert net.endswith(",mtu=1450")


def test_the_gateway_takes_only_the_control_planes_key_as_a_forced_command(monkeypatch):
    module = load("configure-nodes.py")
    calls = []

    def run(*args, input=None):
        calls.append((args, input))
        if args[-1] == "cat /root/.ssh/authorized_keys 2>/dev/null || true":
            return 'ssh-ed25519 ADMIN admin\nfrom="10.200.0.3",restrict,command="/usr/local/lib/carrel/gateway-sync.py" ssh-ed25519 OLD\n'
        if args[-1] == "/etc/ssh/ssh_host_ed25519_key.pub":
            return "ssh-ed25519 HOSTKEY root@carrel-gateway\n"
        return ""

    monkeypatch.setattr(module, "run", run)
    assert module.gateway("ssh-ed25519 NEW") == "ssh-ed25519 HOSTKEY"
    written = next(i for a, i in calls if i and "authorized_keys.carrel-next" in a[-1])
    lines = written.splitlines()
    assert lines[0] == "ssh-ed25519 ADMIN admin"
    assert lines[1:] == [
        'from="10.200.0.3",restrict,command="/usr/local/lib/carrel/gateway-sync.py" ssh-ed25519 NEW'
    ]
    assert ("pct", "push", "101", module.GATEWAY_SYNC, module.GATEWAY_SYNC, "--perms", "755") in [
        a for a, _ in calls
    ]
    sshd = next(i for a, i in calls if i and "sshd_config.d/carrel.conf" in a[-1])
    assert "PasswordAuthentication no" in sshd.splitlines()
    assert "reload" not in next(a[-1] for a, i in calls if i == sshd)
    config = module.ssh_config("", [*module.targets(SITE, "carrel01"), module.GATEWAY])
    assert "Host carrel-gateway\n  HostName 10.200.0.2" in config


def test_the_pinned_caddy_replaces_the_running_package_caddy(monkeypatch, tmp_path):
    module = load("bootstrap-platform.py")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        info = tarfile.TarInfo("caddy")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"\x7fELF"))
    data = archive.getvalue()
    monkeypatch.setattr(module, "CADDY_SHA512", hashlib.sha512(data).hexdigest())
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(data))
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args))
    module.caddy(101)
    steps = [a[4:] for a in calls if a[:2] == ("pct", "exec")]
    assert steps.index(("systemctl", "daemon-reload")) < steps.index(("systemctl", "restart", "caddy"))
