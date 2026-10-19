"""CT 100 reaches the node adapter on every site node (PLAN 15.15 gap 5)."""

import importlib.util
import json
import sys
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


def test_ssh_config_replaces_the_hand_written_node_block_and_keeps_the_edge():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    legacy = "Host *\n  User root\nHost carrel-node\n  HostName 10.200.0.1\nHost carrel-edge\n  HostName 140.113.194.229\n  Port 1121\n"
    first = module.ssh_config(legacy, nodes)
    assert (
        first.count("Host carrel-node\n") == 1
        and "Host carrel-edge\n  HostName 140.113.194.229\n  Port 1121" in first
    )
    assert "Host carrel04\n  HostName 192.168.19.104" in first
    assert module.ssh_config(first, nodes) == first
    fresh = module.ssh_config("", nodes)
    assert fresh.startswith("Host *\n  User root\n  IdentityFile /etc/carrel/node_key")


def test_known_hosts_pins_each_node_and_keeps_other_hosts():
    module = load("configure-nodes.py")
    existing = "10.200.0.1 ssh-ed25519 OLD\n[140.113.194.229]:1121 ssh-ed25519 EDGE\n"
    merged = module.known_hosts(
        existing, [("10.200.0.1", "ssh-ed25519 NEW"), ("192.168.19.102", "ssh-ed25519 TWO")]
    )
    assert merged.splitlines() == [
        "[140.113.194.229]:1121 ssh-ed25519 EDGE",
        "10.200.0.1 ssh-ed25519 NEW",
        "192.168.19.102 ssh-ed25519 TWO",
    ]


def test_infra_firewall_lets_the_control_plane_reach_peer_ssh(monkeypatch, tmp_path):
    module = load("bootstrap-platform.py")
    (tmp_path / "site.json").write_text(json.dumps(SITE))
    real = Path
    monkeypatch.setattr(
        module, "Path", lambda p: tmp_path / "site.json" if str(p) == "/etc/carrel/site.json" else real(p)
    )
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: "carrel01")
    assert module.peer_ssh() == [
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
    real = Path
    monkeypatch.setattr(
        module, "Path", lambda p: tmp_path / "site.json" if str(p) == "/etc/carrel/site.json" else real(p)
    )
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: "carrel02")
    monkeypatch.setattr(sys, "argv", ["bootstrap-platform.py", "--role", "site", "--admin-key", "k"])
    try:
        module.main()
    except AssertionError as e:
        assert "first exit node" in str(e)
    else:
        raise AssertionError("bootstrap ran on a node that is not the first exit node")
