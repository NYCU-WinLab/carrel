"""Site files drive the underlay filter, SDN peers and exit nodes (PLAN 6.3, 15.15)."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SITE = json.loads((ROOT / "sites/b09/cluster.json").read_text())


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_underlay_accepts_only_peers_on_the_underlay_to_this_node():
    rules = load("install-network.py").underlay_rules(
        "vmbr0", "192.168.19.102", ["192.168.19.101", "192.168.19.103"]
    )
    assert rules[:2] == [
        'iifname "vmbr0" ip saddr { 192.168.19.101, 192.168.19.103 } ip daddr 192.168.19.102 udp dport 4789 accept',
        'iifname "vmbr0" ip saddr { 192.168.19.101, 192.168.19.103 } ip daddr 192.168.19.102 tcp dport 179 accept',
    ]
    assert rules[2:] == ["udp dport 4789 counter drop", "tcp dport 179 counter drop"]


def test_single_node_table_drops_vxlan_and_bgp_everywhere():
    nft = load("install-network.py").TENANT_HOST_NFT
    assert "accept\n  udp dport 4789" not in nft
    assert "udp dport 4789 counter drop" in nft and "tcp dport 179 counter drop" in nft
    assert "4789 accept" not in nft and "179 accept" not in nft


def test_b09_layout_peers_every_other_node_and_protects_the_public_address():
    layout = load("install-network.py").site_layout("carrel02", SITE)
    assert layout["address"] == "192.168.19.102"
    assert layout["peers"] == ["192.168.19.101", "192.168.19.103", "192.168.19.104"]
    assert layout["all"] == ["192.168.19.101", "192.168.19.102", "192.168.19.103", "192.168.19.104"]
    assert layout["exit_nodes"] == ["carrel01"]
    assert "140.113.60.184/32" in layout["protected"] and "192.168.19.104/32" in layout["protected"]
    assert "140.113.60.189/32" in layout["protected"]
    assert layout["entries"] == [{"address": "140.113.60.184/32", "port": 443}]


def test_legacy_layout_keeps_the_r640_values():
    layout = load("install-network.py").site_layout("carrel01", None)
    assert layout["address"] == "192.168.13.159" and layout["peers"] == []
    assert layout["entries"] == [{"address": "140.113.194.229/32", "port": 443}]


def test_a_node_outside_the_site_file_is_refused():
    with pytest.raises(SystemExit):
        load("install-network.py").site_layout("carrel09", SITE)


def test_bootstrap_infra_firewall_uses_the_same_underlay_rule(monkeypatch, tmp_path):
    module = load("bootstrap-platform.py")
    (tmp_path / "site.json").write_text(json.dumps(SITE))
    real = Path

    def local(path):
        return tmp_path / "site.json" if str(path) == "/etc/carrel/site.json" else real(path)

    monkeypatch.setattr(module, "Path", local)
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: "carrel01")
    expected = load("install-network.py").underlay_rules(
        "vmbr0", "192.168.19.101", ["192.168.19.102", "192.168.19.103", "192.168.19.104"]
    )
    assert module.underlay() == expected


@pytest.mark.parametrize("node,serves", [("carrel01", True), ("carrel02", False)])
def test_private_dhcp_runs_on_the_first_exit_node_only(monkeypatch, tmp_path, node, serves):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", node)
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    assert module.serves_private_dhcp() is True
    (tmp_path / "site.json").write_text(json.dumps(SITE))
    assert module.serves_private_dhcp() is serves
