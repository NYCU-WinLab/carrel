"""A site with its own public address terminates ingress on its first exit node."""

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


def test_only_the_first_exit_node_holds_the_public_address():
    module = load("install-network.py")
    assert module.site_layout("carrel01", SITE)["public"] == {
        "interface": "vmbr0.60",
        "cidr": "140.113.60.184/27",
        "address": "140.113.60.184",
        "gateway": "140.113.60.190",
    }
    assert module.site_layout("carrel02", SITE)["public"] is None
    assert "public" not in module.site_layout("carrel01", None)


def test_public_interface_keeps_host_ports_off_the_internet():
    nft = load("install-network.py").public_nft("vmbr0.60", "140.113.60.184")
    input_chain = nft.split("chain input")[1].split("\n }")[0]
    assert 'iifname "vmbr0.60" ct state established,related accept' in input_chain
    assert input_chain.strip().splitlines()[-1].strip() == 'iifname "vmbr0.60" counter drop'
    forward = nft.split("chain forward")[1].split("\n }")[0]
    assert 'iifname "vmbr0.60" ct status dnat accept' in forward
    spoofed = forward.index("10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10")
    assert spoofed < forward.index("ct status dnat accept")
    assert forward.strip().splitlines()[-1].strip() == 'iifname "vmbr0.60" counter drop'
    assert 'iifname "vmbr0.60" ct state new ct mark set 0x60' in nft
    # Marking the arriving packets would route them past the local table.
    assert "ct mark 0x60 ct direction reply meta mark set 0x60" in nft
    assert 'oifname "vmbr0.60" ip saddr 10.200.0.0/16 snat to 140.113.60.184' in nft


def test_public_interface_routes_replies_back_out_the_public_gateway():
    stanza = load("install-network.py").public_interface(
        "vmbr0.60", "140.113.60.184/27", "140.113.60.190", "140.113.60.184"
    )
    assert "address 140.113.60.184/27" in stanza
    assert "post-up ip route replace default via 140.113.60.190 dev vmbr0.60 table 160" in stanza
    assert "ip rule add fwmark 0x60 lookup 160 priority 1600" in stanza
    assert "ip rule add from 140.113.60.184 lookup 160 priority 1601" in stanza
    assert "disable_ipv6" in stanza
    assert "post-up ip route replace 140.113.60.160/27 dev vmbr0.60 table 160" in stanza
    assert stanza.index("pre-up nft list table inet carrel_public") < stanza.index("post-up")
    assert "gateway" not in stanza.split("address")[1].split("post-up")[0]


GRANT = {"tenant_n": 3, "vmid": 10300, "public_port": 20030, "port": 22, "proto": "tcp", "ip": "10.200.3.10"}


def test_ports_forward_http_to_the_gateway_and_grants_to_machines():
    nft = load("node-agent.py").ports_nft({"ports": [GRANT]}, "140.113.60.184")
    assert "ip daddr 140.113.60.184 tcp dport { 80, 443 } dnat to 10.200.0.2" in nft
    assert "ip daddr 140.113.60.184 tcp dport 20030 dnat to 10.200.3.10:22" in nft


@pytest.mark.parametrize(
    "change",
    [
        {"public_port": 20040},
        {"ip": "10.200.4.10"},
        {"ip": "10.200.3.200"},
        {"proto": "icmp"},
        {"tenant_n": 0},
    ],
)
def test_ports_refuse_grants_outside_the_tenant(change):
    with pytest.raises(ValueError):
        load("node-agent.py").ports_nft({"ports": [{**GRANT, **change}]}, "140.113.60.184")


def test_ports_refuse_a_duplicate_public_port():
    with pytest.raises(ValueError):
        load("node-agent.py").ports_nft({"ports": [GRANT, {**GRANT, "port": 80}]}, "140.113.60.184")


@pytest.mark.parametrize("node,address", [("carrel01", "140.113.60.184"), ("carrel02", None)])
def test_public_ingress_runs_on_the_first_exit_node(monkeypatch, tmp_path, node, address):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", node)
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    assert module.public_ingress() is None
    (tmp_path / "site.json").write_text(json.dumps(SITE))
    assert module.public_ingress() == address


@pytest.mark.parametrize("with_site,source", [(False, "-source 10.254.200.1 "), (True, "")])
def test_port_grants_admit_the_client_address_when_the_site_is_public(
    monkeypatch, tmp_path, with_site, source
):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    if with_site:
        (tmp_path / "site.json").write_text(json.dumps(SITE))
    machine = {
        "tenant_n": 3,
        "vmid": 10300,
        "host": 10,
        "name": "web",
        "kind": "vm",
        "ip": "10.200.3.10",
        "mac": "02:ca:03:00:00:01",
    }
    rules = module.guest_firewall(
        machine, {"ports": [GRANT], "domains": [], "peers": []}, {"protected_addresses": []}
    )
    assert f"IN ACCEPT {source}-p tcp -dport 22" in rules.splitlines()
