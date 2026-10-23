"""Public IP bindings on the exit node (issue #91, PLAN 6.12): 1:1 NAT."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SITE = json.loads((ROOT / "sites/b09/cluster.json").read_text())
MACHINE = {
    "tenant_n": 3,
    "vmid": 10301,
    "host": 11,
    "name": "app",
    "kind": "vm",
    "ip": "10.200.3.11",
    "mac": "02:ca:00:00:03:0b",
}
OTHER = {
    "tenant_n": 3,
    "vmid": 10302,
    "host": 12,
    "name": "db",
    "kind": "vm",
    "ip": "10.200.3.12",
    "mac": "02:ca:00:00:03:0c",
}


def load():
    spec = importlib.util.spec_from_file_location("node_agent_public_ips", ROOT / "scripts" / "node-agent.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.site = lambda: SITE
    return module


def state(*bindings, status="active"):
    return {
        "tenants": [{"n": 3, "slug": "alice", "status": status}],
        "machines": [MACHINE, OTHER],
        "ports": [],
        "peers": [],
        "domains": [],
        "public_ips": list(bindings),
    }


BOUND = {"address": "140.113.60.163", "tenant_n": 3, "vmid": 10301, "ports": ["tcp/22", "udp/27015"]}


def test_a_bound_address_is_natted_one_to_one():
    module = load()
    bindings = module.public_bindings(state(BOUND))
    nft = module.ports_nft(state(BOUND), "140.113.60.184", bindings)
    prerouting = nft.split("chain prerouting")[1].split("\n }")[0]
    # Only from the uplink: no hairpin from other machines.
    assert 'iifname "vmbr0.60" ip daddr 140.113.60.163 dnat to 10.200.3.11' in prerouting
    postrouting = nft.split("chain postrouting")[1].split("\n }")[0]
    assert 'oifname "vmbr0.60" ip saddr 10.200.3.11 snat to 140.113.60.163' in postrouting
    assert "10.200.3.12" not in nft


def test_no_binding_leaves_the_rules_as_they_were():
    module = load()
    assert module.ports_nft(state(), "140.113.60.184", module.public_bindings(state())) == module.ports_nft(
        state(), "140.113.60.184"
    )


def test_a_suspended_tenant_or_a_missing_machine_holds_nothing():
    module = load()
    assert module.public_bindings(state(BOUND, status="suspended")) == []
    assert module.public_bindings(state({**BOUND, "vmid": 10399})) == []


@pytest.mark.parametrize(
    "change",
    [
        {"tenant_n": 4},  # another tenant's machine
        {"ports": []},
        {"ports": ["icmp/1"]},
        {"ports": ["tcp/0"]},
        {"ports": ["tcp/22", "tcp/22"]},
    ],
)
def test_a_bad_binding_is_refused(change):
    module = load()
    s = state({**BOUND, **change})
    s["tenants"].append({"n": 4, "slug": "bob", "status": "active"})
    with pytest.raises(ValueError):
        module.public_bindings(s, ["140.113.60.170/32"])


def test_two_bindings_of_one_address_or_one_machine_are_refused():
    module = load()
    with pytest.raises(ValueError):
        module.public_bindings(state(BOUND, {**BOUND, "vmid": 10302}))
    with pytest.raises(ValueError):
        module.public_bindings(state(BOUND, {**BOUND, "address": "140.113.60.164"}))


def test_the_firewall_admits_the_internet_on_the_chosen_ports_only():
    module = load()
    lines = module.guest_firewall(MACHINE, state(BOUND), {"protected_addresses": []}).splitlines()
    ipset = lines[lines.index("[IPSET internet]") + 1 : lines.index("[RULES]")]
    assert [x for x in ipset if x] == module.INTERNET_IPSET
    assert "IN ACCEPT -source +internet -p tcp -dport 22" in lines
    assert "IN ACCEPT -source +internet -p udp -dport 27015" in lines
    assert "IN ACCEPT -source +internet" not in lines
    # The other machine of the tenant is not opened.
    other = module.guest_firewall(OTHER, state(BOUND), {"protected_addresses": []})
    assert "+internet" not in other


def test_all_ports_admit_every_internet_source():
    module = load()
    lines = module.guest_firewall(
        MACHINE, state({**BOUND, "ports": ["all"]}), {"protected_addresses": []}
    ).splitlines()
    assert "IN ACCEPT -source +internet" in lines
    assert not [x for x in lines if x.startswith("IN ACCEPT -source +internet -p")]


def test_addresses_are_held_deprecated_and_only_its_own_removed(tmp_path, monkeypatch):
    module = load()
    calls, held = [], set()

    def run(*a, **k):
        calls.append(a)
        if a[:3] == ("ip", "address", "replace"):
            held.add(a[3].split("/")[0])
        if a[:3] == ("ip", "address", "del"):
            held.discard(a[3].split("/")[0])
        if a[:3] == ("ip", "-4", "-j"):
            return json.dumps([{"addr_info": [{"local": x} for x in held]}])
        return ""

    flushed = []
    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module, "conntrack_flush", flushed.append)
    monkeypatch.setattr(module, "PUBLIC_IPS", tmp_path / "public-ips.json")
    module.public_addresses({"140.113.60.163": "10.200.3.11", "140.113.60.164": "10.200.3.12"})
    assert (
        "ip",
        "address",
        "replace",
        "140.113.60.163/32",
        "dev",
        "vmbr0.60",
        "preferred_lft",
        "0",
        "scope",
        "link",
    ) in calls
    assert flushed == []
    calls.clear()
    # .163 leaves, .164 moves to another machine: both lose their connections.
    module.public_addresses({"140.113.60.164": "10.200.3.13"})
    assert ("ip", "address", "del", "140.113.60.163/32", "dev", "vmbr0.60") in calls
    assert not [c for c in calls if c[:3] == ("ip", "address", "del") and "164" in c[3]]
    assert flushed == ["140.113.60.163", "140.113.60.164"]
    assert json.loads((tmp_path / "public-ips.json").read_text()) == {"140.113.60.164": "10.200.3.13"}


def test_a_failed_removal_keeps_the_address_tracked(tmp_path, monkeypatch):
    module = load()

    def run(*a, **k):
        if a[:3] == ("ip", "address", "del"):
            raise module.CommandFailure("busy")
        if a[:3] == ("ip", "-4", "-j"):
            return json.dumps([{"addr_info": [{"local": "140.113.60.163"}]}])
        return ""

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module, "conntrack_flush", lambda a: None)
    monkeypatch.setattr(module, "PUBLIC_IPS", tmp_path / "public-ips.json")
    (tmp_path / "public-ips.json").write_text(json.dumps({"140.113.60.163": "10.200.3.11"}))
    with pytest.raises(module.CommandFailure):
        module.public_addresses({})
    assert "140.113.60.163" in json.loads((tmp_path / "public-ips.json").read_text())


@pytest.mark.parametrize(
    "address", ["140.113.60.184", "140.113.60.190", "140.113.60.191", "140.113.61.10", "140.113.60.170"]
)
def test_an_unusable_address_is_skipped_not_fatal(address):
    # The shared address, the gateway, broadcast, outside the network, protected.
    module = load()
    s = state({**BOUND, "address": address})
    assert module.public_bindings(s, ["140.113.60.170/32"]) == []
    # Every machine's firewall still builds.
    module.guest_firewall(OTHER, s, {"protected_addresses": ["140.113.60.170/32"]})
