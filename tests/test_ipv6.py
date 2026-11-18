"""Site IPv6 (issue #142, PLAN 6.13): addresses, guest rules, tunnel filter and host rules."""

import importlib.util
import json
from pathlib import Path

import pytest
from test_ipv6_off_golden import CONFIG, GOLDEN, STATE, machine

ROOT = Path(__file__).resolve().parents[1]
KEY = "x" * 42 + "A="
SITE6 = {"prefix": "2a14:7581:880::/48", "peer": {"endpoint": "198.51.100.7:51820", "public_key": KEY}}


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_").replace(".py", "") + "_v6", ROOT / "scripts" / name
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def agent(tmp_path):
    a = load("node-agent.py")
    site = tmp_path / "site.json"
    site.write_text(json.dumps({"exit_nodes": ["carrel01"], "ipv6": SITE6}))
    a.SITE = site
    return a


def test_tenant_number_reads_as_decimal_digits(agent):
    assert str(agent.v6_net(SITE6["prefix"], 17)) == "2a14:7581:880:17::/64"
    assert str(agent.v6_net(SITE6["prefix"], 254)) == "2a14:7581:880:254::/64"
    assert str(agent.v6_address(SITE6["prefix"], machine())) == "2a14:7581:880:17::11"
    with pytest.raises(ValueError):
        agent.v6_address(SITE6["prefix"], machine(ip="10.200.18.11"))


@pytest.mark.parametrize(
    "bad",
    [
        {"prefix": "2a14:7581:880::/56"},
        {"prefix": "fd00:1::/48"},
        {"peer": {"endpoint": "example.org:51820", "public_key": KEY}},
        {"peer": {"endpoint": "198.51.100.7:51820", "public_key": "nope"}},
        {"mtu": 1500},
    ],
)
def test_site_block_is_checked(agent, bad):
    agent.SITE.write_text(json.dumps({"exit_nodes": ["carrel01"], "ipv6": dict(SITE6, **bad)}))
    with pytest.raises(ValueError):
        agent.site_ipv6()


def test_machine_without_opt_in_keeps_its_ipv4_rules(agent):
    # A site with IPv6 changes nothing for a machine that did not ask for it.
    assert agent.guest_firewall(machine(), STATE, CONFIG) == (GOLDEN / "guest-firewall-tenant.fw").read_text()
    assert agent.machine_ipv6(machine(), agent.site_ipv6()) is None


def test_opted_in_machine_rules(agent):
    rules = agent.guest_firewall(machine(ipv6=True), STATE, CONFIG).splitlines()
    assert "ndp: 1" in rules and "radv: 0" in rules
    ipset = rules[rules.index("[IPSET ipfilter-net0]") + 1 : rules.index("[RULES]")]
    assert {"10.200.17.11", "2a14:7581:880:17::11", "fe80::/64", "::"} <= set(ipset)
    assert "OUT DROP -dest ::/0" not in rules and "IN DROP -source ::/0" not in rules
    own, site = (
        rules.index("OUT ACCEPT -dest 2a14:7581:880:17::/64"),
        rules.index("OUT DROP -dest 2a14:7581:880::/48"),
    )
    assert rules.index("OUT DROP -dest 2a14:7581:880:17::1") < own < site
    assert "IN ACCEPT -source 2a14:7581:880:17::/64" in rules
    for block in ("fc00::/7", "fe80::/10", "ff00::/8"):
        assert f"OUT DROP -dest {block}" in rules
    assert "IN ACCEPT -source ::/0 -p tcp -dport 22" in rules
    # Restricted: no tenant-wide IPv6 inbound either.
    restricted = agent.guest_firewall(
        machine(ipv6=True, network_access="restricted"), STATE, CONFIG
    ).splitlines()
    assert "IN ACCEPT -source 2a14:7581:880:17::/64" not in restricted


def test_network_file_and_container_options(agent):
    files = {}
    agent.write = lambda path, data, mode=0o640: files.update({path: data})
    name = agent.network_file(machine(ipv6=True))
    primary = json.loads(files["/var/lib/vz/snippets/" + name])["ethernets"]["primary"]
    assert primary["addresses"] == ["10.200.17.11/24", "2a14:7581:880:17::11/64"]
    assert {"to": "::/0", "via": "2a14:7581:880:17::1"} in primary["routes"]
    assert primary["accept-ra"] is False
    assert agent.ct_ipv6(machine(ipv6=True)) == ",ip6=2a14:7581:880:17::11/64,gw6=2a14:7581:880:17::1"
    assert agent.ct_ipv6(machine()) == ""


def test_tunnel_filter(agent):
    empty = agent.v6_nft(agent.site_ipv6(), [])
    assert "{  }" not in empty and 'iifname "wg-v6" counter drop' in empty
    rules = agent.v6_nft(agent.site_ipv6(), ["2a14:7581:880:17::11"])
    lines = [x.strip() for x in rules.splitlines()]
    assert lines.index('iifname "wg-v6" ip6 saddr 2a14:7581:880::/48 counter drop') < lines.index(
        'iifname "wg-v6" ip6 daddr { 2a14:7581:880:17::11 } accept'
    )
    assert 'oifname "wg-v6" ip6 saddr { 2a14:7581:880:17::11 } accept' in lines


def test_tunnel_removed_off_the_exit_node(agent, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(agent, "run", lambda *a, **k: calls.append(a) or "")
    monkeypatch.setattr(agent, "public_ingress", lambda: None)
    assert agent.ipv6({"machines": []}, agent.site_ipv6()) == {}
    assert not any(c[:2] == ("ip", "link") and "add" in c for c in calls)


def test_host_rules_with_ipv6():
    n = load("install-network.py")
    nft = n.tenant_host_nft(n.underlay_rules("vmbr0", "192.168.19.101", []), ipv6=True)
    lines = [x.strip() for x in nft.splitlines()]
    nd = next(i for i, x in enumerate(lines) if "nd-neighbor-solicit" in x)
    drop = next(
        i for i, x in enumerate(lines) if x.startswith('iifname { "t0*"') and x.endswith("counter drop")
    )
    assert nd < drop
    assert any("maxseg size set 1360" in x and "ipv6" in x for x in lines)
    assert any(x.startswith("meta nfproto ipv6 iifname != {") for x in lines)
    # The IPv4 clamp line is unchanged.
    assert "tcp flags syn / syn,rst tcp option maxseg size > 1410 tcp option maxseg size set 1410" in lines


def test_site_check_in_installer():
    n = load("install-network.py")
    assert n.site_ipv6({}) is None
    assert n.site_ipv6({"ipv6": SITE6})["mtu"] == 1420
    with pytest.raises(SystemExit):
        n.site_ipv6({"ipv6": dict(SITE6, prefix="2a14:7581:880::/64")})


def test_other_tenants_and_public_ssh(agent):
    rules = agent.guest_firewall(machine(ipv6=True), STATE, CONFIG).splitlines()
    own, rest = (
        rules.index("IN ACCEPT -source 2a14:7581:880:17::/64"),
        rules.index("IN DROP -source 2a14:7581:880::/48"),
    )
    grant = rules.index("IN ACCEPT -p tcp -dport 22")
    assert own < rest < grant
    no_ssh = agent.guest_firewall(machine(ipv6=True, public_ssh=False), STATE, CONFIG).splitlines()
    assert "IN ACCEPT -source ::/0 -p tcp -dport 22" not in no_ssh


def test_neighbour_advertisements_name_only_own_addresses(agent):
    assert agent.link_local("02:ca:11:00:00:0b") == "fe80::ca:11ff:fe00:b"
    nft = agent.nd_nft(
        [
            (machine(ipv6=True), "2a14:7581:880:17::11"),
            (machine(kind="ct", vmid=11711), "2a14:7581:880:17::12"),
        ]
    )
    lines = [x.strip() for x in nft.splitlines()]
    assert (
        'iifname "tap11710i0" icmpv6 type nd-neighbor-advert icmpv6 taddr { 2a14:7581:880:17::11, fe80::ca:11ff:fe00:b } accept'
        in lines
    )
    assert lines.index('iifname "tap11710i0" icmpv6 type nd-neighbor-advert counter drop') > 0
    assert 'iifname "veth11711i0" icmpv6 type nd-neighbor-advert counter drop' in lines
    assert "nd-neighbor-advert" not in agent.nd_nft([])


def watchdog_stubs(agent, monkeypatch, stamp_age, route=True, tunnel=True):
    """Stub wg and ip. Returns the calls, the state the stubs share, and a runner."""
    now = 1_000_000
    state = {"route": route, "age": stamp_age}
    calls = []

    def fake_run(*a, **k):
        calls.append(a)
        if a[0] == "wg":
            return f"PEER\t{now - state['age'] if state['age'] is not None else 0}"
        if a[:2] == ("ip", "-6") and a[2] == "route":
            if a[3] == "show":
                return "default dev wg-v6" if state["route"] else ""
            state["route"] = a[3] == "replace"
        return ""

    real = Path

    class Net:
        def exists(self):
            return tunnel

    monkeypatch.setattr(agent, "Path", lambda p: Net() if "/sys/class/net" in str(p) else real(p))
    return calls, state, lambda: agent.v6_watchdog(run=fake_run, now=lambda: now)


def test_watchdog_keeps_route_on_fresh_handshake(agent, monkeypatch):
    calls, state, go = watchdog_stubs(agent, monkeypatch, 10)
    assert go() == {"handshake": 10, "route": True}
    assert state["route"] and not any(c[3] in ("del", "replace") for c in calls if c[0] == "ip")


def test_watchdog_withdraws_then_restores(agent, monkeypatch):
    _, state, go = watchdog_stubs(agent, monkeypatch, 200)
    assert go() == {"handshake": 200, "route": False}
    assert not state["route"]
    state["age"] = 3
    assert go() == {"handshake": 3, "route": True}
    assert state["route"]


def test_watchdog_treats_no_handshake_as_stale(agent, monkeypatch):
    _, _, go = watchdog_stubs(agent, monkeypatch, None)
    assert go() == {"handshake": None, "route": False}


def test_watchdog_does_nothing_without_tunnel(agent, monkeypatch):
    calls, _, go = watchdog_stubs(agent, monkeypatch, 500, tunnel=False)
    assert go() is None
    assert calls == []


def test_watchdog_tolerates_a_route_already_withdrawn(agent, monkeypatch):
    # The vip-probe loop deleted the route between this caller's show and del.
    _, state, _ = watchdog_stubs(agent, monkeypatch, 200)

    def racing_run(*a, **k):
        if a[:4] == ("ip", "-6", "route", "del"):
            state["route"] = False
            raise agent.CommandFailure("ip -6 failed: RTNETLINK answers: No such process")
        if a[0] == "wg":
            return "PEER\t1"
        return "default dev wg-v6" if a[3] == "show" and state["route"] else ""

    assert agent.v6_watchdog(run=racing_run, now=lambda: 1_000_000) == {"handshake": 999_999, "route": False}


def test_watchdog_failure_keeps_key_and_port(agent, monkeypatch, tmp_path):
    keys = tmp_path / "wg"
    keys.mkdir()
    (keys / "v6.key").write_text("PRIVATE\n")
    monkeypatch.setattr(agent, "VPN_KEYS", keys)
    monkeypatch.setattr(agent, "write", lambda *a, **k: True)
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(agent, "run", lambda *a, **k: "PUBKEY" if a[:2] == ("wg", "pubkey") else "")

    def broken(*a, **k):
        raise agent.CommandFailure("ip -6 failed: busy")

    monkeypatch.setattr(agent, "v6_watchdog", broken)
    out = agent.ipv6_apply({"prefix": SITE6["prefix"], "mtu": 1420, **SITE6["peer"]}, [])
    assert out["public_key"] == "PUBKEY" and out["port"] == agent.V6_PORT
    assert out["watchdog_error"].startswith("CommandFailure")


def test_watchdog_rereads_handshake_before_deleting(agent, monkeypatch):
    # A handshake completes between the first sample and the delete.
    calls, _, _ = watchdog_stubs(agent, monkeypatch, 200)
    ages = iter([200, 2])

    def run(*a, **k):
        calls.append(a)
        if a[0] == "wg":
            return f"PEER\t{1_000_000 - next(ages)}"
        return "default dev wg-v6" if a[3] == "show" else ""

    assert agent.v6_watchdog(run=run, now=lambda: 1_000_000) == {"handshake": 2, "route": True}
    assert not any(c[:4] == ("ip", "-6", "route", "del") for c in calls)


def test_apply_installs_unreachable_default(agent, monkeypatch, tmp_path):
    keys = tmp_path / "wg"
    keys.mkdir()
    (keys / "v6.key").write_text("PRIVATE\n")
    monkeypatch.setattr(agent, "VPN_KEYS", keys)
    monkeypatch.setattr(agent, "write", lambda *a, **k: True)
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(agent, "v6_watchdog", lambda: None)
    calls = []
    monkeypatch.setattr(agent, "run", lambda *a, **k: calls.append(a) or "")
    agent.ipv6_apply({"prefix": SITE6["prefix"], "mtu": 1420, **SITE6["peer"]}, [])
    want = ("ip", "-6", "route", "replace", "vrf", "vrf_tenants", "unreachable", "default", "metric", "4278198272")
    assert want in calls
