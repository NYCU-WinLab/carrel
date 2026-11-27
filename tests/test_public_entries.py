import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "node-agent.py"
EDGE = "140.113.194.229/32"


def load():
    spec = importlib.util.spec_from_file_location("node_agent_public_entries", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rules(config):
    m = {
        "tenant_n": 3,
        "vmid": 10301,
        "host": 11,
        "name": "app",
        "kind": "vm",
        "ip": "10.200.3.11",
        "mac": "02:ca:00:00:03:0b",
    }
    state = {"peers": [], "ports": [], "domains": [], "machines": [m]}
    return load().guest_firewall(m, state, config).splitlines()


def test_public_entry_is_accepted_before_the_protected_drop():
    lines = rules({"protected_addresses": [EDGE], "public_entries": [{"address": EDGE, "port": 443}]})
    accept = lines.index(f"OUT ACCEPT -dest {EDGE} -p tcp -dport 443")
    assert accept < lines.index(f"OUT DROP -dest {EDGE}")


def test_only_the_listed_port_is_opened_on_a_protected_host():
    lines = rules({"protected_addresses": [EDGE], "public_entries": [{"address": EDGE, "port": 443}]})
    # 443 and the tenant public port block (issue #28), nothing else.
    opened = [line for line in lines if line.startswith("OUT ACCEPT") and EDGE in line]
    assert opened == [
        f"OUT ACCEPT -dest {EDGE} -p tcp -dport 443",
        f"OUT ACCEPT -dest {EDGE} -p tcp -dport 20010:22549",
        f"OUT ACCEPT -dest {EDGE} -p udp -dport 20010:22549",
    ]


def test_no_public_entries_keeps_the_host_fully_protected():
    lines = rules({"protected_addresses": [EDGE]})
    assert not any(line.startswith("OUT ACCEPT") and EDGE in line for line in lines)
    assert f"OUT DROP -dest {EDGE}" in lines


def test_a_public_entry_must_be_a_protected_public_host():
    # Issue #28: a private range, a wider prefix or an unlisted host is refused.
    for entry in ["10.0.0.0/8", "140.113.194.0/24", "140.113.60.184/32", "192.168.19.101/32"]:
        try:
            rules(
                {
                    "protected_addresses": [EDGE, "192.168.19.101/32"],
                    "public_entries": [{"address": entry, "port": 443}],
                }
            )
        except ValueError:
            continue
        raise AssertionError(f"accepted {entry}")


def test_tenants_reach_every_tenant_public_port():
    lines = rules({"protected_addresses": [EDGE], "public_entries": [{"address": EDGE, "port": 443}]})
    drop = lines.index(f"OUT DROP -dest {EDGE}")
    for proto in ("tcp", "udp"):
        assert lines.index(f"OUT ACCEPT -dest {EDGE} -p {proto} -dport 20010:22549") < drop


def staging_rules(tmp_path, entry, public="198.18.61.10/24"):
    module = load()
    site = tmp_path / "site.json"
    if public is not None:
        site.write_text(
            public
            if isinstance(public, str) and public.startswith("{")
            else json.dumps({"public": {"address": public}})
        )
    module.SITE = site
    m = {
        "tenant_n": 3,
        "vmid": 10301,
        "host": 11,
        "name": "app",
        "kind": "vm",
        "ip": "10.200.3.11",
        "mac": "02:ca:00:00:03:0b",
    }
    state = {"peers": [], "ports": [], "domains": [], "machines": [m]}
    config = {
        "protected_addresses": [entry, "198.18.61.10/32"],
        "public_entries": [{"address": entry, "port": 443}],
    }
    return module.guest_firewall(m, state, config).splitlines()


def test_the_site_public_address_is_an_entry_in_a_benchmark_range(tmp_path):
    # Staging's simulated public network is 198.18.0.0/15, which is not global.
    lines = staging_rules(tmp_path, "198.18.61.10/32")
    assert "OUT ACCEPT -dest 198.18.61.10/32 -p tcp -dport 443" in lines


def test_another_non_global_entry_is_still_refused(tmp_path):
    # Only the site's own address is exempt: a second benchmark or private host is not.
    for entry in ["198.18.61.20/32", "192.168.19.101/32"]:
        try:
            staging_rules(tmp_path, entry)
        except ValueError:
            continue
        raise AssertionError(f"accepted {entry}")


def test_a_bad_site_file_grants_no_exemption(tmp_path):
    # Missing file, a number, a wrong type or a bad string: the staging entry is refused.
    for public in [None, 3323084042, "not-an-address", '{"public": "x"}', "{broken"]:
        try:
            staging_rules(tmp_path, "198.18.61.10/32", public)
        except ValueError:
            continue
        raise AssertionError(f"accepted with site public {public!r}")


def test_a_bad_site_file_still_renders_global_entries(tmp_path):
    # Production keeps its firewall when site.json is malformed.
    # A file that is not JSON already stops site_ipv6(), before and after this change.
    for public in ["not-an-address", 7, {"address": 1}]:
        lines = staging_rules(tmp_path, EDGE, public)
        assert f"OUT ACCEPT -dest {EDGE} -p tcp -dport 443" in lines
