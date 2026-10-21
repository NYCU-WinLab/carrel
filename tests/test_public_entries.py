import importlib.util
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
    opened = [line for line in lines if line.startswith("OUT ACCEPT") and EDGE in line]
    assert opened == [f"OUT ACCEPT -dest {EDGE} -p tcp -dport 443"]


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
