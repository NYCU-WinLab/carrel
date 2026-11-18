"""A site without an ipv6 block must produce exactly what it did before IPv6 support (issue #142).

The golden files were generated from main before the IPv6 change; regenerate them only for a
deliberate IPv4 change, never to make an IPv6 change pass.
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = Path(__file__).resolve().parent / "golden"
KEY = "ssh-ed25519 " + "A" * 44


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_").replace(".py", ""), ROOT / "scripts" / name
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def machine(**kw):
    m = {
        "tenant_n": 17,
        "vmid": 11710,
        "host": 11,
        "name": "app",
        "kind": "vm",
        "ip": "10.200.17.11",
        "mac": "02:ca:11:00:00:0b",
        "image": "debian-13",
        "cpu": 1,
        "memory_mb": 1024,
        "disk_gb": 10,
        "ssh_keys": [KEY],
        "nics": [],
        "readiness_token": "test-only",
    }
    m.update(kw)
    return m


STATE = {
    "peers": [
        {"source": "10.200.17.11/32", "target": "10.200.17.12", "port": 5432, "proto": "tcp"},
        {"source": "10.200.3.0/24", "target": "10.200.17.11", "port": 8080, "proto": "udp"},
    ],
    "ports": [
        {"vmid": 11710, "port": 22, "proto": "tcp", "public_port": 22011},
        {"vmid": 11711, "port": 25565, "proto": "tcp", "public_port": 25565, "special": True},
    ],
    "domains": [{"vmid": 11710, "target_port": 3000, "delegated": True}],
    "vips": [],
}
CONFIG = {
    "protected_addresses": ["192.168.19.101/32", "140.113.60.184/32", "140.113.194.229/32"],
    "public_entries": [
        {"address": "140.113.60.184/32", "port": 443},
        {"address": "140.113.194.229/32", "port": 443},
    ],
}

CASES = {
    "guest-firewall-tenant.fw": lambda a, _n: a.guest_firewall(machine(), STATE, CONFIG),
    "guest-firewall-restricted.fw": lambda a, _n: a.guest_firewall(
        machine(network_access="restricted", service_ports=[80, 443]), STATE, CONFIG
    ),
    "tenant-host.nft": lambda _a, n: n.tenant_host_nft(
        n.underlay_rules("vmbr0", "192.168.19.101", ["192.168.19.102", "192.168.19.103"])
    ),
    "public.nft": lambda _a, n: n.public_nft("vmbr0.60", "140.113.60.184"),
    "public-interface": lambda _a, n: n.public_interface(
        "vmbr0.60", "140.113.60.184/27", "140.113.60.190", "140.113.60.184"
    ),
}


def network_file(agent, monkeypatch):
    files = {}
    monkeypatch.setattr(agent, "write", lambda path, data, mode=0o640: files.update({path: data}))
    name = agent.network_file(machine())
    return name + "\n" + files["/var/lib/vz/snippets/" + name] + "\n"


@pytest.mark.parametrize("name", sorted(CASES))
def test_unchanged_without_ipv6(name):
    got = CASES[name](load("node-agent.py"), load("install-network.py"))
    assert got == (GOLDEN / name).read_text()


def test_network_file_unchanged_without_ipv6(monkeypatch):
    assert network_file(load("node-agent.py"), monkeypatch) == (GOLDEN / "network-file.json").read_text()


if __name__ == "__main__":
    # python3 tests/test_ipv6_off_golden.py: write the golden files from the current code.
    GOLDEN.mkdir(exist_ok=True)
    a, n = load("node-agent.py"), load("install-network.py")
    for name, make in CASES.items():
        (GOLDEN / name).write_text(make(a, n))
    files = {}
    a.write = lambda path, data, mode=0o640: files.update({path: data})
    nm = a.network_file(machine())
    (GOLDEN / "network-file.json").write_text(nm + "\n" + files["/var/lib/vz/snippets/" + nm] + "\n")
