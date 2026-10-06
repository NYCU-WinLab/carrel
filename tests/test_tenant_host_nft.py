import importlib.util
import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-network.py"


def load():
    spec = importlib.util.spec_from_file_location("install_network", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dropped_ifaces(nft):
    # The patterns of the input chain's catch-all `iifname { ... } counter drop` rule.
    line = next(
        x
        for x in nft.splitlines()
        if x.strip().startswith("iifname {") and x.strip().endswith("counter drop")
    )
    return re.findall(r'"([^"]+)"', line)


def matches(pattern, name):
    # nft interface wildcards: a trailing * matches any suffix, nothing else is special.
    return name.startswith(pattern[:-1]) if pattern.endswith("*") else name == pattern


@pytest.mark.parametrize("name", ["t001", "t008", "t999", "t1000", "tap10300i0", "tap190i0"])
def test_tenant_interfaces_are_dropped(name):
    patterns = dropped_ifaces(load().TENANT_HOST_NFT)
    assert any(matches(p, name) for p in patterns)


@pytest.mark.parametrize("name", ["tailscale0", "tun0", "team0", "vmbr0", "wg-carrel", "vts0"])
def test_host_interfaces_starting_with_t_are_not_dropped(name):
    patterns = dropped_ifaces(load().TENANT_HOST_NFT)
    assert not any(matches(p, name) for p in patterns)


def test_dhcp_accept_covers_the_same_interfaces():
    nft = load().TENANT_HOST_NFT
    dhcp = next(x for x in nft.splitlines() if "dport 67 accept" in x and x.strip().startswith("iifname"))
    assert set(dropped_ifaces(nft)) | {"vrf_tenants"} == set(re.findall(r'"([^"]+)"', dhcp))
