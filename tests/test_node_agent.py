"""node-agent and its helpers, without a live node: PVE reads and commands are replaced."""

import fcntl
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

KEY = "ssh-ed25519 " + "A" * 44
MACHINE = {
    "tenant_n": 1,
    "vmid": 10100,
    "host": 10,
    "name": "linked",
    "kind": "vm",
    "ip": "10.200.1.10",
    "mac": "02:ca:01:00:00:01",
    "image": "debian-13",
    "cpu": 1,
    "memory_mb": 1024,
    "disk_gb": 10,
    "ssh_keys": [KEY],
    "nics": [],
    "readiness_token": "test-only",
}


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), Path(__file__).parents[1] / "scripts" / name
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cloud_init_matches_all_managed_macs_without_configuring_raw_nics(monkeypatch):
    root = Path(__file__).parents[1]
    spec = importlib.util.spec_from_file_location("node_agent", root / "scripts/node-agent.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files = {}
    monkeypatch.setattr(module, "write", lambda path, data, mode: files.update({path: data}))
    monkeypatch.setattr(
        module,
        "Path",
        lambda path: (
            root / "scripts/guest-report.py"
            if path == "/usr/local/lib/carrel/guest-report.py"
            else Path(path)
        ),
    )
    module.cloud_init(
        {
            "name": "network-check",
            "vmid": 10503,
            "tenant_n": 5,
            "host": 13,
            "mac": "02:ca:05:03:00:01",
            "ip": "10.200.5.13",
            "ssh_keys": [KEY],
            "readiness_token": "test-only",
            "swap_mb": 0,
        }
    )
    config = json.loads(files["/var/lib/vz/snippets/carrel-10503-user.json"].split("\n", 1)[1])
    private = next(
        f["content"]
        for f in config["write_files"]
        if f["path"] == "/etc/systemd/network/20-carrel-private.network"
    )
    macs = next(
        line.split("=", 1)[1].split() for line in private.splitlines() if line.startswith("MACAddress=")
    )
    assert macs == [f"02:cb:05:03:{i:02x}:01" for i in range(1, 8)]
    assert "UseRoutes=no" in private and "UseDNS=no" in private
    network = json.loads(files["/var/lib/vz/snippets/carrel-10503-network.json"])
    assert list(network["ethernets"]) == ["primary"]
    assert network["ethernets"]["primary"]["match"]["macaddress"] == "02:ca:05:03:00:01"


@pytest.mark.parametrize("with_config", [True, False])
def test_private_network_cleanup_removes_veth_before_namespace(monkeypatch, tmp_path, with_config):
    spec = importlib.util.spec_from_file_location(
        "node_agent", Path(__file__).parents[1] / "scripts/node-agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def local(path):
        path = Path(path)
        return path if path.is_relative_to(tmp_path) else tmp_path / str(path).lstrip("/")

    monkeypatch.setattr(module, "Path", local)
    monkeypatch.setattr(module, "STATE", local("/var/lib/carrel"))
    files = ["/run/netns/carrel-p00101", "/sys/class/net/dp00101", "/var/lib/carrel/p00101.leases"]
    if with_config:
        files.append("/etc/carrel/private-p00101.conf")
    for path in files:
        local(path).parent.mkdir(parents=True, exist_ok=True)
        local(path).touch()

    def run(*args):
        if args[:3] == ("ip", "link", "delete"):
            local("/sys/class/net/" + args[3]).unlink()
        if args[:3] == ("ip", "netns", "delete"):
            # A real namespace teardown also removes its veth peer asynchronously.
            assert not local("/sys/class/net/dp00101").exists()
            local("/run/netns/" + args[3]).unlink()

    monkeypatch.setattr(module, "run", run)
    module.private_dhcp({"networks": [], "machines": []})
    assert all(not local(path).exists() for path in files)


@pytest.mark.parametrize("mismatch", [None, "manifest", "description"])
def test_partial_clone_cleanup_requires_matching_allocation_marker(monkeypatch, tmp_path, mismatch):
    spec = importlib.util.spec_from_file_location(
        "node_agent", Path(__file__).parents[1] / "scripts/node-agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "STATE", tmp_path)
    machine = {
        "vmid": 10100,
        "tenant_n": 1,
        "host": 10,
        "ip": "10.200.1.10",
        "mac": "02:ca:01:00:00:01",
        "name": "partial",
        "kind": "vm",
        "readiness_token": "test-only",
    }
    marker = module.provision_marker(machine)
    (tmp_path / "create-10100.json").write_text(
        json.dumps(
            {
                "marker": "other" if mismatch == "manifest" else marker,
                "complete": False,
            }
        )
    )
    config = {"description": "other" if mismatch == "description" else marker}
    monkeypatch.setattr(module, "pve_get", lambda *args: config)
    with pytest.raises(ValueError, match="unowned"):
        module.owned(machine)
    if mismatch:
        with pytest.raises(ValueError, match="unowned"):
            module.owned(machine, allow_provisioning=True)
    else:
        assert module.owned(machine, allow_provisioning=True) == config


@pytest.mark.parametrize("prepared,packages", [(False, []), (True, []), (True, ["nginx"])])
def test_template_preparation_preserves_requested_package_install(monkeypatch, prepared, packages):
    spec = importlib.util.spec_from_file_location(
        "node_agent", Path(__file__).parents[1] / "scripts/node-agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files = {}
    monkeypatch.setattr(module, "write", lambda path, data, mode: files.update({path: data}))
    module.cloud_init(
        {
            "name": "fresh",
            "vmid": 10100,
            "tenant_n": 1,
            "mac": "02:ca:01:00:00:01",
            "ip": "10.200.1.10",
            "ssh_keys": [KEY],
            "packages": packages,
        },
        prepared=prepared,
    )
    data = json.loads(files["/var/lib/vz/snippets/carrel-10100-user.json"].split("\n", 1)[1])
    assert data["package_update"] is (bool(packages) or not prepared)
    assert (
        data.get("packages", [])
        == ([] if prepared else ["qemu-guest-agent", "unattended-upgrades"]) + packages
    )
    assert ("packages" in data) is (bool(packages) or not prepared)
    assert "guest-exec" in data["write_files"][0]["content"]
    assert data["swap"]["size"] == "1024M"
    assert data["users"][0].get("groups", []) == (["docker"] if prepared else [])


@pytest.mark.parametrize("immutable", [True, False])
def test_linked_clone_requires_immutable_template(monkeypatch, tmp_path, immutable):
    machine = dict(MACHINE)
    module = load("node-agent.py")
    (tmp_path / "node.json").write_text(json.dumps({"storage": "local-zfs", "protected_addresses": []}))
    monkeypatch.setattr(module, "CONFIG", tmp_path / "node.json")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "vm_template", lambda image: {"vmid": 9010, "prepared": True})
    monkeypatch.setattr(
        module, "pve_get", lambda *args: {"template": int(immutable), "scsi0": "local-zfs:base-9010-disk-0"}
    )
    monkeypatch.setattr(
        module, "cloud_init", lambda m, **kwargs: "prepared-snippet" if kwargs["prepared"] else "legacy"
    )
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args) or "stopped")
    real_write = module.write
    monkeypatch.setattr(
        module,
        "write",
        lambda path, data, mode=0o640: (
            calls.append(("write", str(path)))
            or (None if str(path).startswith("/etc/pve/") else real_write(path, data, mode))
        ),
    )
    if immutable:
        assert module.create(machine)["state"] == "running"
        clone = next(c for c in calls if c[:2] == ("qm", "clone"))
        assert clone[2] == 9010 and clone[clone.index("--full") + 1] == "0"
        # qm clone dropped the reconcile's firewall file: it is back before the first start.
        firewall = calls.index(("write", "/etc/pve/firewall/10100.fw"))
        assert calls.index(clone) < firewall < calls.index(("qm", "start", 10100))
        manifest = json.loads((tmp_path / f"create-{machine['vmid']}.json").read_text())
        assert manifest["template"] == {"vmid": 9010, "prepared": True}
    else:
        with pytest.raises(ValueError, match="immutable"):
            module.create(machine)
        assert not [c for c in calls if c[0] != "write"]


@pytest.mark.parametrize("disk", ["local-zfs:base-9010-disk-0", "local-lvm:base-9010-disk-0"])
def test_linked_clone_template_must_live_on_the_configured_storage(monkeypatch, tmp_path, disk):
    machine = dict(MACHINE)
    spec = importlib.util.spec_from_file_location(
        "node_agent", Path(__file__).parents[1] / "scripts/node-agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "node.json").write_text(json.dumps({"storage": "local-zfs", "protected_addresses": []}))
    monkeypatch.setattr(module, "CONFIG", tmp_path / "node.json")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "vm_template", lambda image: {"vmid": 9010, "prepared": True})
    monkeypatch.setattr(module, "pve_get", lambda *args: {"template": 1, "scsi0": disk})
    monkeypatch.setattr(module, "cloud_init", lambda m, **kwargs: "prepared-snippet")
    calls = []
    monkeypatch.setattr(module, "first_firewall", lambda m: None)
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args) or "stopped")
    if disk.startswith("local-zfs:"):
        assert module.create(machine)["state"] == "running"
        assert any(c[:2] == ("qm", "clone") for c in calls)
    else:
        with pytest.raises(ValueError, match="guest storage"):
            module.create(machine)
        assert not calls


def test_topology_snapshot_tracks_new_vnets_without_duplicate_creates(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "node_agent", Path(__file__).parents[1] / "scripts/node-agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "api", lambda *args, **kwargs: calls.append((args, kwargs)))
    existing = [{"vnet": "t001", "zone": "tenants"}]
    assert not module.ensure("/cluster/sdn/vnets", "vnet", "t001", existing=existing, zone="tenants")
    assert module.ensure("/cluster/sdn/vnets", "vnet", "t002", existing=existing, zone="tenants")
    assert not module.ensure("/cluster/sdn/vnets", "vnet", "t002", existing=existing, zone="tenants")
    assert len(calls) == 1 and calls[0][0][0] == "create"
    assert existing[-1] == {"vnet": "t002", "zone": "tenants"}


def test_firewall_enforces_only_the_declared_source_protocol_and_port():
    module = load("node-agent.py")
    app = dict(MACHINE, name="app", vmid=10100, host=10, ip="10.200.1.10")
    db = dict(MACHINE, name="db", vmid=10101, host=11, ip="10.200.1.11", network_access="restricted")
    state = {
        "peers": [{"source": "10.200.1.10/32", "target": "10.200.1.11", "port": 5432, "proto": "tcp"}],
        "ports": [],
        "domains": [],
    }
    rules = module.guest_firewall(db, state, {"protected_addresses": []}).splitlines()
    assert "IN ACCEPT -source 10.200.1.10/32 -p tcp -dport 5432" in rules
    assert "policy_in: DROP" in rules
    assert "IN ACCEPT -source 10.200.1.0/24" not in rules
    assert "dhcp: 0" in rules
    assert not any("-p udp -dport 5432" in r for r in rules)
    # The source side may send to the granted port; a tenant machine accepts its tenant.
    sender = module.guest_firewall(app, state, {"protected_addresses": []}).splitlines()
    assert "OUT ACCEPT -dest 10.200.1.11 -p tcp -dport 5432" in sender
    assert "IN ACCEPT -source 10.200.1.0/24" in sender
    # Private NICs run with firewall=0: the rules for net0 do not change (issue #75).
    with_nic = module.guest_firewall(dict(db, nics=[{"index": 1}]), state, {"protected_addresses": []})
    assert with_nic.splitlines() == rules


def test_a_virtual_address_joins_only_its_holders_ipfilter_set():
    module = load("node-agent.py")
    holder = dict(MACHINE, name="cp1", vmid=10100, host=10, ip="10.200.1.10", tenant_n=1)
    other = dict(MACHINE, name="worker", vmid=10101, host=11, ip="10.200.1.11", tenant_n=1)
    vip = {"name": "api", "address": "10.200.1.251", "tenant_n": 1, "vmids": [10100]}
    state = {"peers": [], "ports": [], "domains": [], "vips": [vip]}
    ipset = (
        module.guest_firewall(holder, state, {"protected_addresses": []})
        .split("[IPSET ipfilter-net0]\n")[1]
        .split("\n\n")[0]
    )
    assert ipset.splitlines() == ["10.200.1.10", "10.200.1.251", "0.0.0.0"]
    assert "10.200.1.251" not in module.guest_firewall(other, state, {"protected_addresses": []})
    # No grant can hand a holder another machine's address or another tenant's.
    for bad in ({"address": "10.200.1.11"}, {"address": "10.200.2.251"}, {"tenant_n": 2}):
        with pytest.raises(ValueError):
            module.guest_firewall(holder, dict(state, vips=[dict(vip, **bad)]), {"protected_addresses": []})


def test_a_port_or_domain_at_a_virtual_address_opens_on_every_holder():
    # Issue #146: the public entry follows the address, so each machine that
    # may hold it admits the port, and no other machine does.
    module = load("node-agent.py")
    cp1 = dict(MACHINE, name="cp1", vmid=10100, host=10, ip="10.200.1.10", tenant_n=1)
    cp2 = dict(MACHINE, name="cp2", vmid=10101, host=11, ip="10.200.1.11", tenant_n=1)
    worker = dict(MACHINE, name="worker", vmid=10102, host=12, ip="10.200.1.12", tenant_n=1)
    vip = {"id": "v1", "name": "api", "address": "10.200.1.251", "tenant_n": 1, "vmids": [10100, 10101]}
    port = {
        "tenant_n": 1,
        "vmid": 0,
        "vip": "v1",
        "ip": "10.200.1.251",
        "public_port": 20010,
        "port": 6443,
        "proto": "tcp",
    }
    domain = {"tenant_n": 1, "vmid": 0, "vip": "v1", "target_port": 3000}
    state = {"peers": [], "ports": [port], "domains": [domain], "vips": [vip]}
    for m in (cp1, cp2):
        rules = module.guest_firewall(m, state, {"protected_addresses": []}).splitlines()
        assert "IN ACCEPT -p tcp -dport 6443" in rules
        assert "IN ACCEPT -source 10.200.0.2 -p tcp -dport 3000" in rules
    rules = module.guest_firewall(worker, state, {"protected_addresses": []}).splitlines()
    assert "IN ACCEPT -p tcp -dport 6443" not in rules
    assert "IN ACCEPT -source 10.200.0.2 -p tcp -dport 3000" not in rules
    # A grant of another tenant naming the same id opens nothing.
    foreign = dict(state, ports=[dict(port, tenant_n=2)], domains=[])
    assert "-dport 6443" not in module.guest_firewall(cp1, foreign, {"protected_addresses": []})
    # The exit node DNATs to the virtual address, and only to .251 to .254.
    assert "tcp dport 20010 dnat to 10.200.1.251:6443" in module.ports_nft(
        {"ports": [port]}, "140.113.60.184"
    )
    for bad in ({"ip": "10.200.1.10"}, {"ip": "10.200.2.251"}):
        with pytest.raises(ValueError):
            module.ports_nft({"ports": [dict(port, **bad)]}, "140.113.60.184")
    with pytest.raises(ValueError):
        module.ports_nft({"ports": [dict(port, vip=None)]}, "140.113.60.184")


@pytest.mark.parametrize(
    "routes,ready",
    [
        ('[{"type":"unreachable","dst":"default","metric":4278198272}]', False),
        ("[]", False),
        (
            '[{"dst":"default","gateway":"192.168.19.101","dev":"vrfbr_tenants"},{"type":"unreachable","dst":"default"}]',
            True,
        ),
        ('[{"dst":"default","nexthops":[{"gateway":"192.168.19.101"},{"gateway":"192.168.19.102"}]}]', True),
    ],
)
def test_inventory_says_whether_the_node_routes_tenant_traffic(monkeypatch, tmp_path, routes, ready):
    module = load("node-agent.py")
    vrf = tmp_path / "vrf_tenants"
    vrf.mkdir()
    monkeypatch.setattr(module, "Path", lambda p: vrf if str(p) == "/sys/class/net/vrf_tenants" else Path(p))
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: routes)
    assert module.tenant_route() is ready
    # Before the first tenant there is no VRF yet: unknown, not a fault.
    vrf.rmdir()
    assert module.tenant_route() is None


def test_vip_probe_touches_only_this_nodes_entries_of_registered_vips():
    module = load("node-agent.py")
    state = {"vips": [{"address": "10.200.3.251", "tenant_n": 3, "vmids": [1]}]}
    targets = module.vip_targets(state)
    assert targets == [{"address": "10.200.3.251", "dev": "t003"}]
    with pytest.raises(ValueError):
        module.vip_targets({"vips": [{"address": "10.200.3.12", "tenant_n": 3}]})
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        return json.dumps(entries) if args[1] == "-j" else ""

    for entries, probed in [
        ([{"dst": "10.200.3.251", "lladdr": "02:ca:03:04:00:01", "state": ["STALE"]}], True),
        ([{"dst": "10.200.3.251", "lladdr": "02:ca:03:04:00:01", "state": ["REACHABLE"]}], True),
        (
            [
                {
                    "dst": "10.200.3.251",
                    "lladdr": "02:ca:03:04:00:01",
                    "state": ["NOARP"],
                    "flags": ["extern_learn"],
                }
            ],
            False,
        ),
        ([{"dst": "10.200.3.251", "lladdr": "02:ca:03:04:00:01", "state": ["PROBE"]}], False),
        ([{"dst": "10.200.3.251", "state": ["FAILED"]}], False),
        ([], False),
    ]:
        calls.clear()
        assert bool(module.vip_probe_once(targets, run=run)) == probed
        if probed:
            assert calls[-1] == (
                "ip",
                "neigh",
                "change",
                "10.200.3.251",
                "dev",
                "t003",
                "lladdr",
                "02:ca:03:04:00:01",
                "nud",
                "probe",
            )


def test_cloud_init_files_are_read_whole_and_only_missing_ones_written_back(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "SNIPPETS", tmp_path)
    vm = dict(MACHINE, vmid=10100, kind="vm")
    assert module.cloud_init_files(vm) == {}
    (tmp_path / "carrel-10100-user.json").write_text("#cloud-config\n{}")
    (tmp_path / "carrel-10100-network.json").write_text('{"version": 2}')
    files = module.cloud_init_files(vm)["cloud_init"]
    assert files == {"user": "#cloud-config\n{}", "network": '{"version": 2}'}
    assert module.cloud_init_files(dict(vm, kind="ct")) == {}
    # The node's own copy is what the VM booted with: never replaced.
    module.restore_cloud_init(vm, {"user": "other", "network": "other"})
    assert (tmp_path / "carrel-10100-user.json").read_text() == "#cloud-config\n{}"
    (tmp_path / "carrel-10100-user.json").unlink()
    (tmp_path / "carrel-10100-network.json").unlink()
    module.restore_cloud_init(vm, files)
    assert module.cloud_init_files(vm)["cloud_init"] == files
    assert oct((tmp_path / "carrel-10100-user.json").stat().st_mode & 0o777) == "0o600"
    with pytest.raises(ValueError):
        module.restore_cloud_init(dict(vm, vmid=10101), {"user": None, "network": "x"})
    # Files already in place are not even checked, however large the copy.
    module.restore_cloud_init(vm, {"user": "x" * 5_000_000, "network": None})


def test_migrate_reports_a_cleanup_failure_after_cutover_as_a_warning(monkeypatch, tmp_path):
    module = load("node-agent.py")
    vm = dict(MACHINE, vmid=10100, kind="vm")
    nodes = tmp_path / "nodes"
    for n in ("carrel01", "carrel02"):
        (nodes / n / "qemu-server").mkdir(parents=True)
    conf = nodes / "carrel01" / "qemu-server" / "10100.conf"
    conf.write_text("x")
    monkeypatch.setattr(module, "PVE_NODES", nodes)
    monkeypatch.setattr(module, "NODE", "carrel01")
    monkeypatch.setattr(module, "storage_id", lambda: "local-zfs")
    monkeypatch.setattr(
        module, "owned", lambda m, node=None, **k: {"scsi0": "local-zfs:vm-10100-disk-0,size=10G"}
    )
    moves = [True]

    def run(*args, **kwargs):
        if args[:2] == ("qm", "migrate"):
            if moves[0]:
                conf.rename(nodes / "carrel02" / "qemu-server" / "10100.conf")
            raise module.CommandFailure("qm migrate failed: could not remove the old disk")
        return "status: running"

    monkeypatch.setattr(module, "run", run)
    logged = []
    monkeypatch.setattr(module, "log_warning", logged.append)
    status = {"status": "running"}
    monkeypatch.setattr(module, "pve_get", lambda path: status)
    out = module.migrate({"machine": vm, "target": "carrel02"})
    assert out["state"] == "moved" and "copy of its disk may remain on carrel01" in out["warning"]
    # The Proxmox output goes to the journal only, never to the tenant.
    assert "did not run again" not in out["warning"] and "old disk" not in out["warning"]
    assert len(logged) == 1 and "old disk" in logged[0]
    # A machine that ran before the move and does not run on the target says so.
    nodes.joinpath("carrel02", "qemu-server", "10100.conf").rename(conf)
    status["status"] = "stopped"
    out = module.migrate({"machine": vm, "target": "carrel02"})
    assert out["warning"].startswith("The machine did not run again on carrel02.") and len(logged) == 2
    # A failure before the cutover, with the machine still here, stays an error.
    nodes.joinpath("carrel02", "qemu-server", "10100.conf").rename(conf)
    moves[0] = False
    with pytest.raises(module.CommandFailure):
        module.migrate({"machine": vm, "target": "carrel02"})


def test_migrate_unlinks_a_linked_clone_through_shared_storage_and_is_idempotent(monkeypatch, tmp_path):
    module = load("node-agent.py")
    vm = dict(MACHINE, vmid=10100, kind="vm")
    nodes = tmp_path / "nodes"
    for n in ("carrel01", "carrel02"):
        (nodes / n / "qemu-server").mkdir(parents=True)
    conf = nodes / "carrel01" / "qemu-server" / "10100.conf"
    conf.write_text("x")
    monkeypatch.setattr(module, "PVE_NODES", nodes)
    monkeypatch.setattr(module, "NODE", "carrel01")
    monkeypatch.setattr(module, "storage_id", lambda: "local-zfs")
    monkeypatch.setattr(module, "content_storage", lambda kind: "shared")
    monkeypatch.setattr(module, "storage_entry", lambda s: {"type": "nfs", "content": "images,iso"})
    cfg = {"scsi0": "local-zfs:base-9010-disk-0/vm-10100-disk-0,size=10G"}
    monkeypatch.setattr(module, "owned", lambda m, node=None, **k: cfg)
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("qm", "migrate"):
            conf.rename(nodes / "carrel02" / "qemu-server" / "10100.conf")
        return "status: running" if args[1] == "status" else ""

    monkeypatch.setattr(module, "run", run)
    assert module.migrate({"machine": vm, "target": "carrel02", "bwlimit": 51200}) == {"state": "moved"}
    assert calls[1] == (
        "qm",
        "disk",
        "move",
        10100,
        "scsi0",
        "shared",
        "--format",
        "qcow2",
        "--delete",
        "1",
        "--bwlimit",
        51200,
    )
    assert calls[2] == (
        "qm",
        "migrate",
        10100,
        "carrel02",
        "--with-local-disks",
        "--bwlimit",
        51200,
        "--online",
    )
    # A move that stopped after the disk reached the shared storage resumes
    # with the migration, not a second disk move.
    nodes.joinpath("carrel02", "qemu-server", "10100.conf").rename(conf)
    cfg["scsi0"] = "shared:10100/vm-10100-disk-0.qcow2,size=10G"
    calls.clear()
    module.migrate({"machine": vm, "target": "carrel02"})
    assert [c[:2] for c in calls] == [("qm", "status"), ("qm", "migrate")]
    # A retry after the move does nothing.
    calls.clear()
    assert module.migrate({"machine": vm, "target": "carrel02"}) == {"state": "moved"} and calls == []
    with pytest.raises(ValueError):
        module.migrate({"machine": vm, "target": "../etc"})
    # On the target, the disk goes back to the guest storage.
    monkeypatch.setattr(module, "NODE", "carrel02")
    cfg["scsi0"] = "shared:10100/vm-10100-disk-0.qcow2,size=10G"
    assert module.migrate_finish({"machine": vm}) == {"state": "done"}
    assert calls[-1] == (
        "qm",
        "disk",
        "move",
        10100,
        "scsi0",
        "local-zfs",
        "--delete",
        "1",
        "--bwlimit",
        51200,
    )
    # The old node removes its copy of the cloud-init files only once the VM left.
    monkeypatch.setattr(module, "SNIPPETS", tmp_path)
    (tmp_path / "carrel-10100-user.json").write_text("u")
    (tmp_path / "carrel-10100-vendor.json").write_text("v")
    monkeypatch.setattr(module, "NODE", "carrel01")
    module.cloud_init_remove({"machine": vm})
    assert not (tmp_path / "carrel-10100-user.json").exists()
    assert not (tmp_path / "carrel-10100-vendor.json").exists()
    monkeypatch.setattr(module, "NODE", "carrel02")
    with pytest.raises(ValueError):
        module.cloud_init_remove({"machine": vm})


def test_delete_refuses_a_machine_that_moved_to_another_node(monkeypatch, tmp_path):
    module = load("node-agent.py")
    nodes = tmp_path / "nodes"
    (nodes / "carrel02" / "qemu-server").mkdir(parents=True)
    (nodes / "carrel02" / "qemu-server" / "10100.conf").write_text("x")
    monkeypatch.setattr(module, "PVE_NODES", nodes)
    vm = dict(MACHINE, vmid=10100, kind="vm", name="linked")
    with pytest.raises(ValueError, match="another node"):
        module.action({"machine": vm, "action": "delete", "confirm": "linked"})
    (nodes / "carrel02" / "qemu-server" / "10100.conf").unlink()
    assert module.action({"machine": vm, "action": "delete", "confirm": "linked"}) == {"state": "absent"}


def test_delete_removes_the_vendor_data_of_an_imported_vm(monkeypatch):
    module = load("node-agent.py")
    vm = dict(MACHINE, vmid=10100, kind="vm", name="linked")
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "run", lambda *a, **k: "status: stopped")
    monkeypatch.setattr(module.Path, "exists", lambda self: str(self) == "/etc/pve/qemu-server/10100.conf")
    removed = []
    monkeypatch.setattr(module.Path, "unlink", lambda self, missing_ok=False: removed.append(str(self)))
    module.action({"machine": vm, "action": "delete", "confirm": "linked"})
    assert "/var/lib/vz/snippets/carrel-10100-vendor.json" in removed


def test_jump_sync_accepts_only_forwarding_lines_to_tenant_ssh():
    module = load("jump-sync.py")
    good = 'restrict,port-forwarding,command="/usr/sbin/nologin",permitopen="10.200.1.10:22",permitopen="10.200.3.109:22" ssh-ed25519 AAAAC3Nz=='
    assert module.check(good + "\n") == good + "\n"
    # A machine without SSH forwards its declared ports (issue #94).
    talos = good.replace("10.200.1.10:22", "10.200.1.10:50000").replace("10.200.3.109:22", "10.200.1.10:6443")
    assert module.check(talos + "\n") == talos + "\n"
    for bad in [
        good.replace("10.200.1.10:22", "10.200.0.3:22"),
        good.replace("10.200.1.10:22", "10.200.1.10:0"),
        good.replace("10.200.1.10:22", "10.200.1.10:65536"),
        good.replace("10.200.1.10:22", "10.200.1.10:022"),
        good.replace("10.200.1.10:22", "10.200.1.10:"),
        good.replace("10.200.1.10:22", "10.200.1.110:22"),
        good.replace("restrict,", ""),
        good.replace('command="/usr/sbin/nologin",', 'command="/bin/sh",'),
        good.replace("permitopen", 'environment="X=1",permitopen', 1),
        good + " comment",
        good + "\nssh-ed25519 AAAA",
    ]:
        with pytest.raises(ValueError):
            module.check(bad)


def test_the_jump_host_reaches_port_22_of_every_machine(monkeypatch, tmp_path):
    module = load("node-agent.py")
    rules = module.guest_firewall(
        dict(MACHINE), {"peers": [], "ports": [], "domains": []}, {"protected_addresses": []}
    )
    assert "IN ACCEPT -source 10.200.0.4 -p tcp -dport 22" in rules.splitlines()
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    (tmp_path / "site.json").write_text(json.dumps({"ssh_jump": True, "exit_nodes": ["x"]}))
    assert "tcp dport 22 dnat to 10.200.0.4" in module.ports_nft({"ports": []}, "140.113.60.184")
    (tmp_path / "site.json").write_text(json.dumps({"exit_nodes": ["x"]}))
    assert "10.200.0.4" not in module.ports_nft({"ports": []}, "140.113.60.184")


def test_a_machine_without_ssh_admits_its_declared_ports_only(monkeypatch):
    module = load("node-agent.py")
    talos = dict(MACHINE, service_ports=[50000, 6443])
    rules = module.guest_firewall(
        talos, {"peers": [], "ports": [], "domains": []}, {"protected_addresses": []}
    ).splitlines()
    for source in ("10.200.0.3", "10.200.0.4"):
        assert f"IN ACCEPT -source {source} -p tcp -dport 50000" in rules
        assert f"IN ACCEPT -source {source} -p tcp -dport 6443" in rules
        assert f"IN ACCEPT -source {source} -p tcp -dport 22" not in rules
    # Its cloud-init is the member's document unchanged, or an empty
    # cloud-config that Talos skips; the network file is carrel's.
    files = {}
    monkeypatch.setattr(module, "write", lambda path, data, mode: files.update({path: data}))
    vm = dict(MACHINE, kind="vm", service_ports=[50000], ssh_keys=[], user_data="version: v1alpha1\n")
    assert (
        module.cloud_init(vm)
        == "user=local:snippets/carrel-10100-user.json,network=local:snippets/carrel-10100-network.json"
    )
    assert files["/var/lib/vz/snippets/carrel-10100-user.json"] == "version: v1alpha1\n"
    network = json.loads(files["/var/lib/vz/snippets/carrel-10100-network.json"])
    assert network["ethernets"]["primary"]["mtu"] == 1450
    module.cloud_init(dict(vm, user_data=None))
    assert files["/var/lib/vz/snippets/carrel-10100-user.json"].startswith("#cloud-config\n")
    with pytest.raises(ValueError):
        module.cloud_init(dict(vm, user_data="x" * 65537))


def test_a_talos_vm_moves_with_its_cloud_init_and_takes_no_media(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "located", lambda m: "carrel02")
    monkeypatch.setattr(module, "NODE", "carrel01")
    monkeypatch.setattr(module, "owned", lambda m, **k: {})
    monkeypatch.setattr(module, "SNIPPETS", tmp_path)
    restored = []
    monkeypatch.setattr(module, "restore_cloud_init", lambda m, files: restored.append(files))
    talos = dict(MACHINE, kind="vm", guest_management=0, service_ports=[50000])
    files = {"user": "version: v1alpha1\n", "network": "{}"}
    assert module.migrate_prepare({"machine": talos, "cloud_init": files}) == {"state": "ready"}
    assert restored == [files]
    with pytest.raises(ValueError, match="cloud-init"):
        module.migrate_prepare({"machine": talos})
    # Its ide2 is the cloud-init drive.
    with pytest.raises(ValueError, match="ISO"):
        module.set_media(talos, {}, {"iso_volume": None})


def test_an_iso_install_moves_only_where_its_iso_is_readable(monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "located", lambda m: "carrel02")
    monkeypatch.setattr(module, "NODE", "carrel01")
    monkeypatch.setattr(module, "owned", lambda m, **k: {})
    storages = {
        "old-nas": {"type": "nfs", "path": "/mnt/pve/old-nas"},
        "installers": {"type": "dir", "path": "/srv/installers"},
        "mirrored": {"type": "dir", "path": "/srv/mirrored", "shared": "1"},
    }
    monkeypatch.setattr(module, "storage_entry", lambda s: storages.get(s))
    probed = []
    monkeypatch.setattr(module, "probe", lambda path: probed.append(str(path)))
    name = "carrel-t001-netinst-0123456789ab.iso"
    iso = dict(MACHINE, kind="vm", guest_management=0, iso_volume=f"old-nas:iso/{name}")
    # Shared storage, even one the site no longer imports to: probed, then ready.
    assert module.migrate_prepare({"machine": iso}) == {"state": "ready"}
    mirrored = dict(iso, iso_volume=f"mirrored:iso/{name}")
    assert module.migrate_prepare({"machine": mirrored}) == {"state": "ready"}
    assert probed == [f"/mnt/pve/old-nas/template/iso/{name}", f"/srv/mirrored/template/iso/{name}"]
    # Storage only one node reads, whatever its name: refused before the move.
    for volume in (f"installers:iso/{name}", f"local:iso/{name}"):
        with pytest.raises(module.StorageUnavailable, match="machine_media"):
            module.migrate_prepare({"machine": dict(iso, iso_volume=volume)})
    # Another tenant's ISO.
    with pytest.raises(ValueError, match="invalid ISO"):
        other = "old-nas:iso/carrel-t002-netinst-0123456789ab.iso"
        module.migrate_prepare({"machine": dict(iso, iso_volume=other)})

    def unreadable(path):
        raise module.StorageUnavailable("missing or its storage unreachable")

    monkeypatch.setattr(module, "probe", unreadable)
    with pytest.raises(module.StorageUnavailable):
        module.migrate_prepare({"machine": iso})
    # Ejected: nothing to read.
    assert module.migrate_prepare({"machine": dict(iso, iso_volume=None)}) == {"state": "ready"}


def test_jump_sync_reads_ascii_lines_split_on_newlines_only():
    module = load("jump-sync.py")
    line = 'restrict,port-forwarding,command="/usr/sbin/nologin",permitopen="10.200.1.10:22" ssh-ed25519 AAAA'
    for bad in [line.replace("10.200.1.10", "10.200.١.10"), line + " " + line, line + "\x1c", line]:
        with pytest.raises(ValueError):
            module.check(bad)  # the last one lacks its final newline
    assert module.check("") == ""


def test_jump_sync_keeps_a_certificate_map_of_port_22_targets_only():
    module = load("jump-sync.py")
    ca = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY="
    good = {
        "ca": ca,
        "principals": {"alice": ["10.200.1.10:22"], "project:robotics": ["10.200.2.10:22", "10.200.2.11:22"]},
    }
    assert json.loads(module.check_certs(good)) == good
    for bad in [
        {"ca": ca},
        {**good, "extra": 1},
        {**good, "ca": ca + " comment"},
        {**good, "ca": ca + "\nssh-ed25519 AAAA"},
        {**good, "principals": {"Alice": ["10.200.1.10:22"]}},
        {**good, "principals": {'a",b': ["10.200.1.10:22"]}},
        {**good, "principals": {"project:Robotics": ["10.200.1.10:22"]}},
        {**good, "principals": {"alice": []}},
        {**good, "principals": {"alice": ["10.200.1.10:80"]}},
        {**good, "principals": {"alice": ["10.200.0.3:22"]}},
        {**good, "principals": {"alice": ['10.200.1.10:22",permitopen="1.1.1.1:22']}},
    ]:
        with pytest.raises(ValueError):
            module.check_certs(bad)


def test_jump_sync_drops_the_map_on_null_and_touches_an_unchanged_one(monkeypatch, tmp_path):
    module = load("jump-sync.py")
    monkeypatch.setattr(module, "CERTS", tmp_path / "certs.json")
    monkeypatch.setattr(module, "STATE", tmp_path / "state")
    certs = {"ca": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==", "principals": {"alice": ["10.200.1.10:22"]}}
    monkeypatch.setattr(
        sys,
        "stdin",
        type(
            "S",
            (),
            {"buffer": __import__("io").BytesIO(json.dumps({"op": "certs", "certs": certs}).encode())},
        )(),
    )
    assert module.main()["changed"] is True
    old = time.time() - 3600
    __import__("os").utime(tmp_path / "certs.json", (old, old))
    monkeypatch.setattr(
        sys,
        "stdin",
        type(
            "S",
            (),
            {"buffer": __import__("io").BytesIO(json.dumps({"op": "certs", "certs": certs}).encode())},
        )(),
    )
    assert module.main()["changed"] is False
    assert (tmp_path / "certs.json").stat().st_mtime > old + 3000
    monkeypatch.setattr(
        sys, "stdin", type("S", (), {"buffer": __import__("io").BytesIO(b'{"op": "certs", "certs": null}')})()
    )
    assert module.main() == {"changed": True, "principals": 0}
    assert not (tmp_path / "certs.json").exists()


def certificate(tmp_path, principals, host=False):
    """A user certificate from a throwaway CA: (ca public key, type, blob)."""
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", tmp_path / "ca"], check=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", tmp_path / "id"], check=True)
    args = ["ssh-keygen", "-q", "-s", tmp_path / "ca", "-I", "test", "-n", ",".join(principals)]
    subprocess.run([*args, *(["-h"] if host else []), tmp_path / "id.pub"], check=True)
    cert = (tmp_path / "id-cert.pub").read_text().split()
    return " ".join((tmp_path / "ca.pub").read_text().split()[:2]), cert[0], cert[1]


def test_jump_cert_joins_every_principals_machines_in_one_line(monkeypatch, tmp_path):
    module = load("jump-cert.py")
    ca, kind, blob = certificate(tmp_path, ["alice", "project:robotics", "svc:b09", "carol"])
    certs = tmp_path / "certs.json"
    certs.write_text(
        json.dumps(
            {
                "ca": ca,
                "principals": {
                    "alice": ["10.200.1.10:22"],
                    "project:robotics": ["10.200.2.10:22", "10.200.1.10:22"],
                    "bob": ["10.200.3.10:22"],
                },
            }
        )
    )
    monkeypatch.setattr(module, "CERTS", str(certs))
    assert module.line("ca", kind, blob) == (
        'cert-authority,principals="alice,project:robotics",restrict,port-forwarding,command="/usr/sbin/nologin",'
        f'permitopen="10.200.1.10:22",permitopen="10.200.2.10:22" {ca}'
    )
    # Nothing for another user (the jump user keeps to its keys), a plain
    # key, a bad blob or no machine.
    assert module.line("jump", kind, blob) is None
    assert module.line("root", kind, blob) is None
    assert module.line("ca", "ssh-ed25519", blob) is None
    assert module.line("ca", kind, blob + "\n") is None
    certs.write_text(json.dumps({"ca": ca, "principals": {"bob": ["10.200.3.10:22"]}}))
    assert module.line("ca", kind, blob) is None
    certs.write_text("not json")
    assert module.line("ca", kind, blob) is None


def test_jump_cert_admits_nothing_from_a_map_no_control_plane_keeps(monkeypatch, tmp_path):
    module = load("jump-cert.py")
    ca, kind, blob = certificate(tmp_path, ["alice"])
    certs = tmp_path / "certs.json"
    certs.write_text(json.dumps({"ca": ca, "principals": {"alice": ["10.200.1.10:22"]}}))
    monkeypatch.setattr(module, "CERTS", str(certs))
    assert module.line("ca", kind, blob) is not None
    old = time.time() - module.MAX_AGE - 60
    __import__("os").utime(certs, (old, old))
    assert module.line("ca", kind, blob) is None


def test_jump_cert_ignores_host_certificates(monkeypatch, tmp_path):
    module = load("jump-cert.py")
    ca, kind, blob = certificate(tmp_path, ["alice"], host=True)
    certs = tmp_path / "certs.json"
    certs.write_text(json.dumps({"ca": ca, "principals": {"alice": ["10.200.1.10:22"]}}))
    monkeypatch.setattr(module, "CERTS", str(certs))
    assert module.line("ca", kind, blob) is None


def test_the_fetch_container_reaches_only_public_web_and_the_resolver():
    module = load("node-agent.py")
    rules = module.fetch_firewall({"protected_addresses": ["140.113.60.184/32"]}).splitlines()
    assert "policy_in: DROP" in rules and "policy_out: DROP" in rules
    assert rules[rules.index("[IPSET ipfilter-net0]") + 1] == "10.200.255.10"
    # Private drops come before the web accepts, so 80/443 to the lab stay closed.
    assert rules.index("OUT DROP -dest 192.168.0.0/16") < rules.index("OUT ACCEPT -p tcp -dport 443")
    assert "OUT DROP -dest 140.113.60.184/32" in rules
    # Only path MTU discovery comes in; nothing opens a connection to it.
    assert [r for r in rules if "IN ACCEPT" in r] == ["IN ACCEPT -p icmp -icmp-type fragmentation-needed"]


def test_tenant_hosts_clamp_forwarded_tcp_to_the_tenant_mtu():
    module = load("install-network.py")
    rules = module.tenant_host_nft([])
    assert "hook forward priority mangle" in rules
    assert "tcp option maxseg size > 1410 tcp option maxseg size set 1410" in rules


def test_guests_accept_path_mtu_discovery():
    module = load("node-agent.py")
    m = {
        "tenant_n": 3,
        "vmid": 10300,
        "host": 10,
        "name": "web",
        "kind": "vm",
        "ip": "10.200.3.10",
        "mac": "02:ca:03:00:00:01",
        "network_access": "restricted",
    }
    rules = module.guest_firewall(m, {"ports": [], "domains": [], "peers": []}, {"protected_addresses": []})
    assert "IN ACCEPT -p icmp -icmp-type fragmentation-needed" in rules.splitlines()


def test_fetch_jobs_are_checked_before_anything_runs(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **k: calls.append(a) or "")
    job = "a" * 32
    good = {
        "job": job,
        "url": "https://example.com/x.iso",
        "sha256": "b" * 64,
        "max_bytes": 1024,
        "format": "iso",
    }
    module.fetch_start(good)
    assert calls[0][:2] == ("pct", "push") and calls[1][:5] == ("pct", "exec", 103, "--", "systemd-run")
    assert "--uid=carrel-fetch" in calls[1] and f"--unit=carrel-fetch-{job}" in calls[1]
    for bad in [
        {"job": "../x"},
        {"sha256": "x"},
        {"format": "vmdk"},
        {"max_bytes": 30 * 1024**3},
        {"url": "x" * 5000},
    ]:
        calls.clear()
        with pytest.raises(ValueError):
            module.fetch_start({**good, **bad})
        assert not any(c[:2] == ("pct", "exec") for c in calls)


def test_fetch_store_checks_the_name_and_the_bytes(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    nfs = tmp_path / "nfs"
    (nfs / "template" / "iso").mkdir(parents=True)
    monkeypatch.setattr(module, "content_storage", lambda kind: "shared")
    monkeypatch.setattr(module, "storage_entry", lambda s: {"type": "nfs", "path": str(nfs)})
    data = b"iso bytes"
    digest = hashlib.sha256(data).hexdigest()

    def run(*args, **kwargs):
        if args[0] == sys.executable:
            # The real rate-limited checksum, in its child.
            return subprocess.run([str(a) for a in args], capture_output=True, text=True, check=True).stdout
        return ""

    reads = []

    def bounded(args, out, limit, timeout):
        reads.append(args)
        out.write(data)
        return len(data)

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module, "bounded", bounded)
    req = {
        "job": "c" * 32,
        "volume": "carrel-t003-netinst-" + digest[:12] + ".iso",
        "kind": "iso",
        "sha256": digest,
        "tenant_n": 3,
        "max_bytes": 1024,
    }
    assert module.fetch_store(req)["volume"] == "shared:iso/" + req["volume"]
    stored = nfs / "template" / "iso" / req["volume"]
    assert stored.read_bytes() == data and oct(stored.stat().st_mode & 0o777) == "0o444"
    assert not list((nfs / "template" / "iso").glob(".carrel-*"))
    # The file is read inside the container, never through a host path.
    assert reads[0][:4] == ["pct", "exec", 103, "--"] and "test ! -L" in reads[0][-1]
    # Bytes that do not match the database's checksum never land.
    with pytest.raises(ValueError, match="does not match its checksum"):
        module.fetch_store(
            {**req, "job": "d" * 32, "volume": "carrel-t003-other-" + "e" * 12 + ".iso", "sha256": "e" * 64}
        )
    assert not list((nfs / "template" / "iso").glob(".carrel-*"))
    assert not (nfs / "template" / "iso" / ("carrel-t003-other-" + "e" * 12 + ".iso")).exists()
    for bad in [
        "../x.iso",
        "carrel-t003-x-" + digest[:12] + ".exe",
        "carrel-t3-x-" + digest[:12] + ".iso",
        "carrel-t003-x-" + digest[:12] + ".qcow2",
    ]:
        with pytest.raises(ValueError):
            module.fetch_store({**req, "volume": bad})
    # The name must carry the request's tenant and the checksum's start.
    for bad in [{"tenant_n": 4}, {"volume": "carrel-t003-netinst-" + "0" * 12 + ".iso"}]:
        with pytest.raises(ValueError, match="tenant or checksum"):
            module.fetch_store({**req, **bad})


def test_bounded_stops_at_its_limit_and_kills_the_group(tmp_path):
    module = load("node-agent.py")
    with (tmp_path / "out").open("wb") as out:
        assert module.bounded(["printf", "abc"], out, 10, 5) == 3
    with (tmp_path / "out").open("wb") as out, pytest.raises(ValueError, match="limit"):
        module.bounded(["yes"], out, 1 << 20, 5)
    with (tmp_path / "out").open("wb") as out, pytest.raises(module.subprocess.TimeoutExpired):
        module.bounded(["sh", "-c", "sleep 30 & sleep 30"], out, 10, 1)


def test_fetch_status_reports_progress_and_results(monkeypatch):
    module = load("node-agent.py")
    outputs = iter(
        ["\n1048576\nactive", '{"ok": true, "size": 9, "sha256": "x"}\n9\ninactive', "\n\ninactive"]
    )
    monkeypatch.setattr(module, "run", lambda *a, **k: next(outputs))
    job = {"job": "f" * 32}
    assert module.fetch_status(job) == {"state": "running", "received": 1048576}
    assert module.fetch_status(job)["state"] == "done"
    assert module.fetch_status(job)["state"] == "failed"


def test_image_delete_removes_only_the_tenants_file(monkeypatch, tmp_path):
    module = load("node-agent.py")
    folder = tmp_path / "template" / "iso"
    folder.mkdir(parents=True)
    monkeypatch.setattr(module, "content_storage", lambda kind: "shared")
    monkeypatch.setattr(module, "storage_entry", lambda s: {"type": "nfs", "path": str(tmp_path)})
    name = "carrel-t003-netinst-abababababab.iso"
    (folder / name).write_text("x")
    with pytest.raises(ValueError):
        module.image_delete({"volume": name, "kind": "iso", "tenant_n": 4})
    for bad in ["../../etc/passwd", "carrel-t003-x.iso", name.replace(".iso", ".exe")]:
        with pytest.raises(ValueError):
            module.image_delete({"volume": bad, "kind": "iso", "tenant_n": 3})
    assert module.image_delete({"volume": name, "kind": "iso", "tenant_n": 3}) == {"state": "deleted"}
    assert not (folder / name).exists()


def test_an_iso_machine_is_created_empty_with_its_tenants_iso(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "content_storage", lambda kind: "shared")
    monkeypatch.setattr(module, "storage_entry", lambda s: {"type": "nfs", "path": str(tmp_path)})
    monkeypatch.setattr(module, "storage_id", lambda: "local-zfs")
    monkeypatch.setattr(module, "first_firewall", lambda m: None)
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **k: calls.append(a) or "status: stopped")
    vol = "shared:iso/carrel-t001-netinst-abababababab.iso"
    vm = dict(
        MACHINE,
        kind="vm",
        iso_volume=vol,
        firmware="uefi",
        tpm=True,
        disk_gb=20,
        cpu=2,
        memory_mb=2048,
        nics=[],
    )
    assert module.create_from_iso(vm, False, tmp_path / "m.json", {}, "marker")["state"] == "running"
    create = next(c for c in calls if c[:2] == ("qm", "create"))
    assert f"{vol},media=cdrom" in create and "order=scsi0;ide2" in create and "ovmf" in create
    assert any(str(a).startswith("local-zfs:1,version=v2.0") for a in create)
    for bad in [
        "shared:iso/carrel-t002-netinst-abababababab.iso",
        "other:iso/carrel-t001-netinst-abababababab.iso",
        "shared:iso/../../etc/passwd",
        "shared:import/carrel-t001-disk-abababababab.qcow2",
    ]:
        with pytest.raises(ValueError):
            module.iso_volume(vm, bad)
    with pytest.raises(ValueError, match="UEFI"):
        module.create_from_iso(dict(vm, firmware="bios"), False, tmp_path / "m.json", {}, "marker")


def test_a_console_answers_once_then_hands_stdio_to_qm_or_socat(monkeypatch, capsys):
    module = load("node-agent.py")
    cfg = {"vga": "std"}
    monkeypatch.setattr(module, "owned", lambda m: cfg)
    monkeypatch.setattr(module, "power_status", lambda m: "running")
    monkeypatch.setattr(module.os, "environ", {})
    execs = []
    monkeypatch.setattr(module.os, "execvp", lambda f, args: execs.append(args))
    vm = dict(MACHINE, kind="vm")
    module.console(vm, "vnc", "Ab3dEf7h")
    assert json.loads(capsys.readouterr().out)["result"] == {"state": "streaming", "mode": "vnc"}
    assert execs == [["qm", "vncproxy", "10100"]] and module.os.environ["LC_PVE_TICKET"] == "Ab3dEf7h"
    for ticket in [None, "short", "Ab3dEf7h;", "Ab3dEf7h\n"]:
        with pytest.raises(ValueError):
            module.console(vm, "vnc", ticket)
    cfg["vga"] = "serial0"
    with pytest.raises(ValueError, match="no screen"):
        module.console(vm, "vnc", "Ab3dEf7h")
    monkeypatch.setattr(module.Path, "exists", lambda self: str(self) == "/var/run/qemu-server/10100.serial0")
    module.console(vm, "serial", None)
    assert execs[-1] == ["socat", "-", "UNIX-CONNECT:/var/run/qemu-server/10100.serial0"]
    with pytest.raises(ValueError, match="mode"):
        module.console(vm, "shell", None)
    monkeypatch.setattr(module, "power_status", lambda m: "stopped")
    with pytest.raises(ValueError, match="start"):
        module.console(vm, "serial", None)
    with pytest.raises(ValueError):
        module.console(dict(MACHINE, kind="ct"), "serial", None)


def test_a_cloud_image_is_checked_then_imported(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "content_storage", lambda kind: "shared")
    monkeypatch.setattr(module, "storage_entry", lambda s: {"type": "nfs", "path": str(tmp_path)})
    digest = "cd" * 32
    name = "carrel-t001-noble-" + digest[:12] + ".qcow2"
    virtual = {"size": 10 * 1024**3}

    def run(*a, **k):
        if a[0] == "qemu-img":
            assert a[1:5] == ("info", "-f", "qcow2", "--output=json")
            return json.dumps({"virtual-size": virtual["size"]})
        return digest + "\n"

    monkeypatch.setattr(module, "run", run)
    vm = dict(MACHINE, kind="vm", disk_gb=10)
    assert module.import_volume(vm, "shared:import/" + name, digest) == "shared:import/" + name
    # The host reads the virtual size itself: an image larger than the disk
    # the quota counted is refused, whatever the fetcher reported.
    for size in [10 * 1024**3 + 1, 0, "big"]:
        virtual["size"] = size
        with pytest.raises(ValueError, match="virtual size"):
            module.import_volume(vm, "shared:import/" + name, digest)
    monkeypatch.setattr(module, "run", lambda *a, **k: "0" * 64 + "\n")
    with pytest.raises(ValueError, match="checksum"):
        module.import_volume(vm, "shared:import/" + name, digest)
    for bad, d in [
        ("shared:import/carrel-t002-noble-" + digest[:12] + ".qcow2", digest),
        ("other:import/" + name, digest),
        ("shared:iso/" + name, digest),
        ("shared:import/" + name, "ab" * 32),
    ]:
        with pytest.raises(ValueError):
            module.import_volume(vm, bad, d)


def test_checksums_of_shared_storage_are_rate_limited(monkeypatch, tmp_path):
    module = load("node-agent.py")
    path = tmp_path / "image.raw"
    data = b"x" * (2 << 20)
    path.write_bytes(data)
    monkeypatch.setattr(module, "HASH_RATE", 2 << 20)
    monkeypatch.setattr(
        module,
        "run",
        lambda *a, **k: (
            subprocess.run([str(x) for x in a], capture_output=True, text=True, check=True).stdout
        ),
    )
    started = time.monotonic()
    assert module.sha256_limited(path) == hashlib.sha256(data).hexdigest()
    # 2 MiB at 2 MiB/s: about a second, never at disk speed.
    assert time.monotonic() - started >= 0.5


def test_only_the_first_node_reloads_sdn_for_links_its_reload_brings(monkeypatch):
    # Issue #48: one cluster-wide reload per pass, not one per node.
    module = load("node-agent.py")
    monkeypatch.setattr(module.time, "sleep", lambda s: None)
    assert module.sdn_owed(lambda: True, first=True)
    assert not module.sdn_owed(lambda: False, first=False)
    # The first node's reload brings the links after a few seconds.
    checks = iter([True, True, True, False])
    assert not module.sdn_owed(lambda: next(checks), first=False)
    # They never come: this node reloads after waiting.
    assert module.sdn_owed(lambda: True, first=False, wait=3)


VPN_KEY = "x3Fh2Y0pB0Hq9gYc0vXo4m1kQfN6aT8rW5sLdJ2eCzU="


def test_a_vpn_client_reaches_only_its_tenant():
    # Issue #103: each tenant's interface passes its own clients to its own
    # network, and every other wg-t* packet is dropped.
    module = load("node-agent.py")
    state = {
        "tenants": [{"n": 1, "status": "active"}, {"n": 2, "status": "suspended"}],
        "vpn_clients": [
            {"tenant_n": 1, "address": "10.201.1.2", "public_key": VPN_KEY},
            {"tenant_n": 2, "address": "10.201.2.2", "public_key": VPN_KEY},
        ],
    }
    tenants = module.vpn_clients(state)
    assert tenants == {1: [(VPN_KEY, "10.201.1.2")]}
    rules = module.vpn_nft(tenants).splitlines()
    # Inbound in prerouting: in the VRF, forward and input see vrf_tenants.
    prerouting = rules[rules.index(" chain prerouting {") : rules.index(" chain forward {")]
    accept = prerouting.index('  iifname "wg-t001" ip saddr 10.201.1.0/24 ip daddr 10.200.1.0/24 accept')
    assert accept < prerouting.index('  iifname "wg-t*" counter drop')
    assert prerouting.index('  iifname "wg-t001" ip daddr 10.200.1.1 counter drop') < accept
    forward = rules[rules.index(" chain forward {") :]
    assert forward.index(
        '  oifname "wg-t001" ip saddr 10.200.1.0/24 ip daddr 10.201.1.0/24 accept'
    ) < forward.index('  oifname "wg-t*" counter drop')
    assert not [r for r in forward if r.strip().startswith("iifname")]
    assert not [r for r in rules if "10.200.2." in r]
    # Another tenant's range, the gateway address or a bad key never get in.
    for bad in (
        {"address": "10.201.2.5"},
        {"address": "10.201.1.1"},
        {"address": "10.200.1.9"},
        {"public_key": "x"},
    ):
        with pytest.raises(ValueError):
            module.vpn_clients(dict(state, vpn_clients=[dict(state["vpn_clients"][0], **bad)]))


def test_tenant_machines_accept_their_vpn_clients_and_restricted_ones_do_not():
    module = load("node-agent.py")
    state = {"peers": [], "ports": [], "domains": []}
    open_ = dict(MACHINE, name="app", vmid=10100, host=10, ip="10.200.1.10", tenant_n=1)
    closed = dict(open_, network_access="restricted")
    assert "IN ACCEPT -source 10.201.1.0/24" in module.guest_firewall(
        open_, state, {"protected_addresses": []}
    )
    assert "10.201." not in module.guest_firewall(closed, state, {"protected_addresses": []})


def test_the_exit_node_accepts_the_vpn_ports_and_nothing_else_new():
    rules = load("install-network.py").public_nft("vmbr0.60", "140.113.60.184").splitlines()
    vpn = rules.index('  iifname "vmbr0.60" udp dport 31001-31254 accept')
    assert vpn < rules.index('  iifname "vmbr0.60" counter drop')


def test_a_vpn_failure_stays_out_of_the_reconciliation(monkeypatch):
    # Review of #157: without wireguard-tools, one client must not fail every
    # tenant's reconcile; the filter still goes in first.
    module = load("node-agent.py")
    applied = []
    monkeypatch.setattr(module, "public_ingress", lambda: "140.113.60.184")
    monkeypatch.setattr(module, "write", lambda *a, **k: True)
    monkeypatch.setattr(module, "run", lambda *a, **k: applied.append(a) or "")
    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    state = {
        "tenants": [{"n": 1}],
        "vpn_clients": [{"tenant_n": 1, "address": "10.201.1.2", "public_key": VPN_KEY}],
    }
    out = module.vpn(state)
    assert "wireguard-tools" in out["error"] and ("nft", "-f", "/etc/carrel/vpn.nft") in applied
    assert not [a for a in applied if a[0] in ("ip", "wg")]


@pytest.mark.parametrize(
    "kind,command",
    [("vm", ["qm", "set", 10100, "--name", "portal"]), ("ct", ["pct", "set", 10100, "--hostname", "portal"])],
)
def test_rename_sets_the_proxmox_name_of_an_owned_machine(monkeypatch, kind, command):
    module = load("node-agent.py")
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(list(args)) or "")
    monkeypatch.setattr(module, "pve_get", lambda *args: {"tags": "carrel;tenant-1"})
    module.action({"machine": dict(MACHINE, kind=kind), "action": "rename", "name": "portal"})
    assert calls == [command]
    with pytest.raises(ValueError):
        module.action({"machine": dict(MACHINE, kind=kind), "action": "rename", "name": "Bad Name; rm"})
    # Only machines carrel owns, by their tags.
    monkeypatch.setattr(module, "pve_get", lambda *args: {"tags": "other"})
    with pytest.raises(ValueError, match="unowned"):
        module.action({"machine": dict(MACHINE, kind=kind), "action": "rename", "name": "portal"})


FROZEN_NOTE = "carrel-freeze b09 op1"
VOLID = "pbs:backup/vm/10100/2026-10-26T00:00:00Z"
OLD_VOLID = "pbs:backup/vm/10100/2026-10-25T00:00:00Z"
SCHEDULED_VOLID = "pbs:backup/vm/10100/2026-10-24T03:00:00Z"


def freezer(monkeypatch, tmp_path, *, listing, power="stopped", snapshots=(), lock=None):
    """node-agent with a PBS storage, a recorded command line and a node state directory."""
    module = load("node-agent.py")
    monkeypatch.setattr(
        module, "storage_entry", lambda storage: {"type": "pbs"} if storage == "pbs" else {"type": "zfspool"}
    )
    monkeypatch.setattr(module, "owned", lambda m, allow_provisioning=False, node=None: {"name": m["name"]})
    monkeypatch.setattr(module, "power_status", lambda m: power)
    monkeypatch.setattr(module, "STATE", tmp_path / "state")
    (tmp_path / "state").mkdir(exist_ok=True)
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    (tmp_path / "site.json").write_text(json.dumps({"site": "b09"}))
    monkeypatch.setattr(module.time, "sleep", lambda s: None)
    config = {"digest": "d1"}

    def pve_get(path, **kw):
        if path.endswith("/snapshot"):
            return [{"name": "current"}, *({"name": n} for n in snapshots)]
        return dict(config)

    monkeypatch.setattr(module, "pve_get", pve_get)
    commands = []
    module.test_timeouts = {}

    def run(*args, **kw):
        commands.append([str(a) for a in args])
        module.test_timeouts[str(args[0])] = kw.get("timeout")
        if args[0] == "pvesh" and args[1] == "get":
            return json.dumps(listing(commands))
        if args[0] == "vzdump" and lock:
            raise module.CommandFailure("vzdump 10100 failed: can't lock file '/var/run/vzdump.lock'")
        return ""

    monkeypatch.setattr(module, "run", run)
    module.test_config = config
    return module, commands


def backup(**kw):
    return {
        "volid": VOLID,
        "size": 1 << 30,
        "protected": 1,
        "notes": FROZEN_NOTE,
        "verification": {"state": "ok"},
        **kw,
    }


def freed(commands):
    return [c[2] for c in commands if c[:2] == ["pvesm", "free"]]


def dumped(commands):
    return any(c[0] == "vzdump" for c in commands)


def protect_calls(commands):
    return [c for c in commands if c[:2] == ["pvesh", "set"] and c[-2:] == ["--protected", "1"]]


REQUEST = {"machine": dict(MACHINE), "storage": "pbs", "freeze_id": "op1", "verify_wait": 0}


def test_freeze_protects_the_backup_after_it_is_verified(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch,
        tmp_path,
        listing=lambda c: [backup(protected=int(bool(protect_calls(c))))] if dumped(c) else [],
    )
    out = module.freeze(REQUEST)
    assert out == {"volid": VOLID, "size": 1 << 30, "verification": "ok", "note": FROZEN_NOTE}
    dump = next(c for c in commands if c[0] == "vzdump")
    # No --protected here: the backup server refuses the flag while it verifies the new snapshot.
    assert dump[1:] == ["10100", "--storage", "pbs", "--mode", "stop", "--notes-template", FROZEN_NOTE]
    # The backup's limit leaves room for the verification wait inside one request.
    assert module.test_timeouts["vzdump"] == module.FREEZE_DUMP_SECONDS < module.VZDUMP_SECONDS
    assert protect_calls(commands) == [
        ["pvesh", "set", f"/nodes/{module.NODE}/storage/pbs/content/{VOLID}", "--protected", "1"]
    ]


def test_freeze_does_not_protect_a_backup_that_is_not_verified(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch, tmp_path, listing=lambda c: [backup(protected=0, verification=None)] if dumped(c) else []
    )
    with pytest.raises(module.CommandFailure, match="not verified"):
        module.freeze(REQUEST)
    assert protect_calls(commands) == []


def test_freeze_tries_again_while_the_backup_server_still_holds_the_snapshot(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch,
        tmp_path,
        listing=lambda c: [backup(protected=int(len(protect_calls(c)) > 2))] if dumped(c) else [],
    )
    run = module.run

    def locked(*args, **kw):
        out = run(*args, **kw)
        if args[:2] == ("pvesh", "set") and len(protect_calls(commands)) <= 2:
            raise module.CommandFailure("unable to set protected flag - 400 Bad Request")
        return out

    monkeypatch.setattr(module, "run", locked)
    assert module.freeze(REQUEST)["verification"] == "ok"
    assert len(protect_calls(commands)) == 3


def test_freeze_checks_the_machine_again_after_protecting_the_backup(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch,
        tmp_path,
        listing=lambda c: [backup(protected=int(bool(protect_calls(c))))] if dumped(c) else [],
    )
    run = module.run

    def slow(*args, **kw):
        out = run(*args, **kw)
        if args[:2] == ("pvesh", "set") and args[-2:] == ("--protected", 1):
            # Started and stopped again while the server held the snapshot.
            monkeypatch.setattr(module, "last_start", lambda m: 1793000000)
        return out

    monkeypatch.setattr(module, "run", slow)
    with pytest.raises(module.CommandFailure, match="changed while"):
        module.freeze(REQUEST)
    assert freed(commands) == [VOLID] and not module.freeze_stamp(MACHINE).exists()


def test_freeze_reports_a_refused_protection_at_once(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch, tmp_path, listing=lambda c: [backup(protected=0)] if dumped(c) else []
    )
    run = module.run

    def refused(*args, **kw):
        out = run(*args, **kw)
        if args[:2] == ("pvesh", "set"):
            raise module.CommandFailure("pvesh set failed: 403 Forbidden: permission check failed")
        return out

    monkeypatch.setattr(module, "run", refused)
    with pytest.raises(module.CommandFailure, match="refused to protect"):
        module.freeze(REQUEST)
    # One try, and the backup stays for the retry after the permission is fixed.
    assert len(protect_calls(commands)) == 1 and freed(commands) == []


def test_freeze_does_not_take_a_number_in_the_volume_name_for_a_refusal(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch,
        tmp_path,
        listing=lambda c: [backup(protected=int(len(protect_calls(c)) > 1))] if dumped(c) else [],
    )
    run = module.run

    def locked(*args, **kw):
        out = run(*args, **kw)
        if args[:2] == ("pvesh", "set") and len(protect_calls(commands)) == 1:
            raise module.CommandFailure(
                "pvesh set failed: vm/10403/2026-11-12T04:01:03Z: unable to set protected flag - 400 Bad Request"
            )
        return out

    monkeypatch.setattr(module, "run", locked)
    assert module.freeze(REQUEST)["verification"] == "ok"
    assert len(protect_calls(commands)) == 2


def test_freeze_tries_again_when_protecting_times_out(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch,
        tmp_path,
        listing=lambda c: [backup(protected=int(len(protect_calls(c)) > 1))] if dumped(c) else [],
    )
    run = module.run

    def slow(*args, **kw):
        out = run(*args, **kw)
        if args[:2] == ("pvesh", "set") and len(protect_calls(commands)) == 1:
            assert kw["timeout"] == module.PROTECT_SECONDS
            raise module.subprocess.TimeoutExpired("pvesh", kw["timeout"])
        return out

    monkeypatch.setattr(module, "run", slow)
    assert module.freeze(REQUEST)["verification"] == "ok"
    assert len(protect_calls(commands)) == 2


def test_freeze_returns_the_backup_it_protected(monkeypatch, tmp_path):
    # Two backups carry the note; only the one this freeze protected may be returned.
    other = backup(volid=OLD_VOLID, protected=1)

    def listing(c):
        if not dumped(c):
            return []
        return [backup(protected=0)] if not protect_calls(c) else [other, backup(protected=1)]

    module, _ = freezer(monkeypatch, tmp_path, listing=listing)
    assert module.freeze(REQUEST)["volid"] == VOLID


@pytest.mark.parametrize("later", [{"state": "failed"}, None])
def test_freeze_refuses_a_backup_whose_verification_changed_while_it_was_protected(
    monkeypatch, tmp_path, later
):
    def listing(c):
        if not dumped(c):
            return []
        return [backup(protected=0)] if not protect_calls(c) else [backup(protected=1, verification=later)]

    module, _ = freezer(monkeypatch, tmp_path, listing=listing)
    with pytest.raises(module.CommandFailure, match="could not be verified"):
        module.freeze(REQUEST)


def test_a_freeze_fits_the_control_planes_bound_on_one_request():
    module = load("node-agent.py")
    longest = (
        module.FREEZE_DUMP_SECONDS
        + module.VERIFY_WAIT_MAX
        + module.PROTECT_TRIES * (module.PROTECT_SECONDS + module.VERIFY_POLL_SECONDS)
    )
    assert longest < 4 * 3600 and module.FREEZE_DUMP_SECONDS > 2 * 3600


def test_freeze_keeps_the_machine_when_the_backup_cannot_be_protected(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch, tmp_path, listing=lambda c: [backup(protected=0)] if dumped(c) else []
    )
    run = module.run

    def locked(*args, **kw):
        out = run(*args, **kw)
        if args[:2] == ("pvesh", "set"):
            raise module.CommandFailure("unable to set protected flag - 400 Bad Request")
        return out

    monkeypatch.setattr(module, "run", locked)
    with pytest.raises(module.CommandFailure, match="could not be protected"):
        module.freeze(REQUEST)
    # Kept, with the proof that the machine is unchanged, for the retry.
    assert freed(commands) == [] and module.freeze_stamp(MACHINE).exists()


def test_freeze_waits_for_the_backup_server_to_verify(monkeypatch, tmp_path):
    polls = []

    def listing(c):
        polls.append(1)
        done = len(polls) > 5
        return [backup(verification={"state": "ok"} if done else {})] if dumped(c) else []

    module, _ = freezer(monkeypatch, tmp_path, listing=listing)
    assert module.freeze({**REQUEST, "verify_wait": 3600})["verification"] == "ok"


def test_freeze_refuses_an_unverified_backup_but_keeps_it_for_a_retry(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch, tmp_path, listing=lambda c: [backup(verification=None)] if dumped(c) else []
    )
    with pytest.raises(module.CommandFailure, match="not verified"):
        module.freeze(REQUEST)
    assert freed(commands) == []
    # The retry finds it and, the machine being unchanged, takes no second one.
    module2, commands2 = freezer(monkeypatch, tmp_path, listing=lambda c: [backup()])
    assert module2.freeze(REQUEST)["verification"] == "ok"
    assert not dumped(commands2)


def test_freeze_removes_a_backup_that_failed_its_verification(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch,
        tmp_path,
        listing=lambda c: [backup(verification={"state": "failed"})] if dumped(c) else [],
    )
    with pytest.raises(module.CommandFailure, match="failed its verification"):
        module.freeze(REQUEST)
    assert freed(commands) == [VOLID]
    assert not module.freeze_stamp(MACHINE).exists()


def test_freeze_reuses_its_backup_only_while_the_machine_is_unchanged(monkeypatch, tmp_path):
    state = {"old_gone": False}

    def listing(c):
        state["old_gone"] = OLD_VOLID in freed(c)
        out = [backup(volid=OLD_VOLID)] if not state["old_gone"] else []
        return out + ([backup()] if dumped(c) else [])

    module, commands = freezer(monkeypatch, tmp_path, listing=listing)
    # The first attempt made OLD_VOLID and stamped the machine as it was.
    module.write(
        module.freeze_stamp(MACHINE), json.dumps({"note": FROZEN_NOTE, "digest": "d1", "started": 0})
    )
    # It was started and written to since: the node's own requests drop the stamp.
    module.freeze_stamp(MACHINE).unlink()
    out = module.freeze(REQUEST)
    assert dumped(commands) and freed(commands) == [OLD_VOLID] and out["volid"] == VOLID


def test_freeze_does_not_reuse_a_backup_after_a_configuration_change(monkeypatch, tmp_path):
    module, commands = freezer(
        monkeypatch, tmp_path, listing=lambda c: [backup(volid=OLD_VOLID)] if not dumped(c) else [backup()]
    )
    module.write(
        module.freeze_stamp(MACHINE), json.dumps({"note": FROZEN_NOTE, "digest": "other", "started": 0})
    )
    module.freeze(REQUEST)
    assert dumped(commands)


def test_freeze_does_not_reuse_a_backup_after_a_start_the_agent_never_saw(monkeypatch, tmp_path):
    # The node booted and PVE started the machine, or an admin did: no agent request, no config change.
    module, commands = freezer(
        monkeypatch, tmp_path, listing=lambda c: [backup(volid=OLD_VOLID)] if not dumped(c) else [backup()]
    )
    module.write(
        module.freeze_stamp(MACHINE), json.dumps({"note": FROZEN_NOTE, "digest": "d1", "started": 0})
    )
    monkeypatch.setattr(module, "last_start", lambda m: 1793000000)
    module.freeze(REQUEST)
    assert dumped(commands) and OLD_VOLID in freed(commands)


def test_freeze_checks_the_machine_again_after_waiting_for_the_verification(monkeypatch, tmp_path):
    polls = []

    def listing(c):
        polls.append(1)
        if len(polls) > 4:
            # Started and stopped again while PBS was verifying.
            module.last_start = lambda m: 1793000000
        return [backup(verification={"state": "ok"} if len(polls) > 4 else {})] if dumped(c) else []

    module, commands = freezer(monkeypatch, tmp_path, listing=listing)
    with pytest.raises(module.CommandFailure, match="changed while"):
        module.freeze({**REQUEST, "verify_wait": 3600})
    assert freed(commands) == [VOLID]


def test_freeze_turns_off_start_at_boot_before_the_backup(monkeypatch, tmp_path):
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [backup()] if dumped(c) else [])
    module.test_config["onboot"] = 1
    module.freeze(REQUEST)
    names = [c[:2] for c in commands]
    assert ["qm", "set"] in names and names.index(["qm", "set"]) < next(
        i for i, c in enumerate(commands) if c[0] == "vzdump"
    )


def test_any_request_for_a_machine_drops_the_proof_of_an_unchanged_one(monkeypatch, tmp_path):
    module, _ = freezer(monkeypatch, tmp_path, listing=lambda c: [])
    monkeypatch.setattr(module, "cloud_init_remove", lambda req: {})
    module.write(module.freeze_stamp(MACHINE), "{}")
    request = json.dumps({"op": "cloud_init_remove", "machine": MACHINE}).encode() + b"\n"
    monkeypatch.setattr(module.sys, "stdin", type("In", (), {"buffer": __import__("io").BytesIO(request)})())
    module.main()
    assert not module.freeze_stamp(MACHINE).exists()


def test_freeze_leaves_the_clusters_own_backups_alone(monkeypatch, tmp_path):
    # A scheduled job backs up the same machine into the same storage.
    scheduled = backup(volid=SCHEDULED_VOLID, notes="box", protected=0, verification={"state": "ok"})
    leftover = backup(volid=OLD_VOLID, notes="carrel-freeze b09 op0")
    module, commands = freezer(
        monkeypatch,
        tmp_path,
        listing=lambda c: [scheduled, leftover] + ([backup()] if dumped(c) else []),
    )
    out = module.freeze(REQUEST)
    assert out["volid"] == VOLID
    # An earlier freeze's leftover goes; the scheduled backup is never read as ours.
    assert freed(commands) == [OLD_VOLID]
    assert not any(SCHEDULED_VOLID in c for c in commands if c[0] != "pvesh")
    with pytest.raises(ValueError, match="frozen machine"):
        module.backup_remove({"machine": dict(MACHINE), "volid": SCHEDULED_VOLID})
    assert freed(commands) == [OLD_VOLID]


def test_freeze_names_a_backup_job_that_holds_the_machine(monkeypatch, tmp_path):
    module, _ = freezer(monkeypatch, tmp_path, listing=lambda c: [], lock=True)
    with pytest.raises(module.CommandFailure, match="another job"):
        module.freeze(REQUEST)


@pytest.mark.parametrize("listed", [backup(protected=0), backup(size=0)])
def test_freeze_refuses_a_backup_it_cannot_trust(monkeypatch, tmp_path, listed):
    module, _ = freezer(monkeypatch, tmp_path, listing=lambda c: [listed])
    module.write(
        module.freeze_stamp(MACHINE), json.dumps({"note": FROZEN_NOTE, "digest": "d1", "started": 0})
    )
    with pytest.raises(module.CommandFailure):
        module.freeze(REQUEST)


def test_freeze_refuses_a_running_machine_snapshots_and_a_plain_storage(monkeypatch, tmp_path):
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [], power="running")
    with pytest.raises(ValueError, match="stopped"):
        module.freeze(REQUEST)
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [], snapshots=["before"])
    with pytest.raises(ValueError, match="snapshots"):
        module.freeze(REQUEST)
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [])
    with pytest.raises(ValueError, match="Backup Server"):
        module.freeze({**REQUEST, "storage": "local-zfs"})
    assert not dumped(commands)


def thawer(monkeypatch, tmp_path, config=None):
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [])
    nodes = tmp_path / "nodes"
    (nodes / "carrel01" / "qemu-server").mkdir(parents=True)
    monkeypatch.setattr(module, "PVE_NODES", nodes)
    monkeypatch.setattr(module, "storage_id", lambda: "local-zfs")
    monkeypatch.setattr(module, "NODE", "carrel01")
    if config is not None:
        (nodes / "carrel01" / "qemu-server" / "10100.conf").write_text("x")
        module.test_config.clear()
        module.test_config.update(config)
    return module, commands, nodes


def test_thaw_restores_once_and_refuses_a_taken_vmid(monkeypatch, tmp_path):
    module, commands, nodes = thawer(monkeypatch, tmp_path)
    assert module.thaw({"machine": dict(MACHINE), "volid": VOLID}) == {"state": "restored"}
    assert ["qmrestore", VOLID, "10100", "--storage", "local-zfs"] in [c[:5] for c in commands]
    (nodes / "carrel02" / "qemu-server").mkdir(parents=True)
    (nodes / "carrel02" / "qemu-server" / "10100.conf").write_text("x")
    with pytest.raises(ValueError, match="in use"):
        module.thaw({"machine": dict(MACHINE), "volid": VOLID})


def test_thaw_accepts_a_machine_that_an_earlier_attempt_restored(monkeypatch, tmp_path):
    module, commands, _ = thawer(monkeypatch, tmp_path, config={"name": MACHINE["name"]})
    assert module.thaw({"machine": dict(MACHINE), "volid": VOLID}) == {"state": "restored"}
    assert not any(c[0] == "qmrestore" for c in commands)


def test_thaw_gives_a_restored_vm_its_balloon_device_back(monkeypatch, tmp_path):
    # An old backup carries "balloon: 0". Both a fresh restore and a retry after one fix it.
    for i, (config, removed) in enumerate([({"balloon": 0}, True), ({}, False), ({"balloon": 2048}, False)]):
        for restored in (None, {"name": MACHINE["name"]}):
            case = tmp_path / f"{i}{bool(restored)}"
            case.mkdir()
            module, commands, _ = thawer(monkeypatch, case, config=restored)
            monkeypatch.setattr(
                module, "owned", lambda m, node=None, config=config: {"name": m["name"], **config}
            )
            assert module.thaw({"machine": dict(MACHINE), "volid": VOLID}) == {"state": "restored"}
            assert (["qm", "set", "10100", "--delete", "balloon"] in commands) == removed
            assert any(c[0] == "qmrestore" for c in commands) == (restored is None)


def test_thaw_replaces_the_half_of_a_restore_that_was_cut_off(monkeypatch, tmp_path):
    module, commands, nodes = thawer(monkeypatch, tmp_path, config={"lock": "create"})

    def destroyed(*args, **kw):
        commands.append([str(a) for a in args])
        if args[:2] == ("qm", "destroy"):
            (nodes / "carrel01" / "qemu-server" / "10100.conf").unlink()
        return ""

    monkeypatch.setattr(module, "run", destroyed)
    assert module.thaw({"machine": dict(MACHINE), "volid": VOLID}) == {"state": "restored"}
    names = [c[:2] for c in commands]
    assert ["qm", "unlock"] in names and names.index(["qm", "destroy"]) < names.index(["qmrestore", VOLID])


def test_thaw_discard_removes_what_a_thaw_restored(monkeypatch, tmp_path):
    module, commands, _nodes = thawer(monkeypatch, tmp_path, config={"name": MACHINE["name"]})
    assert module.thaw({"machine": dict(MACHINE), "volid": VOLID, "discard": True}) == {"state": "discarded"}
    assert ["qm", "destroy", "10100", "--purge", "1"] in commands


@pytest.mark.parametrize(
    "config", [{"lock": "create", "name": "someone-else"}, {"lock": "create", "tags": "other"}]
)
def test_thaw_never_destroys_a_locked_machine_that_is_not_the_one_being_restored(
    monkeypatch, tmp_path, config
):
    module, commands, _nodes = thawer(monkeypatch, tmp_path, config=config)
    with pytest.raises(ValueError, match="in use"):
        module.thaw({"machine": dict(MACHINE), "volid": VOLID})
    with pytest.raises(ValueError, match="in use"):
        module.thaw({"machine": dict(MACHINE), "volid": VOLID, "discard": True})
    assert not any(c[:2] in (["qm", "destroy"], ["qm", "unlock"]) for c in commands)


def test_thaw_replaces_a_cut_off_restore_that_has_no_tags_yet(monkeypatch, tmp_path):
    module, commands, nodes = thawer(
        monkeypatch, tmp_path, config={"lock": "create", "name": MACHINE["name"]}
    )

    def destroyed(*args, **kw):
        commands.append([str(a) for a in args])
        if args[:2] == ("qm", "destroy"):
            (nodes / "carrel01" / "qemu-server" / "10100.conf").unlink()
        return ""

    monkeypatch.setattr(module, "run", destroyed)
    assert module.thaw({"machine": dict(MACHINE), "volid": VOLID}) == {"state": "restored"}


def test_thaw_discard_of_a_machine_that_was_never_restored_does_nothing(monkeypatch, tmp_path):
    module, commands, _nodes = thawer(monkeypatch, tmp_path)
    assert module.thaw({"machine": dict(MACHINE), "volid": VOLID, "discard": True}) == {"state": "absent"}
    assert not any(c[0] in ("qm", "qmrestore") for c in commands)


def test_backup_remove_unprotects_then_frees_only_the_freeze_backup(monkeypatch, tmp_path):
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [backup()])
    assert module.backup_remove({"machine": dict(MACHINE), "volid": VOLID, "note": FROZEN_NOTE}) == {
        "state": "removed"
    }
    assert [c[:2] for c in commands if c[0] in ("pvesh", "pvesm")][1:] == [
        ["pvesh", "set"],
        ["pvesm", "free"],
    ]
    # Not another freeze's backup, and not a backup of the cluster's own.
    with pytest.raises(ValueError, match="frozen machine"):
        module.backup_remove({"machine": dict(MACHINE), "volid": VOLID, "note": "carrel-freeze b09 other"})
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [backup(notes="manual backup")])
    with pytest.raises(ValueError, match="frozen machine"):
        module.backup_remove({"machine": dict(MACHINE), "volid": VOLID})
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [])
    assert module.backup_remove({"machine": dict(MACHINE), "volid": VOLID}) == {"state": "absent"}


def test_platform_check_repairs_what_a_boot_loses(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", "carrel01")
    real = module.Path
    lxc = tmp_path / "lxc"
    lxc.mkdir()
    (lxc / "101.conf").write_text("net0: name=eth0,bridge=vmbr98,mtu=1450,type=veth\ntags: carrel-infra\n")
    (lxc / "103.conf").write_text("net0: name=eth0,bridge=t255,mtu=1450,type=veth\ntags: carrel-infra\n")
    monkeypatch.setattr(
        module,
        "Path",
        lambda p: lxc / real(p).name if str(p).startswith("/etc/pve/nodes/carrel01/lxc/") else real(p),
    )
    calls = []
    answers = {
        ("nft", "list"): "chain forward {\n}",
        ("pct", "status", "101"): "status: running",
        ("pct", "status", "103"): "status: stopped",
        ("pct", "exec", "101", "--", "cat", "/sys/class/net/eth0/mtu"): "1500",
        (
            "pct",
            "exec",
            "101",
            "--",
            "cat",
            "/etc/network/interfaces",
        ): "iface eth0 inet static\n\taddress 10.200.0.2/24",
    }

    def run(*args, **kwargs):
        args = tuple(str(a) for a in args)
        calls.append(args)
        return next((v for k, v in answers.items() if args[: len(k)] == k), "")

    monkeypatch.setattr(module, "run", run)
    out = module.platform_check(repair=False)
    assert not any(c[0] in ("ip", "systemctl") or "set" in c or "sed" in c for c in calls)
    assert len(out["needs_repair"]) == 4 and out["repaired"] == []
    calls.clear()
    out = module.platform_check()
    assert calls[0] == ("ip", "route", "flush", "cache")
    assert ("systemctl", "reload", "carrel-tenant-host") in calls
    assert ("pct", "exec", "101", "--", "ip", "link", "set", "eth0", "mtu", "1450") in calls
    assert any(c[:6] == ("pct", "exec", "101", "--", "sed", "-i") for c in calls)
    assert out["problems"] == ["infra CT 103 is not running"]
    assert len(out["repaired"]) == 4
    # Nothing to repair the second time: CTs absent from this node are skipped.
    calls.clear()
    answers[("nft", "list")] = "tcp option maxseg size set 1410"
    answers[("pct", "exec", "101", "--", "cat", "/sys/class/net/eth0/mtu")] = "1450"
    answers[("pct", "exec", "101", "--", "cat", "/etc/network/interfaces")] = "\tmtu 1450"
    assert module.platform_check()["repaired"] == ["route cache flushed"]
    # A CT without the static stanza is reported, not claimed as fixed.
    calls.clear()
    answers[("pct", "exec", "101", "--", "cat", "/etc/network/interfaces")] = "iface eth0 inet dhcp"
    out = module.platform_check()
    assert out["repaired"] == ["route cache flushed"] and not any("sed" in c for c in calls)
    assert "infra CT 101 has no static eth0 stanza for the mtu line" in out["problems"]


def test_thaw_never_destroys_a_cut_off_restore_of_another_tenant(monkeypatch, tmp_path):
    # lock=create with tags written already, but another tenant's (#192).
    module, commands, _nodes = thawer(
        monkeypatch, tmp_path, config={"lock": "create", "name": MACHINE["name"], "tags": "carrel;tenant-9"}
    )
    with pytest.raises(ValueError, match="in use"):
        module.thaw({"machine": dict(MACHINE), "volid": VOLID, "discard": True})
    assert not any(c[:2] in (["qm", "destroy"], ["qm", "unlock"]) for c in commands)


def test_freeze_refuses_at_once_when_the_backup_server_does_not_verify_new_snapshots(monkeypatch, tmp_path):
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [backup()] if dumped(c) else [])
    monkeypatch.setattr(module, "pbs_verify_new", lambda storage: False)
    with pytest.raises(module.CommandFailure, match="Verify New Snapshots"):
        module.freeze(REQUEST)
    assert not dumped(commands)
    # Unknown: the freeze proceeds and the verification wait decides.
    monkeypatch.setattr(module, "pbs_verify_new", lambda storage: None)
    assert module.freeze(REQUEST)["verification"] == "ok"


def test_pbs_verify_new_sends_no_token_before_the_fingerprint_matches(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(
        module,
        "storage_entry",
        lambda storage: {
            "type": "pbs",
            "server": "pbs.example",
            "datastore": "d",
            "username": "u@pbs!t",
            "fingerprint": "AA:BB",
        },
    )
    (tmp_path / "pbs.pw").write_text("secret\n")
    monkeypatch.setattr(module, "PBS_SECRETS", tmp_path)
    sent = []

    class Connection:
        def __init__(self, *a, **kw):
            self.sock = type("S", (), {"getpeercert": lambda self, binary_form=True: b"other-cert"})()

        def connect(self):
            pass

        def close(self):
            pass

        def request(self, *a, **kw):
            sent.append(kw.get("headers", {}))

    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    assert module.pbs_verify_new("pbs") is None
    assert sent == []


def test_pbs_verify_new_is_unknown_without_a_server_or_secret(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "storage_entry", lambda storage: {"type": "pbs"})
    assert module.pbs_verify_new("pbs") is None
    monkeypatch.setattr(
        module,
        "storage_entry",
        lambda storage: {"type": "pbs", "server": "pbs.example", "datastore": "d", "username": "u@pbs!t"},
    )
    monkeypatch.setattr(module, "PBS_SECRETS", tmp_path)
    assert module.pbs_verify_new("pbs") is None


def test_backup_sweep_removes_only_old_orphaned_freeze_backups(monkeypatch, tmp_path):
    import time as _time

    now = int(_time.time())
    listing = [
        backup(volid=VOLID, notes=FROZEN_NOTE, ctime=now - 30 * 86400),  # kept by its row
        backup(volid=OLD_VOLID, notes="carrel-freeze b09 gone", ctime=now - 30 * 86400),  # orphan, old
        backup(
            volid="pbs:backup/vm/10101/2026-10-29T00:00:00Z",
            notes="carrel-freeze b09 fresh",
            ctime=now - 3600,
        ),  # orphan, young
        backup(volid=SCHEDULED_VOLID, notes="nightly", ctime=now - 60 * 86400),  # the cluster's own
        backup(
            volid="pbs:backup/vm/10102/2026-10-20T00:00:00Z", notes="carrel-freeze b09 noage"
        ),  # age unknown
        backup(
            volid="pbs:backup/vm/10103/2026-10-01T00:00:00Z",
            notes="carrel-freeze b09 op9 keep",
            ctime=now - 30 * 86400,
        ),  # note edited, volume still named
    ]
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: listing)
    out = module.backup_sweep(
        {
            "storage": "pbs",
            "keep": [FROZEN_NOTE],
            "keep_volids": ["pbs:backup/vm/10103/2026-10-01T00:00:00Z"],
            "older_than": 7 * 86400,
        }
    )
    assert out == {
        "orphans": [
            OLD_VOLID,
            "pbs:backup/vm/10101/2026-10-29T00:00:00Z",
            "pbs:backup/vm/10102/2026-10-20T00:00:00Z",
        ],
        "removed": [OLD_VOLID],
    }
    assert freed(commands) == [OLD_VOLID]
    assert [
        "pvesh",
        "set",
        f"/nodes/carrel01/storage/pbs/content/{OLD_VOLID}",
        "--protected",
        "0",
    ] in commands or any(c[:2] == ["pvesh", "set"] for c in commands)


def test_freeze_leaves_another_sites_backup_of_the_same_vmid(monkeypatch, tmp_path):
    # Two sites freeze into one datastore and both have a machine 10100 (#202).
    theirs = backup(volid=OLD_VOLID, notes="carrel-freeze b10 op0")
    unsited = backup(volid=SCHEDULED_VOLID, notes="carrel-freeze op0")
    module, commands = freezer(
        monkeypatch,
        tmp_path,
        listing=lambda c: [theirs, unsited] + ([backup()] if dumped(c) else []),
    )
    assert module.freeze(REQUEST)["note"] == FROZEN_NOTE
    assert freed(commands) == []
    assert not protect_calls(commands)


def test_backup_sweep_reads_only_this_sites_notes(monkeypatch, tmp_path):
    import time as _time

    old = int(_time.time()) - 30 * 86400
    running = "pbs:backup/vm/10104/2026-10-01T00:00:00Z"
    listing = [
        backup(volid=VOLID, notes="carrel-freeze b10 gone", ctime=old),  # another site's
        backup(volid=OLD_VOLID, notes="carrel-freeze b091 gone", ctime=old),  # a longer site name
        backup(volid=SCHEDULED_VOLID, notes="carrel-freeze gone", ctime=old),  # written before #202
        backup(volid=running, notes="carrel-freeze b09 op7", ctime=old),  # a running freeze
    ]
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: listing)
    out = module.backup_sweep({"storage": "pbs", "keep": [], "keep_ids": ["op7"], "keep_volids": []})
    assert out == {"orphans": [], "removed": []}
    assert freed(commands) == []
    assert module.backup_sweep({"storage": "pbs"}) == {"orphans": [running], "removed": [running]}
    with pytest.raises(ValueError, match="invalid freeze id"):
        module.backup_sweep({"storage": "pbs", "keep_ids": ["op 7"]})
    with pytest.raises(ValueError, match="invalid keep list"):
        module.backup_sweep({"storage": "pbs", "keep_ids": "op7"})


def test_backup_remove_without_a_note_takes_only_this_sites_backup(monkeypatch, tmp_path):
    for notes in ("carrel-freeze b10 op1", "carrel-freeze op1"):
        module, commands = freezer(
            monkeypatch, tmp_path, listing=lambda c, notes=notes: [backup(notes=notes)]
        )
        with pytest.raises(ValueError, match="frozen machine"):
            module.backup_remove({"machine": dict(MACHINE), "volid": VOLID})
        assert freed(commands) == []
        # The record that names it still removes a backup written before #202.
        assert module.backup_remove({"machine": dict(MACHINE), "volid": VOLID, "note": notes}) == {
            "state": "removed"
        }
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [backup()])
    assert module.backup_remove({"machine": dict(MACHINE), "volid": VOLID}) == {"state": "removed"}


@pytest.mark.parametrize("content", [None, {}, {"site": "B09"}, {"site": "b09 x"}, {"site": 9}])
def test_freeze_needs_a_site_name(monkeypatch, tmp_path, content):
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [])
    if content is None:
        (tmp_path / "site.json").unlink()
    else:
        (tmp_path / "site.json").write_text(json.dumps(content))
    with pytest.raises(ValueError, match="names no site"):
        module.freeze(REQUEST)
    with pytest.raises(ValueError, match="names no site"):
        module.backup_sweep({"storage": "pbs"})
    assert not dumped(commands) and freed(commands) == []


def test_vmids_present_sees_guests_on_any_node_regardless_of_acl(monkeypatch, tmp_path):
    module = load("node-agent.py")
    (tmp_path / "pve01" / "qemu-server").mkdir(parents=True)
    (tmp_path / "pve02" / "lxc").mkdir(parents=True)
    (tmp_path / "pve01" / "qemu-server" / "10204.conf").write_text("")
    (tmp_path / "pve02" / "lxc" / "10206.conf").write_text("")
    monkeypatch.setattr(module, "PVE_NODES", tmp_path)
    monkeypatch.setattr(module, "NODE", "pve01")
    assert module.vmids_present([10204, 10205, 10206]) == [10204, 10206]
    with pytest.raises(ValueError):
        module.vmids_present("10204")


def test_vmids_present_scans_twice_so_a_migration_mid_scan_is_seen(monkeypatch, tmp_path):
    module = load("node-agent.py")
    (tmp_path / "pve01" / "qemu-server").mkdir(parents=True)
    (tmp_path / "pve02" / "qemu-server").mkdir(parents=True)
    conf = tmp_path / "pve02" / "qemu-server" / "10204.conf"
    conf.write_text("")
    monkeypatch.setattr(module, "PVE_NODES", tmp_path)
    monkeypatch.setattr(module, "NODE", "pve01")
    real_listdir = module.os.listdir
    real_scandir = module.os.scandir
    moved = []

    class Ordered:
        # List the node directories as pve01 then pve02, whatever the filesystem order.
        def __init__(self, path):
            self.scan = real_scandir(path)

        def __enter__(self):
            entries = list(self.scan.__enter__())
            return iter(sorted(entries, key=lambda e: e.name))

        def __exit__(self, *exc):
            return self.scan.__exit__(*exc)

    def migrating(path):
        # The first pass reads pve01, then pve02 after the config moved to pve01,
        # so a single pass misses it; the second pass sees it on pve01.
        if not moved and "pve02" in str(path):
            moved.append(path)
            conf.rename(tmp_path / "pve01" / "qemu-server" / "10204.conf")
            return []
        return real_listdir(path)

    monkeypatch.setattr(module.os, "scandir", Ordered)
    monkeypatch.setattr(module.os, "listdir", migrating)
    assert module.vmids_present([10204]) == [10204]


def test_vmids_present_fails_when_the_config_tree_is_unreadable(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", "pve01")
    monkeypatch.setattr(module, "PVE_NODES", tmp_path / "missing")
    with pytest.raises(RuntimeError, match="not readable"):
        module.vmids_present([10204])
    (tmp_path / "pve02" / "qemu-server").mkdir(parents=True)
    monkeypatch.setattr(module, "PVE_NODES", tmp_path)
    with pytest.raises(RuntimeError, match="not readable"):
        module.vmids_present([10204])
    (tmp_path / "pve01" / "qemu-server").mkdir(parents=True)

    def denied(path):
        raise PermissionError(path)

    monkeypatch.setattr(module.os, "listdir", denied)
    with pytest.raises(PermissionError):
        module.vmids_present([10204])


USER_CA = "ecdsa-sha2-nistp256 " + "A" * 140 + "="


def cloud_config(module, monkeypatch, m):
    root = Path(__file__).parents[1]
    files = {}
    monkeypatch.setattr(module, "write", lambda path, data, mode: files.update({path: data}))
    monkeypatch.setattr(
        module,
        "Path",
        lambda path: (
            root / "scripts/guest-report.py"
            if path == "/usr/local/lib/carrel/guest-report.py"
            else Path(path)
        ),
    )
    module.cloud_init(m)
    return json.loads(files[f"/var/lib/vz/snippets/carrel-{m['vmid']}-user.json"].split("\n", 1)[1])


@pytest.mark.parametrize("token", ["test-only", None])
def test_a_vm_trusts_the_lab_ca_for_its_creator_before_sshd_starts(monkeypatch, token):
    module = load("node-agent.py")
    m = {**MACHINE, "readiness_token": token, "ssh_user_ca": USER_CA, "ca_principals": ["alice"]}
    config = cloud_config(module, monkeypatch, m)
    files = {f["path"]: f for f in config["write_files"]}
    assert files["/etc/ssh/ssh_user_ca.pub"]["content"] == USER_CA + "\n"
    assert files["/etc/ssh/sshd_config.d/50-carrel-user-ca.conf"]["content"] == (
        "TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub\nAuthorizedPrincipalsFile /etc/ssh/principals/%u\n"
    )
    assert files["/etc/ssh/principals/user"]["content"] == "alice\n"
    assert all(files[p]["permissions"] == "0644" for p in files if p.startswith("/etc/ssh/"))
    # Keys stay: the CA is in addition to them.
    assert config["users"][0]["ssh_authorized_keys"] == [KEY]
    # write_files, not runcmd: nothing waits for a reload.
    assert not any("ssh" in " ".join(c) for c in config["runcmd"])


def test_a_vm_without_a_lab_ca_gets_no_ca_files(monkeypatch):
    module = load("node-agent.py")
    config = cloud_config(module, monkeypatch, dict(MACHINE))
    assert not any(f["path"].startswith("/etc/ssh/") for f in config["write_files"])


@pytest.mark.parametrize(
    "bad",
    [
        {"ssh_user_ca": USER_CA + " comment", "ca_principals": ["alice"]},
        {"ssh_user_ca": USER_CA + "\nssh-ed25519 AAAA", "ca_principals": ["alice"]},
        {"ssh_user_ca": USER_CA, "ca_principals": []},
        {"ssh_user_ca": USER_CA, "ca_principals": ["alice\nroot"]},
        {"ssh_user_ca": USER_CA, "ca_principals": ["../root"]},
        {"ssh_user_ca": USER_CA, "ca_principals": ["project:"]},
        {"ssh_user_ca": USER_CA, "ca_principals": ["project:Demo"]},
        {"ssh_user_ca": USER_CA, "ca_principals": ["project:demo\nroot"]},
        {"ssh_user_ca": USER_CA, "ca_principals": ["svc:demo"]},
    ],
)
def test_ca_files_refuse_anything_but_one_key_and_plain_usernames(bad):
    module = load("node-agent.py")
    with pytest.raises(ValueError):
        module.ca_files({**MACHINE, **bad}, "user")


def test_a_ct_gets_the_ca_files_for_root():
    module = load("node-agent.py")
    files = dict(
        module.ca_files({**MACHINE, "kind": "ct", "ssh_user_ca": USER_CA, "ca_principals": ["alice"]}, "root")
    )
    assert files["/etc/ssh/principals/root"] == "alice\n"


def test_a_project_machine_admits_the_project_group():
    module = load("node-agent.py")
    files = dict(
        module.ca_files({**MACHINE, "ssh_user_ca": USER_CA, "ca_principals": ["project:iii-edge-ai"]}, "user")
    )
    assert files["/etc/ssh/principals/user"] == "project:iii-edge-ai\n"


def test_a_ct_takes_principals_only_as_a_clean_list(monkeypatch):
    module = load("node-agent.py")
    calls = []
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append(a) or "status: running")
    monkeypatch.setattr(module, "write", lambda *a, **kw: None)
    ct = {**MACHINE, "kind": "ct"}
    assert module.action({"machine": ct, "action": "principals", "principals": ["alice", "bob"]}) == {
        "state": "applied"
    }
    assert any(c[:2] == ("pct", "push") and c[-3] == "/etc/ssh/principals/root" for c in calls)
    for bad in ([], ["alice\nroot"], ["svc:x"], "alice", ["a"] * 52):
        with pytest.raises(ValueError):
            module.action({"machine": ct, "action": "principals", "principals": bad})
    with pytest.raises(ValueError):
        module.action({"machine": MACHINE, "action": "principals", "principals": ["alice"]})


def test_guest_sets_prune_removes_only_sets_of_guests_that_left():
    module = load("node-agent.py")
    sets = [
        "v4-guest-10306/ipfilter-net0",
        "v6-guest-10306/ipfilter-net0",
        "v4-guest-10307/ipfilter-net0",
        "other",
    ]
    listing = {
        "nftables": [
            {"metainfo": {}},
            *({"set": {"name": n}} for n in sets),
            {"chain": {"name": "guest-10307-in"}},
        ]
    }
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        return json.dumps(listing) if args[1] == "-j" else ""

    pruned = module.guest_sets_prune(run)
    assert pruned == ["v4-guest-10306/ipfilter-net0", "v6-guest-10306/ipfilter-net0"]
    assert all(c[:5] == ("nft", "delete", "set", "bridge", "proxmox-firewall-guests") for c in calls[1:])


def test_guest_sets_prune_ignores_a_node_without_the_table():
    module = load("node-agent.py")

    def run(*args, **kwargs):
        raise module.CommandFailure("no table")

    assert module.guest_sets_prune(run) == []


CA = "ssh-ed25519 " + "B" * 43


def backfill_setup(
    monkeypatch,
    tmp_path,
    power="stopped",
    fail_mount=False,
    fail_connect=False,
    fail_umount=False,
    pve_lock=None,
    fstype="ext4",
):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "owned", lambda m: {"lock": pve_lock} if pve_lock else {})
    root = Path(__file__).parents[1]
    guest = tmp_path / "guest"
    guest.mkdir()
    (guest / "etc/ssh").mkdir(parents=True)
    (guest / "etc/os-release").write_text("ID=debian\n")
    calls = []
    monkeypatch.setattr(module, "disk_volume", lambda m: {"disk_volume": "local-zfs:vm-10100-disk-0"})
    monkeypatch.setattr(module, "power_status", lambda m: power)
    monkeypatch.setattr(module, "free_nbd", lambda: "/dev/nbd0")
    monkeypatch.setattr(module, "root_partitions", lambda device: [(device + "p1", fstype)])
    real_mkdtemp = module.tempfile.mkdtemp
    parents = []

    def mkdtemp(prefix):
        parents.append(Path(real_mkdtemp(prefix=prefix, dir=tmp_path)))
        return str(parents[-1])

    monkeypatch.setattr(module.tempfile, "mkdtemp", mkdtemp)
    monkeypatch.setattr(module.os, "fchown", lambda *a: None)
    monkeypatch.setattr(
        module,
        "write",
        lambda *a, **k: pytest.fail("the cloud-init seed must not be written"),
    )
    real_path = module.Path
    monkeypatch.setattr(
        module,
        "Path",
        lambda p: (
            root / "scripts/guest-report.py" if p == "/usr/local/lib/carrel/guest-report.py" else real_path(p)
        ),
    )

    def run(*a, **k):
        calls.append([str(x) for x in a])
        if a[0] == "qemu-nbd" and a[1].startswith("--connect") and fail_connect:
            raise module.CommandFailure("connect failed")
        if a[0] == "mount" and fail_mount:
            raise module.CommandFailure("mount failed")
        if a[0] == "mount":
            # stand in for the mount: the target becomes the guest root
            target = Path(a[-1])
            assert target.parent in parents and target.parent.stat().st_mode & 0o777 == 0o700
            target.rmdir()
            target.symlink_to(guest)
        if a[0] == "mountpoint" and not Path(a[-1]).is_symlink():
            raise module.CommandFailure("not a mountpoint")
        if a[0] == "umount" and fail_umount:
            raise module.CommandFailure("umount failed: target is busy")
        if a[0] == "umount" and Path(a[-1]).is_symlink():
            Path(a[-1]).unlink()
            Path(a[-1]).mkdir(0o700)
        if a[0] == "pvs":
            return "  guestvg\n  guestvg\n"
        return "/dev/zvol/rpool/vm-10100-disk-0" if a[0] == "pvesm" else ""

    monkeypatch.setattr(module, "run", run)
    module.backfill_parents = parents
    return module, guest, calls


def test_ca_backfill_writes_the_ca_files_and_reporter_and_is_idempotent(monkeypatch, tmp_path):
    module, guest, calls = backfill_setup(monkeypatch, tmp_path)
    vm = dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice", "project:lab"])
    module.ca_backfill(vm)
    first = {
        p.relative_to(guest): (p.read_text(), p.stat().st_mode & 0o777)
        for p in guest.rglob("*")
        if p.is_file()
    }
    assert first[Path("etc/ssh/ssh_user_ca.pub")] == (CA + "\n", 0o644)
    assert first[Path("etc/ssh/sshd_config.d/50-carrel-user-ca.conf")][1] == 0o644
    assert first[Path("etc/ssh/principals/user")] == ("alice\nproject:lab\n", 0o644)
    reporter = Path(__file__).parents[1] / "scripts/guest-report.py"
    assert first[Path("usr/local/lib/carrel/guest-report.py")] == (reporter.read_text(), 0o755)
    assert len(first) == 5  # the four written files and the fixture os-release
    assert [c[0] for c in calls if c[0] in ("qemu-nbd", "mount", "umount")] == [
        "qemu-nbd",
        "mount",
        "umount",
        "qemu-nbd",
    ]
    module.ca_backfill(vm)
    second = {
        p.relative_to(guest): (p.read_text(), p.stat().st_mode & 0o777)
        for p in guest.rglob("*")
        if p.is_file()
    }
    assert second == first


def test_ca_backfill_refuses_a_machine_that_is_not_stopped(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path, power="running")
    with pytest.raises(ValueError, match="stop"):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert not any(c[0] in ("qemu-nbd", "mount") for c in calls)


def test_ca_backfill_disconnects_the_nbd_device_when_a_step_fails(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path, fail_mount=True)
    with pytest.raises(module.CommandFailure):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert calls[-1] == ["qemu-nbd", "--disconnect", "/dev/nbd0"]
    assert not any(c[0] == "umount" for c in calls)


def test_ca_backfill_keeps_the_nbd_device_when_umount_keeps_failing(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path, fail_umount=True)
    with pytest.raises(module.CommandFailure, match="/dev/nbd0.*carrel-backfill"):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    umounts = [c for c in calls if c[0] == "umount"]
    assert [c[1] for c in umounts] == [umounts[0][1], umounts[0][1], "-l"]
    assert not any(c[0] in ("vgchange", "pvs") for c in calls)
    assert not any(c[:2] == ["qemu-nbd", "--disconnect"] for c in calls)


def test_ca_backfill_unmounts_a_timed_out_mount_before_disconnecting(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path)
    run = module.run

    def timing_out(*a, **k):
        out = run(*a, **k)
        if a[0] == "mount":
            raise module.subprocess.TimeoutExpired(a, 180)
        return out

    monkeypatch.setattr(module, "run", timing_out)
    with pytest.raises(module.subprocess.TimeoutExpired):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    names = [c[0] for c in calls if c[0] in ("mount", "umount", "qemu-nbd")]
    assert names == ["qemu-nbd", "mount", "umount", "qemu-nbd"]


def test_ca_backfill_does_not_follow_a_guest_symlink_out_of_the_disk(monkeypatch, tmp_path):
    module, guest, _ = backfill_setup(monkeypatch, tmp_path)
    outside = tmp_path / "host-etc"
    outside.mkdir()
    (guest / "etc/ssh/principals").symlink_to(outside)
    with pytest.raises(OSError):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert list(outside.iterdir()) == []


def test_ca_backfill_leaves_an_nbd_device_it_did_not_connect_alone(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path, fail_connect=True)
    with pytest.raises(module.CommandFailure, match="connect"):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert not any(c[0] == "qemu-nbd" and c[1] == "--disconnect" for c in calls)
    assert not any(c[0] in ("mount", "umount") for c in calls)


def test_ca_backfill_mounts_below_a_private_dir_and_removes_both(monkeypatch, tmp_path):
    module, guest, calls = backfill_setup(monkeypatch, tmp_path)
    module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    (parent,) = module.backfill_parents
    mount = next(c for c in calls if c[0] == "mount")
    assert mount[1:5] == ["-t", "ext4", "-o", "nodev,nosuid,noexec,errors=remount-ro"]
    assert mount[-1] == str(parent / "root")
    assert not parent.exists()
    assert (guest / "etc/ssh/ssh_user_ca.pub").exists()


def test_ca_backfill_mounts_an_ext4_root_with_its_type_and_errors_remount_ro(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path, fstype="ext4")
    module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    mount = next(c for c in calls if c[0] == "mount")
    assert mount[1:3] == ["-t", "ext4"]
    assert "errors=remount-ro" in mount[4].split(",")


def test_ca_backfill_mounts_an_xfs_root_with_its_type_and_no_errors_option(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path, fstype="xfs")
    module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    mount = next(c for c in calls if c[0] == "mount")
    assert mount[1:5] == ["-t", "xfs", "-o", "nodev,nosuid,noexec"]


def test_root_partitions_lists_the_linux_partitions_largest_first(monkeypatch):
    module = load("node-agent.py")
    tree = {
        "blockdevices": [
            {
                "name": "nbd0",
                "type": "disk",
                "children": [
                    {"name": "nbd0p1", "size": "1048576", "type": "part", "fstype": "vfat"},
                    {"name": "nbd0p2", "size": "536870912", "type": "part", "fstype": "xfs"},
                    {"name": "nbd0p3", "size": "8589934592", "type": "part", "fstype": "ext4"},
                ],
            }
        ]
    }
    monkeypatch.setattr(module, "run", lambda *a, **k: json.dumps(tree) if a[0] == "lsblk" else "")
    assert module.root_partitions("/dev/nbd0") == [("/dev/nbd0p3", "ext4"), ("/dev/nbd0p2", "xfs")]


def test_ca_backfill_removes_the_mount_dirs_when_a_write_fails(monkeypatch, tmp_path):
    module, guest, calls = backfill_setup(monkeypatch, tmp_path)
    (guest / "etc/ssh/ssh_user_ca.pub").mkdir()
    with pytest.raises(OSError):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    (parent,) = module.backfill_parents
    assert [c[0] for c in calls if c[0] in ("mount", "umount")] == ["mount", "umount"]
    assert not parent.exists()


def test_ca_backfill_refuses_a_machine_whose_lock_a_migration_or_freeze_holds(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path)
    with (tmp_path / f"vm-{MACHINE['vmid']}.lock").open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(ValueError, match="busy"):
            module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert not any(c[0] == "qemu-nbd" for c in calls)


def test_ca_backfill_refuses_a_machine_with_a_proxmox_config_lock(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path, pve_lock="backup")
    with pytest.raises(ValueError, match="locked in Proxmox"):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert not any(c[0] == "qemu-nbd" for c in calls)


def test_ca_backfill_takes_the_node_lock_so_a_start_waits_for_it(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "ca_backfill", lambda m: {})
    locks = []
    monkeypatch.setattr(module.fcntl, "flock", lambda f, how: locks.append(Path(f.name).name))
    request = json.dumps({"op": "ca_backfill", "machine": MACHINE}).encode() + b"\n"
    monkeypatch.setattr(module.sys, "stdin", type("In", (), {"buffer": __import__("io").BytesIO(request)})())
    module.main()
    assert locks == ["node.lock"]


def test_ca_backfill_deactivates_a_guest_vg_on_the_nbd_device_before_disconnect(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path)
    module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    names = [c[0] if c[0] != "qemu-nbd" else c[1].split("=")[0] for c in calls]
    assert names.index("--connect") < names.index("udevadm") < names.index("pvs")
    assert names.index("umount") < names.index("pvs") < names.index("vgchange") < names.index("--disconnect")
    pvs = next(c for c in calls if c[0] == "pvs")
    vgchange = [c for c in calls if c[0] == "vgchange"]
    assert [c[-1] for c in vgchange] == ["guestvg"]
    for c in (pvs, *vgchange):
        config = c[c.index("--config") + 1]
        assert "global_filter" in config and "/dev/nbd0" in config and "r|.*|" in config


def test_ca_backfill_disconnects_even_when_the_vg_deactivation_fails(monkeypatch, tmp_path):
    module, _, calls = backfill_setup(monkeypatch, tmp_path)
    run = module.run

    def failing(*a, **k):
        if a[0] == "vgchange":
            raise module.CommandFailure("vgchange failed")
        return run(*a, **k)

    monkeypatch.setattr(module, "run", failing)
    with pytest.raises(module.CommandFailure):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert calls[-1] == ["qemu-nbd", "--disconnect", "/dev/nbd0"]


def multi_partition_setup(monkeypatch, tmp_path, partitions, roots, subvols=""):
    """partitions: [(device, fstype)] largest first; roots: {(device, subvol): guest dir}."""
    module, guest, calls = backfill_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "root_partitions", lambda device: partitions)
    run = module.run
    mounted = []

    def multi(*a, **k):
        if a[0] == "mount":
            opts = a[4].split(",")
            subvol = next((o[7:] for o in opts if o.startswith("subvol=")), None)
            source = roots[(a[5], subvol)]
            calls.append([str(x) for x in a])
            target = Path(a[-1])
            target.rmdir()
            target.symlink_to(source)
            mounted.append(target)
            return ""
        if a[0] == "btrfs":
            calls.append([str(x) for x in a])
            return subvols
        return run(*a, **k)

    monkeypatch.setattr(module, "run", multi)
    return module, guest, calls


def test_ca_backfill_skips_a_larger_data_partition_for_the_small_root(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    module, guest, calls = multi_partition_setup(
        monkeypatch,
        tmp_path,
        [("/dev/nbd0p2", "ext4"), ("/dev/nbd0p1", "ext4")],
        {("/dev/nbd0p2", None): data, ("/dev/nbd0p1", None): tmp_path / "guest"},
    )
    module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert (guest / "etc/ssh/ssh_user_ca.pub").exists()
    assert list(data.iterdir()) == []
    assert [c[-2] for c in calls if c[0] == "mount"] == ["/dev/nbd0p2", "/dev/nbd0p1"]
    assert [c[0] for c in calls].count("umount") == 2


def test_ca_backfill_fails_naming_the_partitions_when_none_is_a_root(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    module, _, calls = multi_partition_setup(
        monkeypatch,
        tmp_path,
        [("/dev/nbd0p2", "ext4"), ("/dev/nbd0p1", "xfs")],
        {("/dev/nbd0p2", None): data, ("/dev/nbd0p1", None): data},
    )
    with pytest.raises(module.CommandFailure, match="nbd0p2, /dev/nbd0p1"):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert list(data.iterdir()) == []
    assert calls[-1] == ["qemu-nbd", "--disconnect", "/dev/nbd0"]


def test_ca_backfill_mounts_the_at_subvolume_of_a_btrfs_top_level(monkeypatch, tmp_path):
    top = tmp_path / "top"
    top.mkdir()
    module, guest, calls = multi_partition_setup(
        monkeypatch,
        tmp_path,
        [("/dev/nbd0p1", "btrfs")],
        {("/dev/nbd0p1", None): top, ("/dev/nbd0p1", "@"): tmp_path / "guest"},
        subvols="ID 256 gen 8 top level 5 path @home\nID 257 gen 8 top level 5 path @\n",
    )
    module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    mounts = [c for c in calls if c[0] == "mount"]
    assert "subvol=@" in mounts[1][4].split(",")
    assert (guest / "etc/ssh/ssh_user_ca.pub").exists()
    assert list(top.iterdir()) == []


def test_ca_backfill_fails_on_btrfs_without_a_root_subvolume(monkeypatch, tmp_path):
    top = tmp_path / "top"
    top.mkdir()
    module, _, calls = multi_partition_setup(
        monkeypatch,
        tmp_path,
        [("/dev/nbd0p1", "btrfs")],
        {("/dev/nbd0p1", None): top},
        subvols="ID 256 gen 8 top level 5 path data\n",
    )
    with pytest.raises(module.CommandFailure, match="nbd0p1"):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert len([c for c in calls if c[0] == "mount"]) == 1


def test_ca_backfill_writes_the_principals_first_and_the_sshd_dropin_last(monkeypatch, tmp_path):
    module, _guest, _calls = backfill_setup(monkeypatch, tmp_path)
    order = []
    real = module.guest_write
    monkeypatch.setattr(
        module, "guest_write", lambda root, path, *a: (order.append(path), real(root, path, *a))
    )
    module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert order[0] == "/etc/ssh/principals/user"
    assert order[-1] == "/etc/ssh/sshd_config.d/50-carrel-user-ca.conf"
    assert order.index("/etc/ssh/ssh_user_ca.pub") < len(order) - 1


def test_ca_backfill_does_not_write_the_dropin_when_the_principals_write_fails(monkeypatch, tmp_path):
    module, guest, _calls = backfill_setup(monkeypatch, tmp_path)
    (guest / "etc/ssh/principals").mkdir(parents=True)
    (guest / "etc/ssh/principals/user").mkdir()
    with pytest.raises(OSError):
        module.ca_backfill(dict(MACHINE, ssh_user_ca=CA, ca_principals=["alice"]))
    assert not (guest / "etc/ssh/sshd_config.d/50-carrel-user-ca.conf").exists()
    assert not (guest / "etc/ssh/ssh_user_ca.pub").exists()


def test_guest_write_keeps_writing_after_a_short_write(monkeypatch, tmp_path):
    module, _guest, _calls = backfill_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(module.os, "fchown", lambda *a: None)
    real = module.os.write
    monkeypatch.setattr(module.os, "write", lambda fd, data: real(fd, bytes(data)[:3]))
    root = tmp_path / "root"
    root.mkdir()
    module.guest_write(str(root), "/etc/file", "0123456789", 0o644)
    assert (root / "etc/file").read_text() == "0123456789"


def test_guest_write_does_not_rename_when_the_write_stalls(monkeypatch, tmp_path):
    module, _guest, _calls = backfill_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(module.os, "fchown", lambda *a: None)
    real = module.os.write
    sent = []

    def stall(fd, data):
        if sent:
            return 0
        sent.append(1)
        return real(fd, bytes(data)[:3])

    monkeypatch.setattr(module.os, "write", stall)
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(OSError):
        module.guest_write(str(root), "/etc/file", "0123456789", 0o644)
    assert not (root / "etc/file").exists()


def test_guest_write_keeps_old_bytes_when_replacing_and_the_write_stalls(monkeypatch, tmp_path):
    module, _guest, _calls = backfill_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(module.os, "fchown", lambda *a: None)
    real = module.os.write
    sent = []

    def stall(fd, data):
        if sent:
            return 0
        sent.append(1)
        return real(fd, bytes(data)[:3])

    monkeypatch.setattr(module.os, "write", stall)
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    target = root / "etc/file"
    target.write_text("old-content")
    with pytest.raises(OSError):
        module.guest_write(str(root), "/etc/file", "0123456789", 0o644)
    assert target.read_text() == "old-content"


def test_inventory_programs_name_the_release_and_the_agent_digest(tmp_path, monkeypatch):
    agent = load("node-agent.py")
    monkeypatch.setattr(agent, "RELEASE", tmp_path / "release.json")
    digest = hashlib.sha256((Path(__file__).parents[1] / "scripts/node-agent.py").read_bytes()).hexdigest()
    assert agent.programs_info() == {"version": None, "node_agent_sha256": digest, "intact": False}
    (tmp_path / "release.json").write_text('{"version": "0.11.0", "sha256": {"node-agent.py": "0"}}')
    assert agent.programs_info()["version"] == "0.11.0" and agent.programs_info()["intact"] is False
    (tmp_path / "release.json").write_text(
        json.dumps({"version": "0.11.0", "sha256": {"node-agent.py": digest}})
    )
    assert agent.programs_info()["intact"] is True
    (tmp_path / "release.json").write_text("null")
    assert agent.programs_info()["version"] is None


def test_replay_does_nothing_while_a_reconcile_is_pending(monkeypatch, tmp_path):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "PENDING", tmp_path / "reconcile.pending")
    (tmp_path / "desired.json").write_text("{}")
    (tmp_path / "reconcile.pending").write_text("")

    def called(*a, **k):
        raise AssertionError("replay must not touch node files")

    monkeypatch.setattr(module, "private_dhcp", called)
    monkeypatch.setattr(module, "vpn", called)
    assert module.replay() == {"replayed": False, "skipped": "pending reconcile"}


def test_replay_unit_orders_after_pve_cluster_without_pulling_it_in():
    unit = load("node-agent.py").REPLAY_UNIT
    assert "After=pve-cluster.service" in unit
    assert "Wants=pve-cluster.service" not in unit


def _replay_module(monkeypatch, tmp_path, first):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "PENDING", tmp_path / "reconcile.pending")
    (tmp_path / "desired.json").write_text("{}")
    monkeypatch.setattr(module, "first_exit_node", lambda: first)
    monkeypatch.setattr(module, "site_ipv6", lambda: {"prefix": "2001:db8::/48"})
    return module


def test_replay_brings_back_the_site_ipv6_tunnel_and_reports_its_error(monkeypatch, tmp_path):
    module = _replay_module(monkeypatch, tmp_path, True)
    seen = []
    monkeypatch.setattr(module, "private_dhcp", lambda *a, **k: None)
    monkeypatch.setattr(module, "vpn", lambda state: {})
    monkeypatch.setattr(module, "ipv6", lambda state, v6: seen.append(v6) or {})
    assert module.replay()["replayed"] is True
    assert seen == [{"prefix": "2001:db8::/48"}]
    monkeypatch.setattr(module, "ipv6", lambda state, v6: {"error": "RuntimeError: nft"})
    with pytest.raises(RuntimeError, match="IPv6 replay failed"):
        module.replay()


def test_replay_on_a_node_that_is_not_the_first_exit_node_runs_dhcp_without_serving(monkeypatch, tmp_path):
    module = _replay_module(monkeypatch, tmp_path, False)
    serves = []
    monkeypatch.setattr(module, "private_dhcp", lambda state, serve=True: serves.append(serve))
    monkeypatch.setattr(module, "vpn", lambda state: {})
    monkeypatch.setattr(module, "ipv6", lambda state, v6: {})
    assert module.replay()["replayed"] is True
    # It still runs for the per-node work (IPv6 off on the private bridges),
    # but does not serve DHCP.
    assert serves == [False]


def test_a_failed_reconcile_keeps_the_pending_marker_and_a_good_one_clears_it(monkeypatch, tmp_path):
    module = load("node-agent.py")
    marker = tmp_path / "reconcile.pending"
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "PENDING", marker)
    monkeypatch.setattr(module, "CONFIG", tmp_path / "config.json")
    (tmp_path / "config.json").write_text("{}")
    monkeypatch.setattr(module, "topology_read", lambda: ({}, {}))
    monkeypatch.setattr(module, "site_ipv6", lambda: None)
    monkeypatch.setattr(module, "V6_OWNED", tmp_path / "ipv6-prefixes.json")
    monkeypatch.setattr(module, "run", lambda *a, **k: "")

    def boom(*a, **k):
        raise RuntimeError("mid-way")

    with monkeypatch.context() as m:
        m.setattr(module, "ensure", boom)
        with pytest.raises(RuntimeError):
            module.reconcile({"tenants": [{"n": 1, "slug": "a"}]})
    assert marker.exists()
    assert not (tmp_path / "desired.json").exists()
    for name in ("vpn", "ipv6", "guest_sets_prune"):
        monkeypatch.setattr(module, name, lambda *a, **k: {})
    monkeypatch.setattr(module, "public_ingress", lambda: "140.113.60.184")
    monkeypatch.setattr(module, "vip_targets", lambda state: {})
    monkeypatch.setattr(module, "first_exit_node", lambda: False)
    monkeypatch.setattr(module, "public_addresses", lambda *a, **k: {})
    real = module.write
    monkeypatch.setattr(
        module,
        "write",
        lambda path, data, mode=0o640: (
            real(path, data, mode) if Path(path).is_relative_to(tmp_path) else True
        ),
    )
    marker.write_text("")
    module.reconcile(
        {"tenants": [], "networks": [], "machines": [], "peers": [], "ports": [], "public_ips": []}
    )
    assert not marker.exists()
    assert (tmp_path / "desired.json").exists()


def _stub_reconcile(module, monkeypatch, tmp_path):
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "PENDING", tmp_path / "reconcile.pending")
    monkeypatch.setattr(module, "CONFIG", tmp_path / "config.json")
    (tmp_path / "config.json").write_text("{}")
    monkeypatch.setattr(module, "topology_read", lambda: ({}, {}))
    monkeypatch.setattr(module, "site_ipv6", lambda: None)
    monkeypatch.setattr(module, "V6_OWNED", tmp_path / "ipv6-prefixes.json")
    monkeypatch.setattr(module, "run", lambda *a, **k: "")
    for name in ("vpn", "ipv6", "guest_sets_prune"):
        monkeypatch.setattr(module, name, lambda *a, **k: {})
    monkeypatch.setattr(module, "private_dhcp", lambda *a, **k: None)
    monkeypatch.setattr(module, "public_ingress", lambda: None)
    monkeypatch.setattr(module, "public_addresses_release", lambda *a, **k: None)
    monkeypatch.setattr(module, "vip_targets", lambda state: {})
    monkeypatch.setattr(module, "first_exit_node", lambda: False)
    real = module.write
    monkeypatch.setattr(
        module,
        "write",
        lambda path, data, mode=0o640: (
            real(path, data, mode) if Path(path).is_relative_to(tmp_path) else True
        ),
    )


EMPTY_STATE = {"tenants": [], "networks": [], "machines": [], "peers": [], "ports": [], "public_ips": []}
REVISION = "a" * 64


def test_a_reconcile_that_fails_after_the_vpn_step_keeps_the_old_revision(monkeypatch, tmp_path):
    module = load("node-agent.py")
    _stub_reconcile(module, monkeypatch, tmp_path)
    (tmp_path / "desired-revision.json").write_text('{"revision": "old"}')

    def boom(*a, **k):
        raise RuntimeError("after vpn")

    monkeypatch.setattr(module, "ipv6", boom)
    with pytest.raises(RuntimeError):
        module.reconcile(EMPTY_STATE, revision=REVISION)
    assert json.loads((tmp_path / "desired-revision.json").read_text()) == {"revision": "old"}


def test_a_good_reconcile_writes_the_revision(monkeypatch, tmp_path):
    module = load("node-agent.py")
    _stub_reconcile(module, monkeypatch, tmp_path)
    module.reconcile(EMPTY_STATE, revision=REVISION)
    assert module.desired_info()["revision"] == REVISION


def test_a_reconcile_without_a_revision_removes_the_old_one(monkeypatch, tmp_path):
    module = load("node-agent.py")
    _stub_reconcile(module, monkeypatch, tmp_path)
    (tmp_path / "desired-revision.json").write_text('{"revision": "old"}')
    module.reconcile(EMPTY_STATE)
    assert not (tmp_path / "desired-revision.json").exists()
    assert module.desired_info() == {"revision": None}


def test_guest_tasks_reads_the_guests_active_tasks(monkeypatch, tmp_path, capsys):
    # machine_unfence (#682) reads them before it clears a plugin fence.
    module, _ = freezer(monkeypatch, tmp_path, listing=lambda c: [])
    reads = []
    monkeypatch.setattr(
        module, "pve_get", lambda resource, **params: reads.append((resource, params)) or [{"upid": "U"}]
    )
    request = json.dumps({"op": "guest_tasks", "machine": MACHINE}).encode() + b"\n"
    monkeypatch.setattr(module.sys, "stdin", type("In", (), {"buffer": __import__("io").BytesIO(request)})())
    module.main()
    assert reads == [(f"/nodes/{module.NODE}/tasks", {"vmid": MACHINE["vmid"], "source": "active"})]
    assert '"upid": "U"' in capsys.readouterr().out.replace('":"', '": "')


def test_a_failed_action_writes_its_cause_to_the_journal(monkeypatch):
    node = load("node-agent.py")
    logged = []
    monkeypatch.setattr("syslog.openlog", lambda *a: None)
    monkeypatch.setattr("syslog.syslog", lambda priority, message: logged.append(message))
    try:
        raise ValueError("network t005 has no subnet")
    except ValueError as e:
        answer = node.answer_failure(e)
    assert answer == {"ok": False, "error_code": "invalid_request", "error": "Node action failed"}
    assert len(logged) == 1
    assert logged[0].startswith("invalid_request: Traceback")
    assert "ValueError: network t005 has no subnet" in logged[0]


def created_user_file(monkeypatch, module, root):
    files = {}
    monkeypatch.setattr(module, "write", lambda path, data, mode: files.update({str(path): data}))
    monkeypatch.setattr(
        module,
        "Path",
        lambda path: (
            root / "scripts/guest-report.py"
            if path == "/usr/local/lib/carrel/guest-report.py"
            else Path(path)
        ),
    )
    module.cloud_init(
        {
            "name": "web",
            "vmid": 10100,
            "tenant_n": 1,
            "host": 10,
            "mac": "02:ca:01:00:00:01",
            "ip": "10.200.1.10",
            "image": "debian-13",
            "ssh_keys": [KEY],
            "packages": ["mininet"],
            "runcmd": [["touch", "/srv/ran-once"]],
            "readiness_token": "test-only",
            "swap_mb": 1024,
        }
    )
    monkeypatch.setattr(module, "Path", Path)
    return files["/var/lib/vz/snippets/carrel-10100-user.json"]


def test_a_reset_keeps_the_login_and_drops_every_creation_step(monkeypatch):
    root = Path(__file__).parents[1]
    module = load("node-agent.py")
    created = created_user_file(monkeypatch, module, root)
    new = "ssh-ed25519 AAAAnew owner@laptop"
    reset = module.reset_user_data(created, [new], "op-00000001")
    config = json.loads(reset.split("\n", 2)[2])
    assert config["users"][0]["name"] == "user"
    assert config["users"][0]["ssh_authorized_keys"] == [new]
    assert config["users"][0]["sudo"] == "ALL=(ALL) NOPASSWD:ALL"
    assert config["ssh_deletekeys"] is False
    assert config["hostname"] == "web" and config["disable_root"] is True and config["ssh_pwauth"] is False
    assert config["apt"] == {"preserve_sources_list": True}
    for step in ("runcmd", "packages", "package_update", "write_files", "swap"):
        assert step not in config
    # A retry after a lost answer writes the same bytes.
    assert module.reset_user_data(reset, [new], "op-00000001") == reset
    # A new reset with the same keys still changes the bytes, so cloud-init
    # sees a new instance and adds the keys again.
    assert module.reset_user_data(reset, [new], "op-00000002") != reset
    assert reset.split("\n")[1] == "# carrel reset op-00000001"


def test_a_reset_drops_an_unknown_top_level_key(monkeypatch):
    root = Path(__file__).parents[1]
    module = load("node-agent.py")
    created = created_user_file(monkeypatch, module, root)
    prefix, body = created.split("\n", 1)
    data = json.loads(body)
    data["future_step"] = ["echo again"]
    reset = module.reset_user_data(
        prefix + "\n" + json.dumps(data), ["ssh-ed25519 AAAAnew owner@laptop"], "op-00000001"
    )
    config = json.loads(reset.split("\n", 2)[2])
    assert "future_step" not in config
    assert set(config) <= set(module.RESET_KEPT) | {"ssh_deletekeys", "apt"}


def created_user_file_text():
    return '#cloud-config\n{"users": [{"name": "user"}]}'


def test_a_reset_refuses_a_file_carrel_did_not_write():
    module = load("node-agent.py")
    for raw in (
        "",
        "#cloud-config\n{}",
        "#cloud-config\nnot json",
        '#cloud-config\n{"users": []}',
        '#cloud-config\n{"users": [{"name": "root"}]}',
        "machine:\n  type: controlplane\n",
    ):
        with pytest.raises(ValueError):
            module.reset_user_data(raw, [KEY], "op-00000001")
    for bad_id in (None, "", "short", "a\nb" * 8, "x" * 65):
        with pytest.raises(ValueError):
            module.reset_user_data(created_user_file_text(), [KEY], bad_id)


def test_the_reset_action_writes_the_file_and_returns_both(monkeypatch, tmp_path):
    root = Path(__file__).parents[1]
    module = load("node-agent.py")
    created = created_user_file(monkeypatch, module, root)
    monkeypatch.setattr(module, "SNIPPETS", tmp_path)
    (tmp_path / "carrel-10100-user.json").write_text(created)
    (tmp_path / "carrel-10100-network.json").write_text('{"version": 2}')
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "write", lambda path, data, mode: Path(path).write_text(data))
    new = "ssh-ed25519 AAAAnew"
    got = module.action(
        {"machine": MACHINE, "action": "reset_access", "ssh_keys": [new], "reset_id": "op-00000001"}
    )
    assert got["cloud_init"]["user"] == (tmp_path / "carrel-10100-user.json").read_text()
    assert got["cloud_init"]["user"] == module.reset_user_data(created, [new], "op-00000001")
    assert got["cloud_init"]["network"] == '{"version": 2}'
    for bad in ([], ["command=x ssh-ed25519 AAAA"], "ssh-ed25519 AAAA", [7]):
        with pytest.raises((ValueError, TypeError)):
            module.action(
                {"machine": MACHINE, "action": "reset_access", "ssh_keys": bad, "reset_id": "op-00000001"}
            )
    with pytest.raises(ValueError):
        module.action(
            {
                "machine": {**MACHINE, "kind": "ct"},
                "action": "reset_access",
                "ssh_keys": [new],
                "reset_id": "op-00000001",
            }
        )


def test_a_reset_after_a_thaw_writes_the_stored_files_back_first(monkeypatch, tmp_path):
    root = Path(__file__).parents[1]
    module = load("node-agent.py")
    created = created_user_file(monkeypatch, module, root)
    monkeypatch.setattr(module, "SNIPPETS", tmp_path)
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "write", lambda path, data, mode: Path(path).write_text(data))
    request = {"machine": MACHINE, "action": "reset_access", "ssh_keys": [KEY], "reset_id": "op-00000001"}
    with pytest.raises(ValueError):
        module.action(request)
    got = module.action({**request, "cloud_init": {"user": created, "network": '{"version": 2}'}})
    assert got["cloud_init"]["user"] == module.reset_user_data(created, [KEY], "op-00000001")
    assert got["cloud_init"]["network"] == '{"version": 2}'


def test_a_reset_with_no_network_file_leaves_the_user_file_untouched(monkeypatch, tmp_path):
    root = Path(__file__).parents[1]
    module = load("node-agent.py")
    created = created_user_file(monkeypatch, module, root)
    monkeypatch.setattr(module, "SNIPPETS", tmp_path)
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "write", lambda path, data, mode: Path(path).write_text(data))
    (tmp_path / "carrel-10100-user.json").write_text(created)
    with pytest.raises(ValueError):
        module.action(
            {"machine": MACHINE, "action": "reset_access", "ssh_keys": [KEY], "reset_id": "op-00000001"}
        )
    assert (tmp_path / "carrel-10100-user.json").read_text() == created


def test_a_retried_create_keeps_the_user_file_a_reset_wrote(monkeypatch, tmp_path):
    root = Path(__file__).parents[1]
    module = load("node-agent.py")
    created = created_user_file(monkeypatch, module, root)
    snippets = tmp_path / "snippets"
    state = tmp_path / "state"
    snippets.mkdir()
    state.mkdir()
    monkeypatch.setattr(module, "SNIPPETS", snippets)
    monkeypatch.setattr(module, "STATE", state)
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "write", lambda path, data, mode: Path(path).write_text(data))
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("a retry must not reconfigure the VM"))
    real_exists = Path.exists
    monkeypatch.setattr(
        module.Path,
        "exists",
        lambda self: True if str(self) == "/etc/pve/qemu-server/10100.conf" else real_exists(self),
    )
    (snippets / "carrel-10100-user.json").write_text(created)
    (snippets / "carrel-10100-network.json").write_text('{"version": 2}')
    reset = module.action(
        {"machine": MACHINE, "action": "reset_access", "ssh_keys": [KEY], "reset_id": "op-00000001"}
    )["cloud_init"]["user"]
    marker = module.provision_marker(MACHINE)
    (state / "create-10100.json").write_text(json.dumps({"marker": marker, "complete": True}))
    got = module.create(MACHINE)
    assert got["state"] == "exists"
    assert (snippets / "carrel-10100-user.json").read_text() == reset
    assert got["cloud_init"]["user"] == reset


@pytest.mark.parametrize(
    "kind,tool,existing,expected",
    [
        ("vm", "qm", None, "carrel;tenant-1"),
        ("ct", "pct", None, "carrel;tenant-1"),
        ("vm", "qm", "keep;carrel", "keep;carrel;tenant-1"),
        ("ct", "pct", "keep;carrel;tenant-1", None),
    ],
)
def test_import_finish_tags_the_guest_once(monkeypatch, kind, tool, existing, expected):
    module = load("node-agent.py")
    config = {} if existing is None else {"tags": existing}
    monkeypatch.setattr(module, "pve_get", lambda *a: config)
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "storage_id", lambda: "tank")
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **k: calls.append(a) or "")
    req = {"tenant_n": 1, "vmid": 10100, "kind": kind, "hop_storage": "", "bwlimit": 51200}
    assert module.import_finish(req) == {"state": "done", "moved": []}
    if expected is None:
        assert calls == []
    else:
        assert calls == [(tool, "set", 10100, "--tags", expected)]


@pytest.mark.parametrize("change", [{"bwlimit": 0}, {"hop_storage": "Bad Hop"}, {"kind": "pod"}])
def test_import_finish_validates_before_tagging(monkeypatch, change):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "pve_get", lambda *a: {})
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **k: calls.append(a) or "")
    req = {"tenant_n": 1, "vmid": 10100, "kind": "vm", "hop_storage": "local", "bwlimit": 51200, **change}
    with pytest.raises(ValueError):
        module.import_finish(req)
    assert calls == []


@pytest.mark.parametrize("kind", ["vm", "ct"])
def test_import_network_normalizes_net0_and_the_address(monkeypatch, kind):
    module = load("node-agent.py")
    m = {**MACHINE, "kind": kind}
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "located", lambda m: "pve1")
    monkeypatch.setattr(module, "owned", lambda m, **kw: {"net0": "name=eth7,bridge=vmbr0,ip=dhcp"})
    calls, firewall = [], []
    monkeypatch.setattr(module, "run", lambda *a, **k: calls.append(a) or "")
    monkeypatch.setattr(module, "first_firewall", lambda m: firewall.append(m["vmid"]))
    monkeypatch.setattr(module, "guest_mtu", lambda m: 1450)
    monkeypatch.setattr(module, "storage_id", lambda: "tank")
    assert module.import_network({"machine": m}) == {"state": "done"}
    assert firewall == [10100]
    [call] = calls
    if kind == "vm":
        assert call == (
            "qm",
            "set",
            10100,
            "--net0",
            "virtio=02:ca:01:00:00:01,bridge=t001,firewall=1,mtu=1",
            "--ipconfig0",
            "ip=10.200.1.10/24,gw=10.200.1.1",
            "--nameserver",
            "10.200.0.2",
            "--ciupgrade",
            "0",
            "--cpu",
            "x86-64-v3",
            "--ide2",
            "tank:cloudinit",
        )
    else:
        assert call == (
            "pct",
            "set",
            10100,
            "--net0",
            "name=eth7,bridge=t001,firewall=1,hwaddr=02:ca:01:00:00:01,mtu=1450,ip=10.200.1.10/24,gw=10.200.1.1,type=veth",
            "--nameserver",
            "10.200.0.2",
        )


def test_import_verify_boots_a_vm_and_reads_the_agent(monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "located", lambda m: "pve1")
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "pve_get", lambda *a, **k: {"status": "stopped"})
    monkeypatch.setattr(module.time, "sleep", lambda s: None)
    calls = []

    def fake_run(*a, **k):
        calls.append(a)
        if a[-1] == "network-get-interfaces":
            return json.dumps(
                [
                    {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
                    {
                        "name": "eth0",
                        "ip-addresses": [
                            {"ip-address": "10.200.1.10", "ip-address-type": "ipv4"},
                            {"ip-address": "fe80::1", "ip-address-type": "ipv6"},
                        ],
                    },
                ]
            )
        if a[-1] == "info":
            return json.dumps(
                {
                    "version": "9.0",
                    "supported_commands": [
                        {"name": "guest-ping", "enabled": True},
                        {"name": "guest-exec", "enabled": False},
                    ],
                }
            )
        return ""

    monkeypatch.setattr(module, "run", fake_run)
    out = module.import_verify({"machine": {**MACHINE, "kind": "vm"}})
    assert calls[0] == ("qm", "start", 10100)
    assert calls[-1] == ("qm", "guest", "cmd", 10100, "info")
    assert out["addresses"] == ["10.200.1.10"]
    assert out["guest_info"] == {"version": "9.0", "enabled": ["guest-ping"]}


def test_import_verify_waits_past_a_loopback_only_report(monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "located", lambda m: "pve1")
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "pve_get", lambda *a, **k: {"status": "running"})
    monkeypatch.setattr(module.time, "sleep", lambda s: None)
    lo = {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]}
    eth = {"name": "eth0", "ip-addresses": [{"ip-address": "10.200.1.10", "ip-address-type": "ipv4"}]}
    reports = [[lo], [lo, {"name": "eth0", "ip-addresses": []}], [lo, eth]]
    calls = []

    def fake_run(*a, **k):
        calls.append(a)
        if a[-1] == "network-get-interfaces":
            return json.dumps(reports.pop(0))
        return json.dumps({"version": "9.0", "supported_commands": []})

    monkeypatch.setattr(module, "run", fake_run)
    out = module.import_verify({"machine": {**MACHINE, "kind": "vm"}})
    assert reports == []
    assert out["addresses"] == ["10.200.1.10"]
    assert out["guest_info"] == {"version": "9.0", "enabled": []}
    assert calls[-1] == ("qm", "guest", "cmd", 10100, "info")


def test_import_verify_a_ct_reads_lxc_info_and_has_no_guest_info(monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "located", lambda m: "pve1")
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "pve_get", lambda *a, **k: {"status": "running"})
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **k: calls.append(a) or "10.200.1.10")
    out = module.import_verify({"machine": {**MACHINE, "kind": "ct"}})
    assert calls == [("lxc-info", "-n", 10100, "-iH")]
    assert out == {"state": "done", "addresses": ["10.200.1.10"], "guest_info": None}


def test_import_verify_with_no_address_reports_none(monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "located", lambda m: "pve1")
    monkeypatch.setattr(module, "owned", lambda m, **kw: {})
    monkeypatch.setattr(module, "pve_get", lambda *a, **k: {"status": "running"})

    def fail(*a, **k):
        raise module.CommandFailure("agent not running")

    monkeypatch.setattr(module, "run", fail)
    out = module.import_verify({"machine": {**MACHINE, "kind": "vm"}, "seconds": 1})
    assert out == {"state": "done", "addresses": [], "guest_info": None}


def test_import_verify_refuses_a_guest_with_a_second_nic(monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "located", lambda m: "pve1")
    monkeypatch.setattr(
        module,
        "owned",
        lambda m, **kw: {"net0": "virtio=x,bridge=t001", "net1": "virtio=y,bridge=t001,firewall=0"},
    )
    monkeypatch.setattr(module, "pve_get", lambda *a, **k: {"status": "stopped"})
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **k: calls.append(a) or "")
    with pytest.raises(ValueError, match="net1"):
        module.import_verify({"machine": {**MACHINE, "kind": "vm"}})
    assert calls == []


def import_cleanup(module, monkeypatch, kind, cfg, **machine):
    m = {**MACHINE, "kind": kind, **machine}
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "located", lambda m: "pve1")
    monkeypatch.setattr(module, "owned", lambda m, **kw: cfg)
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **k: calls.append(a) or "")
    monkeypatch.setattr(module, "first_firewall", lambda m: None)
    monkeypatch.setattr(module, "guest_mtu", lambda m: 1450)
    monkeypatch.setattr(module, "storage_id", lambda: "tank")
    monkeypatch.setattr(
        module, "write", lambda path, data, mode=0o640: calls.append(("write", str(path), data))
    )
    module.import_network({"machine": m})
    return calls


OLD_VM = {
    "net0": "virtio=aa:bb:cc:dd:ee:ff,bridge=vmbr0",
    "cicustom": "user=old:snippets/u.yaml",
    "hookscript": "old:snippets/hook.pl",
    "hostpci0": "0000:01:00.0",
    "usb1": "host=1-1",
    "cpu": "host",
}


def test_import_network_cleans_a_vm(monkeypatch):
    module = load("node-agent.py")
    calls = import_cleanup(module, monkeypatch, "vm", OLD_VM)
    [(_, path, data)] = [c for c in calls if c[0] == "write"]
    assert path == "/var/lib/vz/snippets/carrel-10100-vendor.json"
    assert "block-rpcs=" in data
    [qm] = [c for c in calls if c[0] == "qm"]
    assert qm[qm.index("--cicustom") + 1] == "vendor=local:snippets/carrel-10100-vendor.json"
    assert qm[qm.index("--cpu") + 1] == "x86-64-v3"
    assert qm[qm.index("--delete") + 1] == "hookscript,hostpci0,usb1"
    assert qm[qm.index("--ciupgrade") + 1] == "0"


def test_import_network_keeps_the_cpu_type_for_nested_virt(monkeypatch):
    module = load("node-agent.py")
    calls = import_cleanup(module, monkeypatch, "vm", OLD_VM, nested_virt=True)
    [qm] = [c for c in calls if c[0] == "qm"]
    assert "--cpu" not in qm


def test_import_network_leaves_a_clean_vm_alone(monkeypatch):
    module = load("node-agent.py")
    calls = import_cleanup(module, monkeypatch, "vm", {"net0": "virtio=aa:bb:cc:dd:ee:ff,bridge=vmbr0"})
    [qm] = [c for c in calls if c[0] == "qm"]
    assert "--delete" not in qm and "--cicustom" not in qm
    assert not [c for c in calls if c[0] == "write"]


def test_import_network_drops_the_hookscript_of_a_container(monkeypatch):
    module = load("node-agent.py")
    calls = import_cleanup(
        module,
        monkeypatch,
        "ct",
        {"net0": "name=eth0,bridge=vmbr0", "hookscript": "old:snippets/h.pl", "usb0": "x"},
    )
    [pct] = [c for c in calls if c[0] == "pct"]
    assert pct[pct.index("--delete") + 1] == "hookscript"
    assert "--cpu" not in pct and "--cicustom" not in pct


def test_import_network_adds_one_cloud_init_drive(monkeypatch):
    module = load("node-agent.py")
    calls = import_cleanup(module, monkeypatch, "vm", OLD_VM)
    [qm] = [c for c in calls if c[0] == "qm"]
    assert qm[qm.index("--ide2") + 1] == "tank:cloudinit"
    # A retry finds the drive Proxmox made and adds no second one.
    made = {**OLD_VM, "ide2": "tank:vm-10100-cloudinit,media=cdrom"}
    calls = import_cleanup(module, monkeypatch, "vm", made)
    [qm] = [c for c in calls if c[0] == "qm"]
    assert not [a for a in qm if str(a).endswith(":cloudinit")]


def test_import_network_drops_the_old_cloud_init_credentials(monkeypatch):
    module = load("node-agent.py")
    old = {**OLD_VM, "ciuser": "lab", "sshkeys": "ssh-ed25519%20AAAA%20admin", "cipassword": "$5$x"}
    calls = import_cleanup(module, monkeypatch, "vm", old)
    [qm] = [c for c in calls if c[0] == "qm"]
    assert qm[qm.index("--delete") + 1] == "cipassword,hookscript,hostpci0,sshkeys,usb1"
    assert "ciuser" not in qm[qm.index("--delete") + 1]
    # A retry, the keys gone, deletes nothing for them.
    calls = import_cleanup(module, monkeypatch, "vm", {"net0": OLD_VM["net0"], "ciuser": "lab"})
    [qm] = [c for c in calls if c[0] == "qm"]
    assert "--delete" not in qm


def test_import_network_turns_off_the_cloud_init_upgrade(monkeypatch):
    module = load("node-agent.py")
    # Proxmox defaults ciupgrade to 1; an explicit 1 or a retry with 0 set
    # both end with 0, so the first boot upgrades no package.
    for old in (OLD_VM, {**OLD_VM, "ciupgrade": 1}, {**OLD_VM, "ciupgrade": 0}):
        calls = import_cleanup(module, monkeypatch, "vm", old)
        [qm] = [c for c in calls if c[0] == "qm"]
        assert qm[qm.index("--ciupgrade") + 1] == "0"
        assert "ciupgrade" not in qm[qm.index("--delete") + 1]
    calls = import_cleanup(module, monkeypatch, "ct", {"net0": "name=eth0,bridge=vmbr0"})
    [pct] = [c for c in calls if c[0] == "pct"]
    assert "--ciupgrade" not in pct


def test_import_network_puts_the_cloud_init_drive_in_a_free_slot(monkeypatch):
    module = load("node-agent.py")
    cd = {**OLD_VM, "ide2": "none,media=cdrom", "ide0": "tank:vm-10100-disk-0"}
    calls = import_cleanup(module, monkeypatch, "vm", cd)
    [qm] = [c for c in calls if c[0] == "qm"]
    assert qm[qm.index("--ide1") + 1] == "tank:cloudinit"
    assert "--ide2" not in qm
    full = {**OLD_VM, **{f"ide{i}": "x" for i in range(4)}, **{f"sata{i}": "x" for i in range(6)}}
    with pytest.raises(ValueError, match="free"):
        import_cleanup(module, monkeypatch, "vm", full)


def test_import_network_refuses_a_guest_on_another_node(monkeypatch):
    module = load("node-agent.py")
    monkeypatch.setattr(module, "NODE", "pve1", raising=False)
    monkeypatch.setattr(module, "located", lambda m: "pve2")
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("must not set anything"))
    with pytest.raises(ValueError):
        module.import_network({"machine": MACHINE})
