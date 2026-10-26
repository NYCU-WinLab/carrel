"""node-agent and its helpers, without a live node: PVE reads and commands are replaced."""

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
    monkeypatch.setattr(module, "NODE", "carrel01")
    module.cloud_init_remove({"machine": vm})
    assert not (tmp_path / "carrel-10100-user.json").exists()
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


def test_jump_sync_reads_ascii_lines_split_on_newlines_only():
    module = load("jump-sync.py")
    line = 'restrict,port-forwarding,command="/usr/sbin/nologin",permitopen="10.200.1.10:22" ssh-ed25519 AAAA'
    for bad in [line.replace("10.200.1.10", "10.200.١.10"), line + " " + line, line + "\x1c", line]:
        with pytest.raises(ValueError):
            module.check(bad)  # the last one lacks its final newline
    assert module.check("") == ""


def test_the_fetch_container_reaches_only_public_web_and_the_resolver():
    module = load("node-agent.py")
    rules = module.fetch_firewall({"protected_addresses": ["140.113.60.184/32"]}).splitlines()
    assert "policy_in: DROP" in rules and "policy_out: DROP" in rules
    assert rules[rules.index("[IPSET ipfilter-net0]") + 1] == "10.200.255.10"
    # Private drops come before the web accepts, so 80/443 to the lab stay closed.
    assert rules.index("OUT DROP -dest 192.168.0.0/16") < rules.index("OUT ACCEPT -p tcp -dport 443")
    assert "OUT DROP -dest 140.113.60.184/32" in rules
    assert not any("IN ACCEPT" in r for r in rules)


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


FROZEN_NOTE = "carrel-freeze op1"
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
    monkeypatch.setattr(module.time, "sleep", lambda s: None)
    config = {"digest": "d1"}

    def pve_get(path, **kw):
        if path.endswith("/snapshot"):
            return [{"name": "current"}, *({"name": n} for n in snapshots)]
        return dict(config)

    monkeypatch.setattr(module, "pve_get", pve_get)
    commands = []

    def run(*args, **kw):
        commands.append([str(a) for a in args])
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


REQUEST = {"machine": dict(MACHINE), "storage": "pbs", "freeze_id": "op1", "verify_wait": 0}


def test_freeze_backs_up_protected_and_requires_a_verified_backup(monkeypatch, tmp_path):
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [backup()] if dumped(c) else [])
    out = module.freeze(REQUEST)
    assert out == {"volid": VOLID, "size": 1 << 30, "verification": "ok", "note": FROZEN_NOTE}
    dump = next(c for c in commands if c[0] == "vzdump")
    assert dump[1:] == [
        "10100",
        "--storage",
        "pbs",
        "--mode",
        "stop",
        "--protected",
        "1",
        "--notes-template",
        FROZEN_NOTE,
    ]


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
    leftover = backup(volid=OLD_VOLID, notes="carrel-freeze op0")
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
        module.backup_remove({"machine": dict(MACHINE), "volid": VOLID, "note": "carrel-freeze other"})
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [backup(notes="manual backup")])
    with pytest.raises(ValueError, match="frozen machine"):
        module.backup_remove({"machine": dict(MACHINE), "volid": VOLID})
    module, commands = freezer(monkeypatch, tmp_path, listing=lambda c: [])
    assert module.backup_remove({"machine": dict(MACHINE), "volid": VOLID}) == {"state": "absent"}
