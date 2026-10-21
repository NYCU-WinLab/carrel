"""node-agent and its helpers, without a live node: PVE reads and commands are replaced."""

import importlib.util
import json
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
    for bad in [
        good.replace("10.200.1.10:22", "10.200.0.3:22"),
        good.replace("10.200.1.10:22", "10.200.1.10:8080"),
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


def test_jump_sync_reads_ascii_lines_split_on_newlines_only():
    module = load("jump-sync.py")
    line = 'restrict,port-forwarding,command="/usr/sbin/nologin",permitopen="10.200.1.10:22" ssh-ed25519 AAAA'
    for bad in [line.replace("10.200.1.10", "10.200.١.10"), line + " " + line, line + "\x1c", line]:
        with pytest.raises(ValueError):
            module.check(bad)  # the last one lacks its final newline
    assert module.check("") == ""
