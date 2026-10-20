import asyncio
import importlib.util
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from test_security import Backend, person

from carrel.capacity import GIB, summarize
from carrel.platform import Failure, Platform
from carrel.store import Store

KEY = "ssh-ed25519 " + "A" * 44


@pytest.fixture
async def platform():
    store = Store(":memory:")
    store.register("user:alice", "alice")
    store.register("user:bob", "bob")
    p = Platform(store, Backend(), {"background_operations": True})

    async def ready(m, previous_boot=None):
        m.update(state="ready", ssh_ready=True)
        store.put("machines", m["vmid"], m["tenant_n"], m)

    p.wait_ready = AsyncMock(side_effect=ready)
    yield p
    await p.operations.close()


async def finish(p, result):
    id = result["operation"]["id"]
    task = p.operations.tasks.get(id)
    if task:
        await asyncio.wait_for(task, 3)
    return p.operations.find(p.store.tenant("user:alice"), id)


def deployment():
    return {
        "machines": [
            {"name": name, "cpu": 2, "memory_mb": 2048, "disk_gb": 20, "ssh_keys": [KEY]}
            for name in ("first", "second")
        ],
        "networks": [{"name": "lan"}],
        "attachments": [{"machine": name, "network": "lan"} for name in ("first", "second")],
    }


async def test_queries_and_queue_submission_do_not_wait_for_create(platform):
    entered, release = asyncio.Event(), asyncio.Event()
    original = platform.backend.call

    async def blocked(req):
        if req["op"] == "create":
            entered.set()
            await release.wait()
        return await original(req)

    platform.backend.call = blocked
    result = await platform.execute(
        "machine_create", {"name": "slow", "ssh_keys": [KEY], "wait_seconds": 0}, person()
    )
    assert result["operation"]["state"] == "queued" and not result["operation"]["reserved"]
    await asyncio.wait_for(entered.wait(), 1)
    for tool in ("whoami", "quota_get", "capacity_get"):
        assert (await asyncio.wait_for(platform.execute(tool, {}, person("bob")), 0.2))["ok"]
    other = await asyncio.wait_for(platform.execute("network_create", {"name": "next"}, person()), 0.2)
    polling = asyncio.create_task(
        platform.execute("operation_get", {"id": result["operation"]["id"]}, person())
    )
    await asyncio.sleep(0)
    assert not polling.done()
    assert (await asyncio.wait_for(platform.execute("whoami", {}, person()), 0.2))["ok"]
    release.set()
    assert (await finish(platform, result))["state"] == "succeeded"
    assert (await polling)["operations"][0]["state"] == "succeeded"
    assert (await finish(platform, other))["state"] == "succeeded"


async def test_idempotency_and_tenant_job_isolation(platform):
    args = {"name": "lan", "idempotency_key": "request-1234"}
    first = await platform.execute("network_create", args, person())
    second = await platform.execute("network_create", args, person())
    assert first["operation"]["id"] == second["operation"]["id"]
    mismatch = await platform.execute("network_create", {**args, "name": "other"}, person())
    assert mismatch["error"]["code"] == "conflict"
    denied = await platform.execute("operation_get", {"id": first["operation"]["id"]}, person("bob"))
    assert denied["error"]["code"] == "not_found"
    await finish(platform, first)
    assert len(platform.store.objects("networks", 1)) == 1


async def test_deployment_reserves_entire_group_before_first_create(platform):
    original = platform.backend.call

    async def inspect(req):
        if req["op"] == "create":
            assert len(platform.store.objects("machines", 1)) == 2
            assert platform.quota(platform.store.tenant("user:alice"))["used"]["disk_gb"] == 40
            assert all(m["nics"][0].get("ip") for m in platform.store.objects("machines", 1))
        return await original(req)

    platform.backend.call = inspect
    op = await finish(platform, await platform.execute("deployment_apply", deployment(), person()))
    assert op["state"] == "succeeded", op
    assert len(platform.store.objects("networks", 1)) == 1
    assert platform.wait_ready.await_count == 2


async def test_deployment_checks_existing_vm_after_managed_attachment(platform):
    await finish(
        platform, await platform.execute("machine_create", {"name": "existing", "ssh_keys": [KEY]}, person())
    )
    platform.wait_ready.reset_mock()
    op = await finish(
        platform,
        await platform.execute(
            "deployment_apply",
            {
                "networks": [{"name": "lan"}],
                "attachments": [{"machine": "existing", "network": "lan"}],
            },
            person(),
        ),
    )
    assert op["state"] == "succeeded", op
    platform.wait_ready.assert_awaited_once()
    assert platform.wait_ready.call_args.args[0]["nics"][0]["ip"]


async def test_retry_detach_cannot_remove_reused_nic_index(platform):
    await finish(platform, await platform.execute("deployment_apply", deployment(), person()))
    original = platform.backend.call

    async def broken(req):
        if req.get("action") == "nic_detach":
            raise RuntimeError("interrupted")
        return await original(req)

    platform.backend.call = broken
    op = await finish(
        platform, await platform.execute("machine_nic_detach", {"machine": "first", "nic": 1}, person())
    )
    assert op["state"] == "failed"
    m = platform.store.objects("machines", 1)[0]
    m["nics"][0]["operation_id"] = "different-attachment"
    platform.store.put("machines", m["vmid"], 1, m)
    platform.backend.call = original
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "failed" and "different attachment" in op["error"]["message"]
    assert len(platform.store.objects("machines", 1)[0]["nics"]) == 1


@pytest.mark.parametrize("keep", [True, False])
async def test_partial_deployment_failure_cleanup_and_resume(platform, keep):
    original = platform.backend.call
    broken = True

    async def failure(req):
        if broken and req["op"] == "create" and req["machine"]["name"] == "second":
            raise RuntimeError("injected failure")
        return await original(req)

    platform.backend.call = failure
    result = await platform.execute(
        "deployment_apply", {**deployment(), "on_failure": "keep" if keep else "rollback"}, person()
    )
    op = await finish(platform, result)
    assert op["state"] == ("failed" if keep else "rolled_back"), op
    assert len(platform.store.objects("machines", 1)) == (2 if keep else 0)
    assert len(platform.store.objects("networks", 1)) == (1 if keep else 0)
    broken = False
    retry = await platform.execute("operation_retry", {"id": op["id"]}, person())
    op = await finish(platform, retry)
    assert op["state"] == "succeeded", op
    assert len(platform.store.objects("machines", 1)) == 2


async def test_cleanup_failure_stays_charged_and_retry_only_cleans(platform):
    original = platform.backend.call
    broken = True

    async def failure(req):
        if broken and (req["op"] == "create" or req.get("action") == "delete"):
            raise RuntimeError("injected failure")
        return await original(req)

    platform.backend.call = failure
    op = await finish(platform, await platform.execute("deployment_apply", deployment(), person()))
    assert op["state"] == "cleanup_failed" and op["cleanup"]
    assert platform.quota(platform.store.tenant("user:alice"))["used"]["disk_gb"] == 40
    broken = False
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "rolled_back", op
    assert not platform.store.objects("machines", 1)


async def test_service_restart_reuses_original_allocation(platform):
    entered = asyncio.Event()
    original = platform.backend.call

    async def interrupted(req):
        if req["op"] == "create":
            entered.set()
            await asyncio.Event().wait()
        return await original(req)

    platform.backend.call = interrupted
    result = await platform.execute(
        "machine_create", {"name": "restart", "ssh_keys": [KEY], "wait_seconds": 0}, person()
    )
    await entered.wait()
    allocation = platform.store.objects("machines", 1)[0]["allocation_id"]
    await platform.operations.close()
    await asyncio.sleep(0)
    platform.backend.call = original
    platform.operations.recover()
    op = await finish(platform, result)
    assert op["state"] == "succeeded", op
    assert len(platform.store.objects("machines", 1)) == 1
    assert platform.store.objects("machines", 1)[0]["allocation_id"] == allocation


async def test_failed_delete_cannot_delete_reused_vmid(platform):
    result = await platform.execute("machine_create", {"name": "original", "ssh_keys": [KEY]}, person())
    await finish(platform, result)
    original = platform.backend.call

    async def broken(req):
        if req.get("action") == "delete":
            raise RuntimeError("interrupted")
        return await original(req)

    platform.backend.call = broken
    op = await finish(
        platform,
        await platform.execute("machine_delete", {"machine": "original", "confirm": "original"}, person()),
    )
    m = platform.store.objects("machines", 1)[0]
    m["allocation_id"] = "replacement"
    platform.store.put("machines", m["vmid"], 1, m)
    platform.backend.call = original
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "failed" and "different allocation" in op["error"]["message"]
    assert platform.store.objects("machines", 1)[0]["allocation_id"] == "replacement"


async def test_stopped_machine_keeps_capacity(platform):
    result = await platform.execute("machine_create", {"name": "reserved", "ssh_keys": [KEY]}, person())
    await finish(platform, result)
    m = platform.store.objects("machines", 1)[0]
    m["state"] = "stopped"
    platform.store.put("machines", m["vmid"], 1, m)
    capacity = await platform.capacity()
    assert capacity["allocatable"]["vcpu"]["committed"] == m["cpu"]
    assert capacity["allocatable"]["memory_gib"]["committed"] == m["memory_mb"] / 1024
    original = platform.backend.call

    async def no_capacity_check(req):
        assert req["op"] != "inventory", "Starting an existing reservation must not compete for capacity"
        return await original(req)

    platform.backend.call = no_capacity_check
    op = await finish(
        platform,
        await platform.execute("machine_power", {"machine": "reserved", "action": "start"}, person()),
    )
    assert op["state"] == "succeeded"


async def test_two_snapshots_do_not_consume_virtual_disk_quota(platform):
    await finish(
        platform,
        await platform.execute(
            "machine_create", {"name": "snap", "disk_gb": 40, "ssh_keys": [KEY]}, person()
        ),
    )
    for name in ("one", "two"):
        op = await finish(
            platform, await platform.execute("snapshot_create", {"machine": "snap", "name": name}, person())
        )
        assert op["state"] == "succeeded", op
    quota = platform.quota(platform.store.tenant("user:alice"))
    assert quota["used"]["disk_gb"] == 40 and quota["used"]["snapshot_gb"] == 80
    op = await finish(
        platform, await platform.execute("snapshot_create", {"machine": "snap", "name": "three"}, person())
    )
    assert op["error"]["code"] == "quota_exceeded"


async def test_cpu_ram_shrink_releases_only_after_backend_success(platform):
    await finish(
        platform,
        await platform.execute(
            "machine_create", {"name": "shrink", "cpu": 4, "memory_mb": 4096, "ssh_keys": [KEY]}, person()
        ),
    )
    original = platform.backend.call
    broken = True

    async def stopped(req):
        if req["op"] == "status":
            return {"status": "stopped"}
        if req.get("action") == "resize" and broken:
            raise RuntimeError("resize interrupted")
        return await original(req)

    platform.backend.call = stopped
    op = await finish(
        platform,
        await platform.execute(
            "machine_resize", {"machine": "shrink", "cpu": 1, "memory_mb": 1024}, person()
        ),
    )
    assert op["state"] == "failed"
    quota = platform.quota(platform.store.tenant("user:alice"))["used"]
    assert quota["vcpu"] == 4 and quota["memory_mb"] == 4096
    broken = False
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "succeeded"
    quota = platform.quota(platform.store.tenant("user:alice"))["used"]
    assert quota["vcpu"] == 1 and quota["memory_mb"] == 1024


async def test_edge_cleanup_failure_keeps_machine_and_port_reservations(platform):
    await finish(
        platform, await platform.execute("machine_create", {"name": "delete", "ssh_keys": [KEY]}, person())
    )
    original = platform.backend.reconcile
    platform.backend.reconcile = AsyncMock(side_effect=RuntimeError("edge offline"))
    op = await finish(
        platform,
        await platform.execute("machine_delete", {"machine": "delete", "confirm": "delete"}, person()),
    )
    assert op["state"] == "failed"
    quota = platform.quota(platform.store.tenant("user:alice"))["used"]
    assert quota["machines"] == 1 and quota["public_ports"] == 1
    assert not platform.store.desired()["machines"] and not platform.store.desired()["ports"]
    platform.backend.reconcile = original
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "succeeded"
    assert platform.quota(platform.store.tenant("user:alice"))["used"]["machines"] == 0


def test_metadata_pressure_blocks_new_storage():
    capacity = summarize(
        {
            "status": {"cpuinfo": {"cpus": 32}, "memory": {"total": 192 * GIB}},
            "storage": {"used": 10 * GIB, "total": 1500 * GIB},
            "resources": [],
            "thin_pool": {"metadata_fraction": 0.81},
        }
    )
    assert capacity["policy"]["storage_admission_blocked"]


async def test_managed_networks_and_raw_networks(platform):
    plan = await platform.execute("deployment_plan", deployment(), person())
    assert plan["ok"] and plan["networks"][0]["dhcp"] and plan["networks"][0]["gateway"] is None
    net = platform.network_spec(platform.store.tenant("user:alice"), {"name": "lab", "mode": "raw_l2"})
    assert net["cidr"] is None and not net["dhcp"]
    for cidr in ("10.200.1.0/24", "8.8.8.0/24", "10.1.1.0/28"):
        with pytest.raises(Failure):
            platform.network_spec(platform.store.tenant("user:alice"), {"name": "bad", "cidr": cidr})


async def test_guest_report_is_bound_to_ip_and_token_and_failures_are_not_ready(platform, monkeypatch):
    await finish(
        platform, await platform.execute("machine_create", {"name": "guest", "ssh_keys": [KEY]}, person())
    )
    m = platform.store.objects("machines", 1)[0]
    body = {
        "vmid": m["vmid"],
        "token": m["readiness_token"],
        "boot_id": "a" * 36,
        "initialization_status": "failed",
        "application_status": "not_checked",
    }
    with pytest.raises(Failure):
        platform.guest_report(body, "10.200.2.10")
    with pytest.raises(Failure):
        platform.guest_report({**body, "token": "wrong"}, m["ip"])
    platform.guest_report(body, m["ip"])
    reader = AsyncMock()
    reader.readline.return_value = b"SSH-2.0-test\n"
    writer = type("Writer", (), {"close": lambda self: None, "wait_closed": AsyncMock()})()
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
    with pytest.raises(Failure) as exc:
        await Platform.wait_ready(platform, m)
    assert exc.value.result["error"]["code"] == "guest_not_ready"
    assert platform.store.objects("machines", 1)[0]["state"] == "needs_owner_fix"
    public = platform.public_machine(m, [])
    assert "readiness_token" not in public
    assert public["readiness"]["initialization_status"] == "failed"


def test_thin_snapshot_accounting_counts_shared_blocks_once():
    spec = importlib.util.spec_from_file_location(
        "thin_usage", Path(__file__).parents[1] / "scripts/thin-usage.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    xml = """<superblock data_block_size="128"><device dev_id="1"><range_mapping data_begin="0" length="10"/></device>
    <device dev_id="2"><range_mapping data_begin="0" length="15"/></device>
    <device dev_id="3"><range_mapping data_begin="5" length="15"/></device></superblock>"""
    volumes = [
        {"lv_name": "vm-10100-disk-0", "thin_id": "1"},
        {"lv_name": "snap_vm-10100-disk-0_one", "thin_id": "2"},
        {"lv_name": "snap_vm-10100-disk-0_two", "thin_id": "3"},
    ]
    result = module.account(xml, volumes, [{"vmid": 10100, "tenant_n": 1}])[0]
    assert result["retained_snapshot_bytes"] == 10 * 65536
    assert result["unique_total_bytes"] == 20 * 65536


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


async def test_create_returns_ready_result_without_polling(platform):
    result = await platform.execute("machine_create", {"name": "direct", "ssh_keys": [KEY]}, person())
    op = result["operation"]
    assert op["state"] == "succeeded"
    assert op["result"]["machine"]["state"] == "ready"
    assert op["result"]["machine"]["ssh_short"] == "ssh direct.alice"
    platform.wait_ready.assert_awaited_once()


@pytest.mark.parametrize("disconnect", [False, True])
async def test_creation_wait_keeps_worker_alive_and_deduplicates(platform, disconnect):
    entered, release = asyncio.Event(), asyncio.Event()
    original = platform.wait_ready

    async def blocked(machine, previous_boot=None):
        entered.set()
        await release.wait()
        await original(machine, previous_boot)

    platform.wait_ready = blocked
    args = {"name": "waiting", "ssh_keys": [KEY], "idempotency_key": "waiting-1234"}
    request = asyncio.create_task(platform.execute("machine_create", args, person()))
    await asyncio.wait_for(entered.wait(), 1)
    assert (await asyncio.wait_for(platform.execute("whoami", {}, person("bob")), 0.2))["ok"]
    if disconnect:
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
    op = platform.store.objects("operations", 1)[0]
    assert not platform.operations.tasks[op["id"]].done()
    # A bounded timeout returns current state, without cancelling the worker.
    bounded = await platform.operations.wait(platform.store.tenant("user:alice"), op["id"], 0.01)
    assert bounded["state"] == "running"
    duplicate = await platform.execute("machine_create", {**args, "wait_seconds": 0}, person())
    assert duplicate["operation"]["id"] == op["id"]
    assert len(platform.store.objects("machines", 1)) == 1
    release.set()
    await finish(platform, duplicate)
    if not disconnect:
        assert (await request)["operation"]["state"] == "succeeded"
    again = await platform.execute("machine_create", {**args, "wait_seconds": 1}, person())
    assert again["operation"]["state"] == "succeeded"
    assert again["operation"]["id"] == op["id"]


async def test_short_ssh_aliases_are_scoped_by_tenant(platform, tmp_path):
    import subprocess

    for user in ("alice", "bob"):
        result = await platform.execute("machine_create", {"name": "dev", "ssh_keys": [KEY]}, person(user))
        machine = result["operation"]["result"]["machine"]
        path = tmp_path / user
        path.write_text(machine["ssh_config"])
        for alias in (f"dev.{user}", f"dev.{user}.winlab.tw"):
            parsed = await asyncio.to_thread(
                subprocess.check_output, ["ssh", "-F", str(path), "-G", alias], text=True
            )
            assert "hostname carrel.winlab.tw\n" in parsed
            assert "user user\n" in parsed
            assert f"port {machine['ssh'].split()[2]}\n" in parsed
        assert machine["ssh_short"] == f"ssh dev.{user}"


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


async def test_group_creation_waits_and_preview_remains_read_only(platform):
    preview = await platform.execute("machine_create", {"name": "preview", "dry_run": True}, person())
    assert preview["ok"] and not platform.store.objects("operations", 1)
    result = await platform.execute("deployment_apply", deployment(), person())
    assert result["operation"]["state"] == "succeeded"
    assert [m["name"] for m in result["operation"]["result"]["machines"]] == ["first", "second"]


def test_wait_is_request_policy_not_nested_machine_spec():
    from carrel.tools import BY_NAME

    for name in ("machine_create", "deployment_apply", "operation_get"):
        wait = BY_NAME[name].inputSchema["properties"]["wait_seconds"]
        assert wait["default"] == wait["maximum"] == 55
    assert (
        "wait_seconds"
        not in BY_NAME["deployment_plan"].inputSchema["properties"]["machines"]["items"]["properties"]
    )


@pytest.mark.parametrize("immutable", [True, False])
async def test_linked_clone_requires_immutable_thin_template(platform, monkeypatch, tmp_path, immutable):
    from carrel.operations import current_operation

    # Obtain a real validated allocation; replace only the privileged node boundary.
    await platform.execute("machine_create", {"name": "linked", "ssh_keys": [KEY]}, person())
    machine = platform.store.objects("machines", 1)[0]
    spec = importlib.util.spec_from_file_location(
        "node_agent", Path(__file__).parents[1] / "scripts/node-agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "vm_template", lambda image: {"vmid": 9010, "prepared": True})
    monkeypatch.setattr(
        module, "pve_get", lambda *args: {"template": int(immutable), "scsi0": "local-lvm:base-9010-disk-0"}
    )
    monkeypatch.setattr(
        module, "cloud_init", lambda m, **kwargs: "prepared-snippet" if kwargs["prepared"] else "legacy"
    )
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args) or "stopped")
    assert current_operation.get() is None
    if immutable:
        assert module.create(machine)["state"] == "running"
        clone = next(c for c in calls if c[:2] == ("qm", "clone"))
        assert clone[2] == 9010 and clone[clone.index("--full") + 1] == "0"
        manifest = json.loads((tmp_path / f"create-{machine['vmid']}.json").read_text())
        assert manifest["template"] == {"vmid": 9010, "prepared": True}
    else:
        with pytest.raises(ValueError, match="immutable"):
            module.create(machine)
        assert not calls


@pytest.mark.parametrize("disk", ["local-zfs:base-9010-disk-0", "local-lvm:base-9010-disk-0"])
async def test_linked_clone_template_must_live_on_the_configured_storage(
    platform, monkeypatch, tmp_path, disk
):
    await platform.execute("machine_create", {"name": "linked", "ssh_keys": [KEY]}, person())
    machine = platform.store.objects("machines", 1)[0]
    spec = importlib.util.spec_from_file_location(
        "node_agent", Path(__file__).parents[1] / "scripts/node-agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "node.json").write_text(json.dumps({"storage": "local-zfs"}))
    monkeypatch.setattr(module, "CONFIG", tmp_path / "node.json")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "vm_template", lambda image: {"vmid": 9010, "prepared": True})
    monkeypatch.setattr(module, "pve_get", lambda *args: {"template": 1, "scsi0": disk})
    monkeypatch.setattr(module, "cloud_init", lambda m, **kwargs: "prepared-snippet")
    calls = []
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
