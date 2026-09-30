import json
from unittest.mock import AsyncMock

import httpx
import jsonschema
import pytest
from test_security import Backend, person

from carrel.capacity import GIB, summarize
from carrel.platform import Platform
from carrel.server import build
from carrel.store import Store
from carrel.tools import BY_NAME, TOOLS

KEY = "ssh-ed25519 " + "A" * 44


@pytest.fixture
def platform():
    store = Store(":memory:")
    store.register("user:alice", "alice")
    store.register("user:bob", "bob")
    store.register("winlab-projects/shared", "shared")
    return Platform(store, Backend(), {})


def seed(platform):
    m = {
        "vmid": 10100,
        "tenant_n": 1,
        "name": "test",
        "kind": "vm",
        "image": "ubuntu-24.04",
        "cpu": 2,
        "memory_mb": 2048,
        "disk_gb": 20,
        "nics": [],
        "ip": "10.200.1.10",
        "state": "ready",
        "ssh_keys": [KEY],
    }
    platform.store.put("machines", m["vmid"], 1, m)
    platform.store.put("networks", "p00101", 1, {"id": "p00101", "name": "lan", "serial": 1, "tenant_n": 1})
    platform.store.put(
        "ports", "ssh", 1, {"id": "ssh", "vmid": 10100, "public_port": 20010, "port": 22, "proto": "tcp"}
    )
    return m


def resource_state(platform):
    return {
        table: list(map(tuple, platform.store.db.execute(f"SELECT * FROM {table}")))
        for table in ("objects", "tenants")
    }


async def preview(platform, tool, args, delta, who=None):
    before = resource_state(platform)
    result = await platform.execute(tool, {**args, "dry_run": True}, who or person())
    assert result["ok"], result
    assert result["delta"] == delta
    assert result["state"] == "planned" and result["reserved"] is False
    assert result["resource_changes"] is False
    for k, used in result["quota_before"]["used"].items():
        assert result["quota_after"]["used"][k] == used + delta.get(k, 0)
        assert result["quota_after"]["remaining"][k] == result["quota_after"]["limit"][k] - used - delta.get(
            k, 0
        )
    assert resource_state(platform) == before
    assert all(c["op"] == "inventory" for c in platform.backend.calls)
    return result


@pytest.mark.parametrize(
    "tool,args,delta",
    [
        ("network_create", {"name": "new"}, {"networks": 1}),
        ("network_delete", {"network": "lan", "confirm": "lan"}, {"networks": -1}),
        ("port_open", {"machine": "test", "port": 80, "proto": "tcp"}, {"public_ports": 1}),
        ("port_open", {"machine": "test", "port": 22, "proto": "tcp"}, {}),
        ("port_close", {"id": "ssh"}, {"public_ports": -1}),
        ("domain_add", {"machine": "test", "sub": "www", "target_port": 80}, {"domains": 1}),
        ("snapshot_create", {"machine": "test", "name": "before"}, {"snapshots": 1, "snapshot_gb": 20}),
        ("machine_resize", {"machine": "test", "cpu": 4, "disk_gb": 30}, {"vcpu": 2, "disk_gb": 10}),
        ("machine_power", {"machine": "test", "action": "stop"}, {}),
        ("machine_nic_attach", {"machine": "test", "network": "lan"}, {}),
        ("peer_allow", {"machine": "test", "port": 80, "from_tenant": "bob"}, {}),
        ("ssh_key_add", {"key": KEY}, {}),
        ("ssh_key_remove", {"id": "missing"}, {}),
        ("quota_request", {"dimension": "vcpu", "amount": 16, "reason": "test expansion"}, {}),
    ],
)
async def test_preview_contract(platform, tool, args, delta):
    seed(platform)
    await preview(platform, tool, args, delta)


async def test_preview_deletes_cascades_and_releases_snapshot_disks(platform):
    m = seed(platform)
    platform.store.put("domains", "domain", 1, {"id": "domain", "vmid": 10100, "name": "www.alice.winlab.tw"})
    platform.store.put(
        "snapshots",
        "10100-before",
        1,
        {
            "id": "10100-before",
            "vmid": 10100,
            "name": "before",
            "disk_gb": 20,
            "configuration": {k: m[k] for k in ("cpu", "memory_mb", "disk_gb", "nics")},
        },
    )
    await preview(platform, "domain_remove", {"name": "www.alice.winlab.tw"}, {"domains": -1})
    await preview(platform, "domain_add", {"machine": "test", "sub": "www", "target_port": 8080}, {})
    await preview(
        platform,
        "snapshot_delete",
        {"machine": "test", "name": "before"},
        {"snapshots": -1, "snapshot_gb": -20},
    )
    await preview(
        platform, "snapshot_rollback", {"machine": "test", "name": "before", "confirm": "before"}, {}
    )
    await preview(
        platform,
        "machine_delete",
        {"machine": "test", "confirm": "test"},
        {
            "vcpu": -2,
            "memory_mb": -2048,
            "disk_gb": -20,
            "snapshot_gb": -20,
            "machines": -1,
            "ips": -1,
            "public_ports": -1,
            "domains": -1,
            "snapshots": -1,
        },
    )
    # Reductions must remain possible even after an expired quota grant.
    platform.store.db.execute("UPDATE tenants SET quota=json_set(quota, '$.vcpu', 1) WHERE n=1")
    await preview(platform, "port_close", {"id": "ssh"}, {"public_ports": -1})


async def test_remaining_zero_delta_mutations(platform):
    m = seed(platform)
    m.update(state="error", nics=[{"index": 1, "network": "p00101"}])
    platform.store.put("machines", 10100, 1, m)
    platform.store.put("peers", "peer", 1, {"id": "peer"})
    await preview(platform, "machine_retry", {"machine": "test"}, {})
    await preview(platform, "machine_nic_detach", {"machine": "test", "nic": 1}, {})
    await preview(platform, "peer_revoke", {"id": "peer"}, {})


async def test_keyless_planning_checks_quota_and_capacity_but_apply_requires_key(platform):
    result = await preview(
        platform,
        "machine_create",
        {"name": "new"},
        {"vcpu": 2, "memory_mb": 2048, "disk_gb": 20, "machines": 1, "ips": 1, "public_ports": 1},
    )
    assert result["admission"]["accepted"]
    assert result["requirements"] == ["ssh_public_key"] and not result["ready_to_apply"]
    assert result["machine"]["state"] == "planned"
    assert (
        not {"vmid", "ip", "mac", "host", "tenant_n", "created_at", "ssh", "ssh_config"}
        & result["machine"].keys()
    )
    result = await platform.execute("machine_create", {"name": "new"}, person())
    assert result["error"]["code"] == "invalid"
    result = await platform.execute(
        "machine_create", {"name": "new", "ssh_keys": ["invalid"], "dry_run": True}, person()
    )
    assert result["error"]["code"] == "invalid"
    result = await platform.execute(
        "machine_create", {"name": "new", "cpu": 16, "memory_mb": 32768, "dry_run": True}, person()
    )
    assert {v["dimension"] for v in result["error"]["violations"]} == {"vcpu", "memory_mb"}
    platform.backend.call = AsyncMock(
        return_value={
            "status": {"cpuinfo": {"cpus": 32}, "memory": {"total": 8 * GIB}},
            "storage": {"total": 100 * GIB, "used": GIB},
            "resources": [],
        }
    )
    result = await platform.execute("machine_create", {"name": "new", "dry_run": True}, person())
    assert result["error"]["code"] == "capacity_exhausted"
    assert not platform.store.objects("machines")


async def test_deployment_plan_aggregate_references_and_isolation(platform):
    args = {
        "machines": [{"name": name, "cpu": 2, "ssh_keys": [KEY]} for name in ("one", "two")],
        "networks": [{"name": "lab"}],
        "attachments": [{"machine": name, "network": "lab"} for name in ("one", "two")],
    }
    before = resource_state(platform)
    result = await platform.execute("deployment_plan", args, person())
    assert result["ok"] and result["ready_to_apply"]
    assert result["delta"] == {
        "vcpu": 4,
        "memory_mb": 4096,
        "disk_gb": 40,
        "machines": 2,
        "ips": 2,
        "public_ports": 2,
        "networks": 1,
    }
    assert [m["name"] for m in result["machines"]] == ["one", "two"]
    assert len(result["attachments"]) == 2 and all(x["nic"] == 1 for x in result["attachments"])
    assert resource_state(platform) == before
    assert len(platform.backend.calls) == 1
    assert all(c["op"] == "inventory" for c in platform.backend.calls)
    for m in args["machines"]:
        m["cpu"] = 6
    result = await platform.execute("deployment_plan", args, person())
    assert result["error"]["code"] == "quota_exceeded" and result["error"]["used"] == 12
    assert len(platform.backend.calls) == 1
    seed(platform)
    result = await platform.execute(
        "deployment_plan", {"attachments": [{"machine": "test", "network": "lan"}]}, person("bob")
    )
    assert result["error"]["code"] == "not_found"
    result = await platform.execute(
        "deployment_plan", {"tenant": "bob", "machines": [{"name": "x"}]}, person()
    )
    assert result["error"]["code"] == "forbidden"


@pytest.mark.parametrize(
    "args,code",
    [
        ({}, "invalid"),
        ({"machines": [{"name": "a"}, {"name": "a"}]}, "conflict"),
        ({"networks": [{"name": "a"}, {"name": "a"}]}, "conflict"),
        ({"networks": [{"name": "a", "cidr": "bad"}]}, "invalid"),
        ({"machines": [{"name": "a", "kind": "ct", "packages": ["docker.io"]}]}, "invalid"),
        ({"attachments": [{"machine": "missing", "network": "missing"}]}, "not_found"),
    ],
)
async def test_plan_rejects_invalid_resources(platform, args, code):
    before = resource_state(platform)
    result = await platform.execute("deployment_plan", args, person())
    assert result["error"]["code"] == code
    assert resource_state(platform) == before


async def test_plan_existing_nics_and_missing_keys(platform):
    seed(platform)
    result = await platform.execute(
        "deployment_plan",
        {
            "machines": [{"name": "new"}],
            "networks": [{"name": "new-lan"}],
            "attachments": [{"machine": "test", "network": "new-lan"}, {"machine": "new", "network": "lan"}],
        },
        person(),
    )
    assert result["ok"] and not result["ready_to_apply"]
    assert result["requirements"] == [{"machine": "new", "requirement": "ssh_public_key"}]
    assert not platform.store.objects("machines", 1)[0]["nics"]
    args = {"attachments": [{"machine": "test", "network": "lan"}] * 2}
    assert (await platform.execute("deployment_plan", args, person()))["error"]["code"] == "conflict"


async def test_overview_capabilities_aliases_and_hidden_images(platform):
    result = await platform.execute("whoami", {}, person(projects=["winlab-projects/shared"]))
    assert result["default_tenant"] == "alice"
    assert {t["slug"] for t in result["tenants"]} == {"alice", "shared"}
    assert "images_gb" not in json.dumps(result)
    assert "subject" not in json.dumps(result)
    assert platform.store.tenant("user:alice")["quota"]["images_gb"] == 20
    catalog = await platform.execute("catalog_get", {}, person())
    assert catalog["capabilities"]["gpu_allocation"] is False
    assert catalog["units"]["memory_mb"] == "MiB"
    assert (await platform.execute("images_list", {}, person()))["images"] == catalog["images"]
    assert (await platform.execute("sizes_list", {}, person()))["sizes"] == catalog["sizes"]
    assert not {"images_list", "sizes_list"} & {t.name for t in TOOLS}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"dimension": "images_gb", "amount": 10, "reason": "test image"},
            BY_NAME["quota_request"].inputSchema,
        )


async def test_capacity_privacy_and_shared_admission(platform):
    inventory = {
        "node": "carrel01",
        "status": {
            "cpuinfo": {"cpus": 32, "cores": 16, "sockets": 1},
            "cpu": 0.1,
            "memory": {"total": 192 * GIB, "used": 32 * GIB},
        },
        "storage": {"total": 1500 * GIB, "used": 100 * GIB},
        "disk_committed_bytes": 200 * GIB,
        "resources": [
            {
                "type": "qemu",
                "node": "carrel01",
                "name": "secret-other-tenant",
                "vmid": 190,
                "status": "running",
                "maxcpu": 8,
                "maxmem": 24 * GIB,
                "maxdisk": 32 * GIB,
            }
        ],
    }
    platform.backend.call = AsyncMock(return_value=inventory)
    result = (await platform.execute("capacity_get", {}, person()))["capacity"]
    assert "secret-other-tenant" not in json.dumps(result) and "vmid" not in json.dumps(result)
    assert result["physical"]["cpu"]["cores"] == 16
    assert result["allocatable"]["vcpu"]["remaining"] == 120
    assert result["allocatable"]["disk_gib"]["committed"] == 200  # includes secondary disks
    assert result["gpu"] == {"allocation_supported": False, "inventory": "unknown"}
    # Physical usage ceiling is shared by the public summary and actual admission.
    inventory["storage"]["used"] = 1300 * GIB
    result = (await platform.execute("capacity_get", {}, person()))["capacity"]
    assert result["allocatable"]["disk_gib"]["remaining"] == 0
    r = await platform.execute("machine_create", {"name": "new", "dry_run": True}, person())
    assert r["error"]["code"] == "capacity_exhausted"
    # Pending allocations, absent from the hypervisor, still consume admission headroom.
    result = summarize(
        inventory, [{"vmid": 10100, "cpu": 4, "memory_mb": 8192, "disk_gb": 40, "state": "error"}]
    )
    assert result["allocatable"]["vcpu"]["committed"] == 12
    assert result["allocatable"]["memory_gib"]["committed"] == 32
    assert result["allocatable"]["disk_gib"]["committed"] == 240


async def test_plan_checks_aggregate_host_capacity_once(platform):
    platform.backend.call = AsyncMock(
        return_value={
            "status": {"cpuinfo": {"cpus": 1}, "memory": {"total": 192 * GIB}},
            "storage": {"total": 1500 * GIB, "used": GIB},
            "resources": [{"type": "qemu", "status": "running", "maxcpu": 1}],
        }
    )
    for name in ("one", "two"):
        assert (
            await platform.execute("machine_create", {"name": name, "cpu": 2, "dry_run": True}, person())
        )["ok"]
    before = resource_state(platform)
    result = await platform.execute(
        "deployment_plan", {"machines": [{"name": "one"}, {"name": "two"}]}, person()
    )
    assert result["error"]["code"] == "capacity_exhausted"
    assert result["error"]["dimension"] == "vcpu"
    assert resource_state(platform) == before
    assert platform.backend.call.await_count == 3


async def test_start_does_not_double_count_pending_reservation(platform):
    m = seed(platform)
    m.update(state="error", cpu=4)
    platform.store.put("machines", 10100, 1, m)
    platform.backend.call = AsyncMock(
        return_value={
            "status": {"cpuinfo": {"cpus": 1}, "memory": {"total": 192 * GIB}},
            "storage": {"total": 1500 * GIB, "used": GIB},
            "resources": [],
        }
    )
    result = await platform.execute(
        "machine_power", {"machine": "test", "action": "start", "dry_run": True}, person()
    )
    assert result["ok"]


@pytest.mark.parametrize("power_state", ["running", "stopped"])
async def test_rollback_updates_actual_power_state_and_restart_guidance(platform, power_state):
    m = seed(platform)
    platform.store.put(
        "snapshots",
        "10100-before",
        1,
        {
            "id": "10100-before",
            "vmid": 10100,
            "name": "before",
            "disk_gb": 20,
            "configuration": {k: m[k] for k in ("cpu", "memory_mb", "disk_gb", "nics")},
        },
    )
    platform.backend.call = AsyncMock(return_value={"status": power_state, "state": "stopped"})

    async def ready(machine, previous_boot=None):
        machine["state"] = "ready"
        platform.store.put("machines", machine["vmid"], 1, machine)

    platform.wait_ready = AsyncMock(side_effect=ready)
    args = {"machine": "test", "name": "before", "confirm": "before"}
    result = await platform.execute("snapshot_rollback", {**args, "dry_run": True}, person())
    assert result["power_state"] == "restored_to_previous"
    assert platform.store.objects("machines", 1)[0]["state"] == "ready"
    platform.backend.call.assert_not_awaited()
    result = await platform.execute("snapshot_rollback", args, person())
    assert result["ok"] and result["power_state"] == power_state
    assert platform.store.objects("machines", 1)[0]["state"] == (
        "ready" if power_state == "running" else "stopped"
    )
    assert result["power_state_restored"] is True
    assert platform.wait_ready.await_count == (1 if power_state == "running" else 0)
    assert result["delta"] == {}


async def test_admin_quota_previews_change_limits_without_writing(platform):
    r = await preview(
        platform, "quota_set", {"tenant": "alice", "dimension": "vcpu", "amount": 16}, {}, person(admin=True)
    )
    assert r["limit_delta"] == {"vcpu": 8} and r["quota_after"]["remaining"]["vcpu"] == 16
    platform.store.put(
        "requests", "r", 1, {"id": "r", "tenant_n": 1, "dimension": "vcpu", "amount": 16, "status": "pending"}
    )
    r = await preview(platform, "request_approve", {"id": "r"}, {}, person(admin=True))
    assert r["limit_delta"] == {"vcpu": 8}
    await preview(platform, "request_reject", {"id": "r"}, {}, person(admin=True))
    await preview(platform, "tenant_suspend", {"tenant": "alice"}, {}, person(admin=True))


async def test_mcp_discovery_is_empty_and_new_tools_are_member_visible(platform):
    verifier = type("Verifier", (), {"verify": AsyncMock(return_value=person())})()
    app = build(
        {"origin": "https://carrel.test", "issuer": "https://issuer.test"},
        backend=platform.backend,
        store=platform.store,
        verifier=verifier,
    )
    async with (
        app.app.router.lifespan_context(app.app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="https://carrel.test",
            headers={"Authorization": "Bearer test", "Accept": "application/json, text/event-stream"},
        ) as client,
    ):
        for method, key in [
            ("resources/list", "resources"),
            ("resources/templates/list", "resourceTemplates"),
        ]:
            response = await client.post(
                "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}
            )
            assert response.json()["result"][key] == []
        r = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = {t["name"] for t in r.json()["result"]["tools"]}
        assert {"catalog_get", "capacity_get", "deployment_plan"} <= names
        assert not {"images_list", "sizes_list", "node_list", "quota_set"} & names
        r = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "deployment_plan",
                    "arguments": {"machines": [{"name": "a", "tenant": "bob"}]},
                },
            },
        )
        assert r.json()["result"]["structuredContent"]["error"]["code"] == "invalid"
