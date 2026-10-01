import asyncio
import importlib.util
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from test_reliability import KEY
from test_security import Backend, person

from carrel.platform import Failure, Platform
from carrel.store import Store
from carrel.tools import BY_NAME


@pytest.fixture
async def platform():
    store = Store(":memory:")
    store.register("user:alice", "alice")
    store.register("user:bob", "bob")
    p = Platform(store, Backend(), {"background_operations": True})

    async def ready(m, previous_boot=None):
        p.require_active(m["tenant_n"])
        m.update(state="ready", ssh_ready=True)
        store.put("machines", m["vmid"], m["tenant_n"], m)

    p.wait_ready = AsyncMock(side_effect=ready)
    p.domains.ensure = AsyncMock(return_value={"state": "ready"})
    p.domains.record = AsyncMock()
    p.domains.bundles = lambda domains: []
    yield p
    await p.operations.close()


def web_stack():
    return {
        "machines": [
            {"name": name, "ssh_keys": [KEY], "network_access": "restricted"} for name in ("app", "db")
        ],
        "connections": [{"from": "app", "to": "db", "port": 5432}],
        "publications": [
            {"machine": "app", "protocol": "https", "port": 80, "sub": "web"},
            {"machine": "app", "protocol": "tcp", "port": 8080},
        ],
    }


async def create(p, name="existing", **args):
    return await finish(
        p, await p.execute("machine_create", {"name": name, "ssh_keys": [KEY], **args}, person())
    )


async def finish(p, result):
    id = result["operation"]["id"]
    if task := p.operations.tasks.get(id):
        await asyncio.wait_for(task, 3)
    return next(o for o in p.store.objects("operations") if o["id"] == id)


async def wait_state(p, id, state):
    async with asyncio.timeout(2):
        while True:
            op = p.operations.find(p.store.tenant("user:alice"), id)
            if op["state"] == state:
                return op
            await asyncio.sleep(0.001)


async def test_dns_outage_does_not_block_unrelated_private_network(platform):
    platform.store.put(
        "domains", "old", 1, {"id": "old", "state": "ready", "tenant_n": 1, "name": "old.alice.winlab.tw"}
    )
    platform.domains.record.side_effect = RuntimeError("provider unavailable")
    op = await finish(platform, await platform.execute("network_create", {"name": "private"}, person("bob")))
    assert op["state"] == "succeeded"
    platform.domains.record.assert_not_awaited()
    assert any(c["op"] == "reconcile" for c in platform.backend.calls)
    await platform.maintain_domains()
    assert platform.store.objects("domain_status", 1)[0]["state"] == "retrying"


async def test_project_collision_does_not_block_personal_queries(platform):
    who = person(projects=["winlab-projects/www"])
    platform.reserved = AsyncMock(return_value=set())
    assert (await platform.execute("quota_get", {}, who))["ok"]
    platform.reserved.assert_not_awaited()
    overview = await platform.execute("whoami", {}, who)
    assert overview["ok"] and overview["default_tenant"] == "alice"
    assert overview["onboarding"][0]["code"] == "conflict"
    assert not platform.store.tenant("winlab-projects/www")


@pytest.mark.parametrize("dimension", ["snapshots", "domains", "networks", "vcpu", "memory_mb"])
async def test_expiry_keeps_machines_and_allows_repair(platform, dimension):
    await create(platform)
    if dimension in ("snapshots", "domains", "networks"):
        platform.store.put(dimension, "existing", 1, {"id": "existing", "disk_gb": 20})
    platform.store.put(
        "requests",
        "grant",
        1,
        {
            "id": "grant",
            "tenant_n": 1,
            "status": "approved",
            "until": "2020-01-01",
            "dimension": dimension,
            "previous_limit": 0,
        },
    )
    platform.backend.calls.clear()
    await platform.expire_grants()
    assert not platform.backend.calls
    quota = platform.quota(platform.store.tenant("user:alice"))
    assert dimension in quota["over_limit"]
    assert platform.store.objects("machines", 1)[0]["state"] == "ready"
    assert platform.store.objects("requests", 1)[0]["status"] == "expired"
    # Quota enforcement blocks growth only in that dimension.
    with pytest.raises(Failure) as exc:
        platform.quota(platform.store.tenant("user:alice"), {dimension: 1})
    assert exc.value.result["error"]["code"] == "quota_exceeded"
    platform.quota(platform.store.tenant("user:alice"), {dimension: -1})


async def test_certificate_wait_releases_writer_and_recovers_after_restart(platform):
    await create(platform)
    platform.domains.ensure.side_effect = [
        {"state": "queued", "ready_at": time.time() + 0.15},
        {"state": "ready"},
    ]
    submitted = await platform.execute(
        "domain_add", {"machine": "existing", "sub": "web", "target_port": 80}, person()
    )
    id = submitted["operation"]["id"]
    op = await wait_state(platform, id, "waiting")
    assert op["phase"] == "waiting_for_certificate" and "result" not in op
    other = await finish(platform, await platform.execute("network_create", {"name": "other"}, person("bob")))
    assert other["state"] == "succeeded"
    await platform.operations.close()
    assert platform.operations.find(platform.store.tenant("user:alice"), id)["state"] == "waiting"
    platform.operations.recover()
    op = await finish(platform, submitted)
    assert op["state"] == "succeeded" and op["result"]["domain"]["state"] == "ready"
    assert len(platform.store.objects("domains", 1)) == 1


async def test_real_certificate_budget_never_reports_success(platform):
    from carrel.domains import Domains

    await create(platform)
    for index in range(30):
        platform.store.put(
            "certificates",
            str(index),
            2,
            {"id": str(index), "tenant_n": 2, "slug": "bob", "issued_at": time.time()},
        )
    platform.domains.ensure = Domains(platform.store, {}).ensure
    result = await platform.execute(
        "domain_add", {"machine": "existing", "sub": "budget", "target_port": 80}, person()
    )
    op = await wait_state(platform, result["operation"]["id"], "waiting")
    assert op["ready_at"] > time.time() + 86400
    platform.domains.record.assert_not_awaited()


async def test_suspension_blocks_submissions_and_takes_priority(platform):
    await create(platform)
    async with platform.lock:
        normal = await platform.execute("network_create", {"name": "queued"}, person("bob"))
        suspended = await platform.execute("tenant_suspend", {"tenant": "alice"}, person("bob", admin=True))
        assert platform.store.tenant("user:alice")["status"] == "suspending"
        assert (await platform.execute("network_create", {"name": "blocked"}, person()))["error"][
            "code"
        ] == "forbidden"
        assert (await platform.execute("quota_get", {}, person()))["ok"]
        await asyncio.sleep(0)
    assert (await finish(platform, suspended))["state"] == "succeeded"
    assert (await finish(platform, normal))["state"] == "succeeded"
    assert platform.store.tenant("user:alice")["status"] == "suspended"
    assert platform.store.objects("machines", 1)[0]["state"] == "stopped"


async def test_bounded_queue_preserves_idempotency_and_admin_suspension(platform):
    platform.config["max_tenant_pending_operations"] = 1
    async with platform.lock:
        a = {"name": "first", "idempotency_key": "bounded-1234"}
        first = await platform.execute("network_create", a, person())
        assert (await platform.execute("network_create", a, person()))["operation"]["id"] == first[
            "operation"
        ]["id"]
        assert (await platform.execute("network_create", {"name": "second"}, person()))["error"]["retryable"]
        suspend = await platform.execute("tenant_suspend", {"tenant": "alice"}, person(admin=True))
    assert (await finish(platform, suspend))["state"] == "succeeded"
    assert (await finish(platform, first))["state"] == "failed"


async def test_intent_preview_and_whole_group_reservation(platform):
    import jsonschema

    spec = web_stack()
    jsonschema.validate(spec, BY_NAME["deployment_apply"].inputSchema)
    preview = await platform.execute("deployment_plan", spec, person())
    assert preview["ok"] and preview["ready_to_apply"]
    assert preview["delta"]["public_ports"] == 3 and preview["delta"]["domains"] == 1
    assert not platform.store.objects("machines") and not platform.store.objects("domains")
    original = platform.backend.call

    async def inspect(request):
        if request["op"] == "create":
            assert len(platform.store.objects("machines", 1)) == 2
            assert len(platform.store.objects("ports", 1)) == 3
            assert len(platform.store.objects("domains", 1)) == 1
            assert len(platform.store.objects("peers", 1)) == 1
        return await original(request)

    platform.backend.call = inspect
    op = await finish(platform, await platform.execute("deployment_apply", spec, person()))
    assert op["state"] == "succeeded", op
    assert len(op["result"]["endpoints"]) == 2
    assert op["result"]["endpoints"][0]["url"] == "https://web.alice.winlab.tw"
    assert all(m["readiness"]["ssh_ready"] for m in op["result"]["machines"])


async def test_publication_failure_rolls_back_only_its_grants_on_existing_machine(platform):
    await create(platform)
    before = json.dumps(platform.store.objects("machines"), sort_keys=True)
    platform.domains.ensure.side_effect = RuntimeError("ACME down")
    spec = {
        "publications": [
            {"machine": "existing", "protocol": "tcp", "port": 22},
            {"machine": "existing", "protocol": "https", "port": 80, "sub": "new"},
            {"machine": "existing", "protocol": "tcp", "port": 8080},
        ]
    }
    op = await finish(platform, await platform.execute("deployment_apply", spec, person()))
    assert op["state"] == "rolled_back", op
    assert json.dumps(platform.store.objects("machines"), sort_keys=True) == before
    assert len(platform.store.objects("ports", 1)) == 1
    assert not platform.store.objects("domains", 1)


async def test_existing_machine_publication_and_retry_do_not_duplicate_resources(platform):
    await create(platform)
    spec = {
        "publications": [{"machine": "existing", "protocol": "https", "port": 80, "sub": "web"}],
        "on_failure": "keep",
    }
    platform.domains.ensure.side_effect = RuntimeError("ACME down")
    submitted = await platform.execute("deployment_apply", spec, person())
    op = await finish(platform, submitted)
    assert op["state"] == "failed"
    platform.domains.ensure.side_effect = None
    retried = await platform.execute("operation_retry", {"id": op["id"]}, person())
    op = await finish(platform, retried)
    assert op["state"] == "succeeded", op
    assert len(platform.store.objects("domains", 1)) == 1
    assert len(platform.store.objects("machines", 1)) == 1


async def test_preview_guides_missing_requirements_then_one_apply(platform):
    spec = web_stack()
    for m in spec["machines"]:
        m.pop("ssh_keys")
    result = await platform.execute("deployment_plan", spec, person())
    assert result["ok"] and not result["ready_to_apply"]
    assert result["next_action"] == "provide_requirements"
    assert {r["machine"] for r in result["requirements"]} == {"app", "db"}
    result = await platform.execute("deployment_plan", web_stack(), person())
    assert result["ready_to_apply"] and result["next_action"] == "deployment_apply"
    assert not platform.store.objects("machines", 1)
    assert not platform.store.objects("operations", 1)


async def test_invalid_unreserved_job_requires_revised_request(platform):
    submitted = await platform.execute(
        "machine_create", {"name": "web", "kind": "ct", "ssh_keys": [KEY], "packages": ["nginx"]}, person()
    )
    op = await finish(platform, submitted)
    assert op["state"] == "failed" and not op["reserved"]
    assert platform.operations.public(op)["next_action"] == "revise_request"
    assert not platform.store.objects("machines", 1)
    corrected = await platform.execute(
        "machine_create", {"name": "web", "kind": "vm", "ssh_keys": [KEY], "packages": ["nginx"]}, person()
    )
    op = await finish(platform, corrected)
    assert op["state"] == "succeeded"
    assert platform.operations.public(op)["next_action"] == "use_result"


def test_reserved_or_cleanup_failure_keeps_recovery_path(platform):
    for state, reserved in [("failed", True), ("cleanup_failed", False)]:
        op = {"state": state, "reserved": reserved, "error": {"code": "invalid"}}
        assert platform.operations.public(op)["next_action"] == "operation_retry"


@pytest.mark.parametrize("change", ["foreign", "unrestricted", "extra_nic", "duplicate", "ports_quota"])
async def test_invalid_intents_fail_before_reservation(platform, change):
    spec = web_stack()
    if change == "foreign":
        spec["connections"][0]["from"] = "bobs-machine"
    elif change == "unrestricted":
        spec["machines"][1]["network_access"] = "tenant"
    elif change == "extra_nic":
        spec.update(networks=[{"name": "bypass"}], attachments=[{"machine": "db", "network": "bypass"}])
    elif change == "duplicate":
        spec["publications"].append(spec["publications"][0])
    else:
        platform.store.db.execute("UPDATE tenants SET quota=json_set(quota, '$.public_ports', 2) WHERE n=1")
    result = await platform.execute("deployment_plan", spec, person())
    assert not result["ok"]
    assert not platform.store.objects("machines", 1) and not platform.store.objects("ports", 1)


async def test_firewall_enforces_only_the_declared_source_protocol_and_port(platform):
    op = await finish(platform, await platform.execute("deployment_apply", web_stack(), person()))
    assert op["state"] == "succeeded"
    spec = importlib.util.spec_from_file_location(
        "intent_node", Path(__file__).parents[1] / "scripts/node-agent.py"
    )
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    t = platform.store.tenant("user:alice")
    app, db = platform.machine(t, "app"), platform.machine(t, "db")
    rules = adapter.guest_firewall(db, platform.store.desired(), {"protected_addresses": []})
    assert f"IN ACCEPT -source {app['ip']}/32 -p tcp -dport 5432" in rules
    assert "IN ACCEPT -source 10.200.1.0/24" not in rules
    assert "policy_in: DROP" in rules
    assert "-p udp -dport 5432" not in rules
    assert "IN ACCEPT -source 10.200.2.0/24" not in rules
    attached = await finish(platform, await platform.execute("network_create", {"name": "bypass"}, person()))
    assert attached["state"] == "succeeded"
    denied = await finish(
        platform,
        await platform.execute("machine_nic_attach", {"machine": "db", "network": "bypass"}, person()),
    )
    assert denied["state"] == "failed"
    assert not platform.machine(t, "db")["nics"]


async def test_domain_ready_requires_successful_route_application(platform):
    await create(platform)
    reconcile = platform.backend.reconcile
    platform.backend.reconcile = AsyncMock(side_effect=RuntimeError("edge unavailable"))
    op = await finish(
        platform,
        await platform.execute(
            "domain_add", {"machine": "existing", "sub": "web", "target_port": 80}, person()
        ),
    )
    assert op["state"] == "failed"
    assert platform.store.objects("domains", 1)[0]["state"] == "configuring"
    platform.backend.reconcile = reconcile
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "succeeded"
    assert platform.store.objects("domains", 1)[0]["state"] == "ready"
    assert platform.domains.ensure.await_count == 1


async def test_legacy_domain_failure_is_isolated_per_tenant(platform):
    platform.store.put(
        "domains",
        "orphan",
        1,
        {"id": "orphan", "tenant_n": 1, "state": "queued", "vmid": 12345, "sub": "web", "target_port": 80},
    )
    platform.store.put("domains", "bob", 2, {"id": "bob", "tenant_n": 2, "state": "ready"})
    await platform.maintain_domains()
    assert platform.store.objects("domain_status", 1)[0]["state"] == "retrying"
    assert platform.store.objects("domain_status", 2)[0]["state"] == "ready"


async def test_selected_project_uses_registration_slug_normalization(platform):
    platform.reserved = AsyncMock(return_value=set())
    result = await platform.execute(
        "quota_get", {"tenant": "my-project"}, person(projects=["winlab-projects/my__project"])
    )
    assert result["ok"]
    assert platform.store.tenant("winlab-projects/my__project")["slug"] == "my-project"


async def test_failed_reservation_transaction_can_retry_without_phantom_resources(platform):
    reserve = platform.reserve_access

    def interrupted(*args):
        reserve(*args)
        raise RuntimeError("reservation interrupted")

    platform.reserve_access = interrupted
    op = await finish(
        platform, await platform.execute("deployment_apply", {**web_stack(), "on_failure": "keep"}, person())
    )
    assert op["state"] == "failed" and "deployment" not in op
    for kind in ("machines", "ports", "peers", "domains"):
        assert not platform.store.objects(kind)
    platform.reserve_access = reserve
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "succeeded"


@pytest.mark.parametrize("replacement", ["machine", "domain", "reused_port"])
async def test_retry_refuses_replaced_intent_resources(platform, replacement):
    await create(platform)
    spec = {
        "publications": [
            {"machine": "existing", "protocol": "https", "port": 80, "sub": "web"},
            {"machine": "existing", "protocol": "tcp", "port": 22},
        ],
        "on_failure": "keep",
    }
    platform.domains.ensure.side_effect = RuntimeError("ACME down")
    tool = "domain_add" if replacement == "domain" else "deployment_apply"
    args = {"machine": "existing", "sub": "web", "target_port": 80} if tool == "domain_add" else spec
    op = await finish(platform, await platform.execute(tool, args, person()))
    assert op["state"] == "failed"
    if replacement == "machine":
        m = platform.store.objects("machines", 1)[0]
        m["allocation_id"] = "replacement"
        platform.store.put("machines", m["vmid"], 1, m)
    elif replacement == "domain":
        d = platform.store.objects("domains", 1)[0]
        platform.store.remove("domains", d["id"])
    else:
        p = platform.store.objects("ports", 1)[0]
        p["operation_id"] = "replacement"
        platform.store.put("ports", p["id"], 1, p)
    before = platform.store.desired()
    platform.domains.ensure.side_effect = None
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "failed" and op["error"]["code"] == "conflict"
    assert platform.store.desired() == before


async def test_publish_ssh_again_after_explicit_port_close(platform):
    await create(platform)
    port = platform.store.objects("ports", 1)[0]
    await finish(platform, await platform.execute("port_close", {"id": port["id"]}, person()))
    spec = {"publications": [{"machine": "existing", "protocol": "tcp", "port": 22}]}
    plan = await platform.execute("deployment_plan", spec, person())
    assert plan["delta"]["public_ports"] == 1
    op = await finish(platform, await platform.execute("deployment_apply", spec, person()))
    assert op["state"] == "succeeded"
    assert len(platform.store.objects("ports", 1)) == 1


async def test_partial_grant_cleanup_stays_charged_and_preserves_reused_route(platform):
    await create(platform)
    await finish(
        platform,
        await platform.execute(
            "domain_add", {"machine": "existing", "sub": "keep", "target_port": 80}, person()
        ),
    )
    kept = platform.store.objects("domains", 1)[0]
    platform.domains.ensure.side_effect = RuntimeError("issuance failed")
    platform.domains.record.side_effect = RuntimeError("DNS cleanup failed")
    spec = {
        "publications": [
            {"machine": "existing", "protocol": "https", "port": 80, "sub": "keep"},
            {"machine": "existing", "protocol": "https", "port": 8080, "sub": "new"},
        ]
    }
    # Simulate failure after the only new route has been withdrawn at the edge.
    reconcile = platform.backend.reconcile
    count = 0

    async def fail_cleanup(state):
        nonlocal count
        count += 1
        if count > 1:
            raise RuntimeError("edge cleanup unavailable")
        return await reconcile(state)

    platform.backend.reconcile = fail_cleanup
    op = await finish(platform, await platform.execute("deployment_apply", spec, person()))
    assert op["state"] == "cleanup_failed" and op["reserved"]
    assert platform.quota(platform.store.tenant("user:alice"))["used"]["domains"] == 2
    assert kept in platform.store.objects("domains", 1)
    platform.backend.reconcile = reconcile
    platform.domains.record.side_effect = None
    op = await finish(platform, await platform.execute("operation_retry", {"id": op["id"]}, person()))
    assert op["state"] == "rolled_back" and not op["reserved"]
    assert platform.store.objects("domains", 1) == [kept]


async def test_legacy_tcp_peer_tool_preserves_declared_udp_connection(platform):
    spec = web_stack()
    spec["connections"][0]["protocol"] = "udp"
    await finish(platform, await platform.execute("deployment_apply", spec, person()))
    original = platform.store.objects("peers", 1)[0]
    op = await finish(
        platform,
        await platform.execute(
            "peer_allow",
            {"machine": "db", "from_tenant": "alice", "from_machine": "app", "port": 5432},
            person(),
        ),
    )
    assert op["state"] == "succeeded"
    peers = platform.store.objects("peers", 1)
    assert len(peers) == 2 and original in peers
    assert {p["proto"] for p in peers} == {"tcp", "udp"}


async def test_retry_obeys_pending_queue_limit(platform):
    platform.config["max_tenant_pending_operations"] = 1
    op = await finish(
        platform,
        await platform.execute(
            "domain_add", {"machine": "missing", "sub": "web", "target_port": 80}, person()
        ),
    )
    assert op["state"] == "failed"
    async with platform.lock:
        submitted = await platform.execute("network_create", {"name": "pending"}, person())
        rejected = await platform.execute("operation_retry", {"id": op["id"]}, person())
        assert not rejected["ok"] and rejected["error"]["retryable"]
        assert platform.operations.find(platform.store.tenant("user:alice"), op["id"])["state"] == "failed"
    assert (await finish(platform, submitted))["state"] == "succeeded"
