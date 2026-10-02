"""Generate frozen, deterministic behavior cases from the released Python control plane."""

import asyncio
import copy
import json
from pathlib import Path

from carrel.platform import Platform
from carrel.store import Store


class Backend:
    async def call(self, request, target=None):
        if request["op"] == "inventory":
            return {
                "status": {
                    "cpuinfo": {"cpus": 32, "cores": 16, "sockets": 2},
                    "memory": {"total": 192 * 1024**3, "used": 20 * 1024**3},
                },
                "storage": {"total": 1500 * 1024**3, "used": 10 * 1024**3},
                "resources": [],
                "disk_committed_bytes": 20 * 1024**3,
                "thin_pool": {"metadata_fraction": 0.01},
            }
        return {"status": "running"}

    async def reconcile(self, state):
        return {"node": {}, "edge": {}}


WHO = {"sub": "alice", "username": "alice", "admin": False, "projects": []}
ADMIN = {**WHO, "admin": True}


def setup():
    store = Store(":memory:")
    for subject, slug in [("user:alice", "alice"), ("user:bob", "bob"), ("winlab-projects/shared", "shared")]:
        store.register(subject, slug)
    platform = Platform(store, Backend(), {})
    tenant = store.tenant("user:alice")
    spec = platform.machine_spec(
        tenant, {"name": "existing", "ssh_keys": ["ssh-ed25519 AAAA fixture"]}, False
    )
    machine, _ = platform.allocate_machine(tenant, spec)
    machine.update(
        state="ready",
        created_at=1,
        allocation_id="fixture",
        readiness_token="fixture-token",
        operation_id="seed",
    )
    store.put("machines", machine["vmid"], 1, machine)
    network = platform.network_spec(tenant, {"name": "private"})
    store.put("networks", network["id"], 1, network)
    snapshot = {
        "id": "10100-before",
        "vmid": 10100,
        "name": "before",
        "disk_gb": 20,
        "configuration": {k: machine[k] for k in ("cpu", "memory_mb", "disk_gb", "nics")},
        "state": "ready",
    }
    store.put("snapshots", snapshot["id"], 1, snapshot)
    store.put(
        "requests",
        "request",
        1,
        {
            "id": "request",
            "tenant_n": 1,
            "kind": "quota",
            "status": "pending",
            "dimension": "vcpu",
            "amount": 12,
            "until": None,
        },
    )
    return platform


def cases():
    for tool in (
        "whoami",
        "catalog_get",
        "quota_get",
        "machine_list",
        "network_list",
        "port_list",
        "domain_list",
        "peer_list",
        "ssh_key_list",
        "request_list",
        "operation_get",
        "sizes_list",
        "images_list",
        "capacity_get",
    ):
        yield tool, {}, WHO
    yield "whoami", {}, {**WHO, "projects": ["winlab-projects/shared"]}
    yield "machine_get", {"machine": "existing"}, WHO
    yield "snapshot_list", {"machine": "existing"}, WHO
    for args in ({"tenant": "bob"}, {"tenant": "shared"}):
        yield "quota_get", args, WHO
    for args in (
        {},
        {"kind": "ct"},
        {"image": "ubuntu-24.04", "size": "medium"},
        {"cpu": 4, "memory_mb": 4096},
        {"ssh_keys": ["ssh-ed25519 AAAA fixture"]},
        {"network_access": "restricted"},
        {"kind": "ct", "packages": ["git"]},
        {"kind": "ct", "nested_virt": True},
        {"ssh_keys": ["private key"]},
        {"name": "existing"},
        {"cpu": 20},
    ):
        yield "machine_create", {"name": "new", "dry_run": True, **args}, WHO
    for tool, args in [
        ("machine_delete", {"machine": "existing", "confirm": "existing"}),
        ("machine_delete", {"machine": "existing", "confirm": "wrong"}),
        ("machine_power", {"machine": "existing", "action": "stop"}),
        ("machine_resize", {"machine": "existing", "cpu": 1}),
        ("machine_resize", {"machine": "existing", "disk_gb": 40}),
        ("machine_resize", {"machine": "existing", "disk_gb": 10}),
        ("network_create", {"name": "new"}),
        ("network_create", {"name": "new", "mode": "raw_l2"}),
        ("network_create", {"name": "new", "cidr": "10.200.5.0/24"}),
        ("network_delete", {"network": "private", "confirm": "private"}),
        ("machine_nic_attach", {"machine": "existing", "network": "private"}),
        ("machine_nic_detach", {"machine": "existing", "nic": 0}),
        ("port_open", {"machine": "existing", "port": 8080, "proto": "tcp"}),
        ("port_open", {"machine": "existing", "port": 22, "proto": "tcp"}),
        ("port_close", {"id": "1-20010-tcp"}),
        ("domain_add", {"machine": "existing", "sub": "web", "target_port": 8080}),
        ("domain_remove", {"name": "missing.alice.winlab.tw"}),
        ("peer_allow", {"machine": "existing", "from_tenant": "bob", "port": 5432}),
        ("peer_revoke", {"id": "missing"}),
        ("snapshot_create", {"machine": "existing", "name": "after"}),
        ("snapshot_create", {"machine": "existing", "name": "before"}),
        ("snapshot_delete", {"machine": "existing", "name": "before"}),
        ("snapshot_rollback", {"machine": "existing", "name": "before", "confirm": "before"}),
        ("snapshot_rollback", {"machine": "existing", "name": "before", "confirm": "wrong"}),
        ("quota_request", {"dimension": "vcpu", "amount": 12, "reason": "experiment"}),
        ("ssh_key_add", {"key": "ssh-ed25519 AAAA fixture"}),
        ("ssh_key_remove", {"id": "missing"}),
    ]:
        yield tool, {**args, "dry_run": True}, WHO
    for tool in ("tenant_list", "node_list", "usage_report", "request_list_all"):
        yield tool, {}, ADMIN
        yield tool, {}, WHO
    for tool, args in [
        ("quota_set", {"tenant": "alice", "dimension": "vcpu", "amount": 12}),
        ("quota_set", {"tenant": "alice", "dimension": "vcpu", "amount": 1}),
        ("tenant_suspend", {"tenant": "alice"}),
        ("request_approve", {"id": "request"}),
        ("request_reject", {"id": "request"}),
        ("reconcile_run", {}),
    ]:
        yield tool, {**args, "dry_run": True}, ADMIN
    for spec in (
        {"machines": [{"name": "new"}]},
        {
            "machines": [{"name": "app"}, {"name": "db", "network_access": "restricted"}],
            "connections": [{"from": "app", "to": "db", "port": 5432}],
            "publications": [{"machine": "app", "protocol": "https", "port": 80, "sub": "web"}],
        },
        {
            "machines": [{"name": "app"}],
            "networks": [{"name": "experiment"}],
            "attachments": [{"machine": "app", "network": "experiment"}],
        },
        {"machines": [{"name": "duplicate"}, {"name": "duplicate"}]},
        {"machines": [{"name": "app"}], "connections": [{"from": "app", "to": "existing", "port": 5432}]},
        {"publications": [{"machine": "existing", "protocol": "tcp", "port": 22}]},
        {"networks": [{"name": "experiment"}]},
        {},
    ):
        yield "deployment_plan", spec, WHO


async def main():
    out = []
    for tool, args, who in cases():
        p = setup()
        seed = {
            "tenants": p.store.tenants(),
            "objects": [dict(r) for r in p.store.db.execute("SELECT * FROM objects")],
        }
        result = await p.execute(tool, copy.deepcopy(args), copy.deepcopy(who))
        out.append({"tool": tool, "args": args, "who": who, "seed": seed, "expected": result})
        p.store.db.close()
    dest = Path(__file__).resolve().parents[1] / "internal/carrel/testdata/python-parity.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2) + "\n")
    print(f"Exported {len(out)} reference cases")


if __name__ == "__main__":
    asyncio.run(main())
