"""Durable, tenant-scoped jobs. Reads never wait for the infrastructure writer."""

import asyncio
import hashlib
import json
import secrets
import time
from contextvars import ContextVar

current_operation = ContextVar("carrel_operation", default=None)

ASYNC_TOOLS = {
    "deployment_apply",
    "machine_create",
    "machine_retry",
    "machine_delete",
    "machine_resize",
    "machine_power",
    "network_create",
    "network_delete",
    "machine_nic_attach",
    "machine_nic_detach",
    "port_open",
    "port_close",
    "domain_add",
    "domain_remove",
    "peer_allow",
    "peer_revoke",
    "snapshot_create",
    "snapshot_delete",
    "snapshot_rollback",
    "reconcile_run",
    "tenant_suspend",
}
TERMINAL = {"succeeded", "failed", "rolled_back", "cleanup_failed"}


class Waiting(Exception):
    """A durable dependency wait, resumed automatically without holding the writer."""

    def __init__(self, phase, ready_at):
        self.phase, self.ready_at = phase, ready_at


def operation_id():
    op = current_operation.get()
    return op["id"] if op else None


class Operations:
    def __init__(self, platform):
        self.platform = platform
        self.store = platform.store
        self.tasks = {}

    def save(self, op):
        op["updated_at"] = time.time()
        self.store.put("operations", op["id"], op["tenant_n"], op)

    def public(self, op):
        revise = (
            op["state"] in {"failed", "rolled_back"}
            and not op.get("reserved")
            and op.get("error", {}).get("code") == "invalid"
        )
        result = {
            k: v
            for k, v in op.items()
            if k
            in {
                "id",
                "tool",
                "state",
                "phase",
                "created_at",
                "updated_at",
                "attempts",
                "result",
                "error",
                "cleanup",
                "reserved",
                "resource_changes",
                "current_resource",
                "ready_at",
            }
        }
        result["poll_after_seconds"] = (
            max(5, min(60, int(op.get("ready_at", 0) - time.time()))) if op["state"] not in TERMINAL else None
        )
        if op["state"] == "succeeded":
            result["next_action"] = "use_result"
        elif revise:
            result["next_action"] = "revise_request"
            result["next_action_detail"] = (
                "No resources remain reserved. Correct the request, preview it, then submit with a new "
                "idempotency_key; retrying this operation reuses the invalid arguments."
            )
        else:
            result["next_action"] = "operation_retry" if op["state"] in TERMINAL else "operation_get"
        return result

    def find(self, tenant, id):
        from .platform import fail

        op = next((o for o in self.store.objects("operations", tenant["n"]) if o["id"] == id), None)
        if not op:
            fail("not_found", "Operation not found in this tenant")
        return op

    def submit(self, tool, args, who, tenant, key=None):
        from .platform import fail

        args = {k: v for k, v in args.items() if k not in ("dry_run", "idempotency_key")}
        fingerprint = hashlib.sha256(json.dumps([tool, args], sort_keys=True).encode()).hexdigest()
        # The caller supplies a stable key when it needs deduplication after a lost response.
        if key:
            for old in self.store.objects("operations", tenant["n"]):
                if old.get("idempotency_key") == key:
                    if old["fingerprint"] != fingerprint:
                        fail("conflict", "Idempotency key was already used for different arguments")
                    return {"operation": self.public(old)}
        pending = self.check_queue_capacity(tenant, tool)
        if tool == "tenant_suspend":
            old = next((o for o in pending if o["tenant_n"] == tenant["n"] and o["tool"] == tool), None)
            if old:
                return {"operation": self.public(old)}
        op = {
            "id": secrets.token_hex(16),
            "tenant_n": tenant["n"],
            "tool": tool,
            "args": args,
            "who": who,
            "fingerprint": fingerprint,
            "idempotency_key": key,
            "state": "queued",
            "phase": "awaiting_capacity_check",
            "reserved": False,
            "resource_changes": False,
            "created_at": time.time(),
            "queued_at": time.time(),
            "attempts": 0,
            "generation": 0,
        }
        self.save(op)
        self.start(op)
        return {"operation": self.public(op)}

    def check_queue_capacity(self, tenant, tool):
        from .platform import fail

        pending = [o for o in self.store.objects("operations") if o["state"] not in TERMINAL]
        if tool != "tenant_suspend" and (
            len(pending) >= self.platform.config.get("max_pending_operations", 256)
            or sum(o["tenant_n"] == tenant["n"] for o in pending)
            >= self.platform.config.get("max_tenant_pending_operations", 16)
        ):
            fail("conflict", "Operation queue is full; wait for an existing operation", retryable=True)
        return pending

    def bind_machine(self, op, tenant):
        from .platform import fail

        if not op["args"].get("machine"):
            return False
        machines = self.store.objects("machines", tenant["n"])
        bound = op.get("machine_target")
        if bound:
            m = next((m for m in machines if m["vmid"] == bound["vmid"]), None)
            if not m:
                if op["tool"] == "machine_delete":
                    return True
                fail("not_found", "The operation's original machine no longer exists")
            if (m.get("allocation_id"), m.get("created_at"), m.get("operation_id")) != tuple(
                bound["identity"]
            ):
                fail("conflict", "VMID now belongs to a different allocation; retry refused")
            op["args"]["machine"] = str(bound["vmid"])
        else:
            m = self.platform.machine(tenant, op["args"]["machine"])
            op["machine_target"] = {
                "vmid": m["vmid"],
                "identity": [m.get("allocation_id"), m.get("created_at"), m.get("operation_id")],
            }
            self.save(op)
        if op["tool"] == "machine_nic_detach":
            nic = next((nic for nic in m["nics"] if nic["index"] == op["args"]["nic"]), None)
            identity = [nic.get(k) for k in ("network", "mac", "operation_id")] if nic else None
            if "nic_target" in op:
                if nic is None:
                    return True
                if identity != op["nic_target"]:
                    fail("conflict", "NIC index belongs to a different attachment; retry refused")
            elif nic:
                op["nic_target"] = identity
                self.save(op)
        return False

    def bind_object(self, op, tenant):
        from .platform import fail

        selectors = {
            "machine_nic_attach": ("networks", "network", "name"),
            "network_delete": ("networks", "network", "name"),
            "port_close": ("ports", "id", "id"),
            "domain_remove": ("domains", "name", "name"),
            "peer_revoke": ("peers", "id", "id"),
            "snapshot_delete": ("snapshots", "name", "name"),
            "snapshot_rollback": ("snapshots", "name", "name"),
        }
        if op["tool"] not in selectors:
            return False
        kind, arg, field = selectors[op["tool"]]
        objects = self.store.objects(kind, tenant["n"])
        bound = op.get("object_target")
        if bound:
            obj = next((o for o in objects if o["id"] == bound["id"]), None)
            if not obj:
                if op["tool"] not in ("snapshot_rollback", "machine_nic_attach"):
                    return True
                fail("not_found", "The operation's original resource no longer exists")
            if obj.get("operation_id") != bound["operation_id"]:
                fail("conflict", "Resource identifier belongs to a different allocation; retry refused")
        else:
            obj = next(
                (
                    o
                    for o in objects
                    if op["args"][arg] in (o["id"], o.get(field))
                    and (kind != "snapshots" or o["vmid"] == op["machine_target"]["vmid"])
                ),
                None,
            )
            if obj:
                op["object_target"] = {"id": obj["id"], "operation_id": obj.get("operation_id")}
                self.save(op)
        return False

    def start(self, op):
        if op["id"] not in self.tasks:
            task = asyncio.create_task(self.run(op["id"]))
            self.tasks[op["id"]] = task
            task.add_done_callback(lambda _: self.tasks.pop(op["id"], None))

    def recover(self):
        for op in sorted(self.store.objects("operations"), key=lambda o: o.get("queued_at", o["created_at"])):
            if op["state"] not in TERMINAL:
                self.start(op)

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def run(self, id):
        while True:
            op = next(o for o in self.store.objects("operations") if o["id"] == id)
            if op["state"] == "waiting":
                delay = max(0, op.get("ready_at", 0) - time.time())
                tenant = next(t for t in self.store.tenants() if t["n"] == op["tenant_n"])
                if tenant["status"] != "active" and op["phase"] != "waiting_for_priority_operation":
                    delay = 0
                if delay:
                    await asyncio.sleep(min(delay, 30))
                    continue
            await self.step(id)
            op = next(o for o in self.store.objects("operations") if o["id"] == id)
            if op["state"] != "waiting":
                return

    async def step(self, id):
        from .platform import Failure

        # A single infrastructure writer deliberately preserves admission order.
        # No HTTP request or read-only tool takes this lock. The durable queue is
        # returned immediately, before waiting for this worker.
        async with self.platform.lock:
            op = next(o for o in self.store.objects("operations") if o["id"] == id)
            if op["tool"] != "tenant_suspend" and any(
                o["tool"] == "tenant_suspend" and o["state"] not in TERMINAL
                for o in self.store.objects("operations")
            ):
                op.update(
                    state="waiting", phase="waiting_for_priority_operation", ready_at=time.time() + 0.05
                )
                self.save(op)
                return
            cleanup_only = op["state"] == "cleaning_up" or op.pop("resume_cleanup", False)
            context = current_operation.set(
                {"id": id, "generation": op["generation"], "store": self.store, "record": op}
            )
            op.update(state="running", phase="applying", attempts=op["attempts"] + 1)
            self.save(op)
            try:
                tenant = next(t for t in self.store.tenants() if t["n"] == op["tenant_n"])
                if tenant["status"] != "active" and op["tool"] != "tenant_suspend" and not cleanup_only:
                    raise Failure("forbidden", "Tenant is suspended")
                if cleanup_only:
                    cleanup = await self.platform.cleanup_deployment(op, op["who"])
                    op.update(
                        cleanup=cleanup,
                        state="cleanup_failed" if cleanup else "rolled_back",
                        phase="cleanup_failed" if cleanup else "rolled_back",
                        reserved=bool(cleanup),
                    )
                    self.save(op)
                    return
                if self.bind_machine(op, tenant) or self.bind_object(op, tenant):
                    await self.platform.reconcile()
                    op.update(
                        state="succeeded", phase="complete", result={"ok": True, "already_deleted": True}
                    )
                    self.save(op)
                    return
                result, _ = await self.platform._execute(op["tool"], op["args"], op["who"])
                # Readiness belongs to the job outcome, not merely the SSH probe.
                machines = [
                    m for m in self.store.objects("machines", tenant["n"]) if m.get("operation_id") == id
                ]
                if result.get("machine"):
                    m = self.platform.machine(tenant, result["machine"]["name"])
                    machines = [v for v in machines if v["vmid"] != m["vmid"]] + [m]
                for m in machines:
                    if m.get("state") in ("initializing", "provisioning", "needs_owner_fix"):
                        op["phase"] = "waiting_for_guest"
                        op["current_resource"] = m["name"]
                        self.save(op)
                        await self.platform.wait_ready(m)
                if result.get("machine"):
                    m = self.platform.machine(tenant, result["machine"]["name"])
                    result["machine"] = self.platform.public_machine(
                        m, self.store.objects("ports", tenant["n"])
                    )
                if op["tool"] == "deployment_apply":
                    result["machines"] = [
                        self.platform.public_machine(
                            self.platform.machine(tenant, str(vmid)), self.store.objects("ports", tenant["n"])
                        )
                        for vmid in op["deployment"]["machines"]
                    ]
                op.update(
                    state="succeeded",
                    phase="complete",
                    result={"ok": True, **result},
                    resource_changes=True,
                )
                op.pop("ready_at", None)
            except Waiting as exc:
                op.update(state="waiting", phase=exc.phase, ready_at=exc.ready_at)
            except asyncio.CancelledError:
                # Leave the durable running state for recovery at the next startup.
                raise
            except Exception as exc:  # noqa: BLE001 - persist all worker failures for recovery
                error = (
                    exc.result["error"]
                    if isinstance(exc, Failure)
                    else {
                        "code": "conflict",
                        "message": "Infrastructure operation failed; retry uses the same allocation",
                    }
                )
                op.update(state="failed", phase="failed", error=error)
                print(json.dumps({"event": "operation_failed", "operation": id, "type": type(exc).__name__}))
                self.save(op)
                if (
                    op["tool"] == "deployment_apply"
                    and op["args"].get("on_failure", "rollback") == "rollback"
                ):
                    op.update(state="cleaning_up", phase="removing_new_resources")
                    self.save(op)
                    cleanup = await self.platform.cleanup_deployment(op, op["who"])
                    op.update(
                        cleanup=cleanup,
                        state="cleanup_failed" if cleanup else "rolled_back",
                        phase="cleanup_failed" if cleanup else "rolled_back",
                        reserved=bool(cleanup),
                    )
            finally:
                current_operation.reset(context)
            op["reserved"] = any(
                o.get("operation_id") == id
                for kind in ("machines", "networks", "snapshots", "ports", "domains", "peers")
                for o in self.store.objects(kind, op["tenant_n"])
            )
            self.save(op)
            self.store.log(
                op["who"]["sub"],
                op["tenant_n"],
                "operation_finished" if op["state"] in TERMINAL else "operation_waiting",
                {"operation": id, "tool": op["tool"]},
                op["state"],
            )

    def retry(self, tenant, id, who):
        op = self.find(tenant, id)
        if op["state"] in TERMINAL - {"succeeded"}:
            self.check_queue_capacity(tenant, op["tool"])
            if op["state"] == "cleanup_failed":
                op["resume_cleanup"] = True
            if op["state"] == "rolled_back":
                op["generation"] += 1
                op.pop("deployment", None)
            op.update(state="queued", phase="retry_queued", who=who, queued_at=time.time())
            op.pop("error", None)
            op.pop("result", None)
            op.pop("ready_at", None)
            self.save(op)
            self.start(op)
        return {"operation": self.public(op)}
