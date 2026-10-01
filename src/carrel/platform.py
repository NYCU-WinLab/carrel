import asyncio
import ipaddress
import json
import re
import secrets
import time
from datetime import UTC, datetime

import httpx

from .capacity import UNITS, summarize
from .domains import Domains
from .intent import Intent
from .lifecycle import Lifecycle
from .operations import ASYNC_TOOLS, Operations, Waiting, current_operation, operation_id
from .store import DEFAULT_QUOTA

QUOTA_DIMENSIONS = tuple(k for k in DEFAULT_QUOTA if k != "images_gb")
CAPABILITIES = {
    "deployment_planning": True,
    "background_operations": True,
    "deployment_apply": True,
    "deployment_connections": True,
    "deployment_publications": True,
    "restricted_machine_ingress": True,
    "managed_private_networks": True,
    "guest_readiness": True,
    "stopped_machine_reservations": True,
    "separate_snapshot_quota": True,
    "capacity_summary": True,
    "capacity_visibility": "aggregate_only",
    "gpu_allocation": False,
    "gpu_hardware_inventory": "unknown",
    "custom_image_upload": False,
    "custom_image_import": False,
    "mcp_resources": False,
}

SIZES = {
    "small": {"cpu": 2, "memory_mb": 2048, "disk_gb": 20},
    "medium": {"cpu": 4, "memory_mb": 8192, "disk_gb": 40},
    "large": {"cpu": 8, "memory_mb": 16384, "disk_gb": 80},
}
RESERVED = {"carrel", "www", "auth", "mail", "admin", "api", "mcp", "status", "internal"}
IMAGES = [
    {"name": "debian-13", "kind": "vm", "default": True, "support_until": "2030-06-30"},
    {"name": "debian-13", "kind": "ct", "default": True, "support_until": "2030-06-30"},
    {"name": "ubuntu-24.04", "kind": "vm", "default": False, "support_until": "2029-04-30"},
    {"name": "ubuntu-24.04", "kind": "ct", "default": False, "support_until": "2029-04-30"},
]


class Failure(Exception):
    def __init__(self, code, message, **details):
        self.result = {"ok": False, "error": {"code": code, "message": message, **details}}


def fail(code, message, **details):
    raise Failure(code, message, **details)


def slug(value):
    value = re.sub("-+", "-", value.lower().replace(".", "-").replace("_", "-")).strip("-")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value) or value in RESERVED:
        fail("conflict", "Username requires an administrator-assigned tenant alias")
    return value


def validate_keys(keys):
    if not 1 <= len(keys) <= 20:
        fail("invalid", "Supply 1 to 20 SSH public keys")
    for k in keys:
        if len(k) > 16000 or not re.fullmatch(
            r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+(?: [^\r\n]*)?", k
        ):
            fail("invalid", "Only SSH public keys are accepted")


class Platform(Lifecycle, Intent):
    def __init__(self, store, backend, config):
        self.store, self.backend, self.config = store, backend, config
        self.lock = asyncio.Lock()
        self.registration_lock = asyncio.Lock()
        self.operations = Operations(self)
        self.domains = Domains(store, config)

    async def reserved(self):
        token = self.config.get("cloudflare_token")
        zone = self.config.get("cloudflare_zone")
        if not token or not zone:
            fail("conflict", "DNS ownership checks are not configured; registration is paused")
        async with httpx.AsyncClient(timeout=15) as h:
            response = await h.get(
                f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                params={"per_page": 5000},
                headers={"Authorization": "Bearer " + token},
            )
        response.raise_for_status()
        data = response.json()
        if not data.get("success") or data.get("result_info", {}).get("total_pages", 1) > 1:
            fail("conflict", "Could not verify DNS namespace ownership")
        labels = set(RESERVED)
        for r in data["result"]:
            name = r["name"].removesuffix(".winlab.tw")
            labels.add(name.split(".")[-1])
        return labels

    def subjects(self, who):
        return [("user:" + who["sub"], who["username"]), *[(g, g.split("/")[1]) for g in who["projects"]]]

    async def register_tenants(self, who, name=None, overview=False):
        subjects = self.subjects(who)
        if not overview:
            if name:
                existing = [self.store.tenant(s) for s, _ in subjects]
                if any(t and t["slug"] == name for t in existing):
                    return []
                subjects = [
                    (s, label)
                    for s, label in subjects
                    if re.sub("-+", "-", label.lower().replace("_", "-").replace(".", "-")).strip("-") == name
                ]
                if not subjects:
                    fail("forbidden", "Tenant is not in your current Keycloak memberships")
            else:
                subjects = subjects[:1]
        missing = [(s, label) for s, label in subjects if not self.store.tenant(s)]
        if not missing:
            return []
        async with self.registration_lock:
            return await self._register_tenants(who, missing, overview)

    async def _register_tenants(self, who, subjects, overview):
        missing = [(s, name) for s, name in subjects if not self.store.tenant(s)]
        if not missing:
            return []
        try:
            reserved = await self.reserved()
        except (Failure, RuntimeError, httpx.HTTPError):
            if not overview:
                raise
            return [{"name": name, "code": "registration_unavailable"} for _, name in missing]
        reserved.update(t["slug"] for t in self.store.tenants())
        problems = []
        for subject, name in missing:
            try:
                label = slug(name)
                if label in reserved:
                    fail("conflict", "Tenant slug is already owned; administrator alias required")
                t = self.store.register(subject, label)
            except Failure as exc:
                if not overview:
                    raise
                problems.append({"name": name, **exc.result["error"]})
                continue
            reserved.add(label)
            self.store.log(who["sub"], t["n"], "tenant_register", {}, "ok")
        return problems

    def tenant(self, who, name=None):
        allowed = [self.store.tenant(s) for s, _ in self.subjects(who)]
        allowed = [t for t in allowed if t]
        if name:
            t = next((t for t in allowed if t["slug"] == name), None)
        else:
            t = self.store.tenant("user:" + who["sub"])
        if not t:
            fail("forbidden", "Tenant is not registered or is not in your current Keycloak memberships")
        return t

    def machine(self, t, ref):
        m = next(
            (
                m
                for m in self.store.objects("machines", t["n"])
                if str(m["vmid"]) == str(ref) or m["name"] == str(ref)
            ),
            None,
        )
        if not m:
            fail("not_found", "Machine not found in this tenant")
        return m

    def usage(self, t):
        used = dict.fromkeys(DEFAULT_QUOTA, 0)
        for m in self.store.objects("machines", t["n"]):
            used["vcpu"] += m["cpu"]
            used["memory_mb"] += m["memory_mb"]
            used["disk_gb"] += m["disk_gb"]
            used["machines"] += 1
            used["ips"] += 1
        for kind, dimension in [
            ("ports", "public_ports"),
            ("domains", "domains"),
            ("networks", "networks"),
            ("snapshots", "snapshots"),
        ]:
            used[dimension] = len(self.store.objects(kind, t["n"]))
        # Snapshots reserve a full virtual disk: conservative until precise thin
        # snapshot accounting is available, rather than making a false promise.
        used["snapshot_gb"] = sum(s["disk_gb"] for s in self.store.objects("snapshots", t["n"]))
        return used

    def quota(self, t, delta=None):
        usage = {k: v for k, v in self.usage(t).items() if k in QUOTA_DIMENSIONS}
        limits = {k: t["quota"][k] for k in QUOTA_DIMENSIONS}
        for key, value in (delta or {}).items():
            usage[key] += value
        result = {
            "used": usage,
            "limit": limits,
            "remaining": {k: limits[k] - usage[k] for k in limits},
            "units": UNITS,
            "over_limit": [k for k in limits if usage[k] > limits[k]],
        }
        exceeded = [
            {"dimension": k, "used": v, "limit": limits[k]}
            for k, v in usage.items()
            if delta is not None and v > limits[k] and (not delta or delta.get(k, 0) > 0)
        ]
        if exceeded:
            fail(
                "quota_exceeded",
                "Tenant quota would be exceeded",
                **exceeded[0],
                violations=exceeded,
                quota_after=result,
            )
        return result

    def snapshot_usage(self, t):
        samples = self.store.objects("storage_usage", t["n"])
        return (
            {k: v for k, v in samples[0].items() if k not in ("tenant_n", "operation_id")}
            if samples
            else {
                "available": False,
                "retained_snapshot_bytes": None,
                "accounting": "pending_sample; snapshot_gb reserves worst-case size",
            }
        )

    async def capacity(self, proposed=None):
        reservations = self.store.objects("machines")
        if proposed:
            reservations = [m for m in reservations if m["vmid"] != proposed["vmid"]] + [proposed]
        return summarize(
            await self.backend.call({"op": "inventory"}), reservations, self.store.objects("snapshots")
        )

    async def admission(self, cpu, memory, disk, proposed=None, snapshot=False):
        capacity = await self.capacity(proposed)
        demand = {"vcpu": cpu, "memory_gib": memory / 1024, "disk_gib": disk}
        for key, amount in demand.items():
            allocation = capacity["allocatable"][key]
            if amount + allocation["committed"] > allocation["limit"]:
                fail(
                    "capacity_exhausted",
                    "Node admission limit",
                    dimension=key,
                    requested=amount,
                    remaining=capacity["allocatable"][key]["remaining"],
                )
        if snapshot and disk > capacity["policy"]["snapshot_headroom_gib"]:
            fail("capacity_exhausted", "Snapshot worst-case reservation exceeds safe physical headroom")
        growing_disk = disk > 0 or (
            proposed
            and any(
                m["vmid"] == proposed["vmid"] and proposed["disk_gb"] > m["disk_gb"]
                for m in self.store.objects("machines")
            )
        )
        if growing_disk and capacity["policy"]["storage_admission_blocked"]:
            fail("capacity_exhausted", "Storage usage exceeds admission ceiling")
        return {"accepted": True, "checked_at": capacity["checked_at"], "reserved": False}

    def machine_spec(self, t, a, dry):
        if any(m["name"] == a["name"] for m in self.store.objects("machines", t["n"])):
            fail("conflict", "Machine name is already allocated")
        spec = {
            **SIZES[a.get("size", "small")],
            **{k: a[k] for k in ("cpu", "memory_mb", "disk_gb") if k in a},
        }
        kind, image = a.get("kind", "vm"), a.get("image", "debian-13")
        if not any(i["name"] == image and i["kind"] == kind for i in IMAGES):
            fail("invalid", "Image is not available")
        keys = a.get("ssh_keys") or [k["key"] for k in self.store.objects("keys", t["n"])]
        if keys or not dry:
            validate_keys(keys)
        if kind == "ct" and (
            a.get("nested_virt") or a.get("packages") or a.get("runcmd") or a.get("health_checks")
        ):
            fail("invalid", "Use a VM for nested virtualization or cloud-init commands")
        return {
            "name": a["name"],
            "kind": kind,
            "image": image,
            **spec,
            "ssh_keys": keys,
            "nested_virt": a.get("nested_virt", False),
            "swap_mb": a.get("swap_mb", 4096 if kind == "vm" else 0),
            "packages": a.get("packages", []),
            "runcmd": a.get("runcmd", []),
            "health_checks": a.get("health_checks", []),
            "network_access": a.get("network_access", "tenant"),
            "readiness_token": secrets.token_urlsafe(32) if not dry else None,
            "guest_management": 1,
            "nics": [],
        }

    @staticmethod
    def machine_delta(m):
        return {
            "vcpu": m["cpu"],
            "memory_mb": m["memory_mb"],
            "disk_gb": m["disk_gb"],
            "machines": 1,
            "ips": 1,
            "public_ports": 1,
        }

    @staticmethod
    def planned_machine(m):
        return {
            k: v
            for k, v in m.items()
            if k
            in (
                "name",
                "kind",
                "image",
                "cpu",
                "memory_mb",
                "disk_gb",
                "swap_mb",
                "nested_virt",
                "packages",
                "health_checks",
                "network_access",
            )
        } | {
            "state": "planned",
            "reserved": False,
            "requirements": [] if m["ssh_keys"] else ["ssh_public_key"],
        }

    @staticmethod
    def validate_network(a):
        if a.get("cidr"):
            try:
                ipaddress.IPv4Network(a["cidr"])
            except ValueError:
                fail("invalid", "Invalid network CIDR")

    @staticmethod
    def mutation_result(before, result, dry):
        after = result.get("quota_after", before)
        result.update(
            quota_before=before,
            quota_after=after,
            delta={
                k: after["used"][k] - before["used"][k]
                for k in before["used"]
                if after["used"][k] != before["used"][k]
            },
            dry_run=dry,
        )
        if after["limit"] != before["limit"]:
            result["limit_delta"] = {
                k: after["limit"][k] - before["limit"][k]
                for k in before["limit"]
                if after["limit"][k] != before["limit"][k]
            }
        if dry:
            result.update(state="planned", reserved=False, resource_changes=False)
            result.setdefault("requirements", [])
            result.setdefault("ready_to_apply", not result["requirements"])
        return result

    async def reconcile(self):
        # Local network/edge convergence never makes a DNS-provider request.
        # Certificate issuance and DNS retries belong to their own domain jobs.
        state = self.store.desired()
        state["domains"] = [
            dict(d, state="ready") if d["state"] == "configuring" else d for d in state["domains"]
        ]
        state["certificates"] = self.domains.bundles(state["domains"])
        result = await self.backend.reconcile(state)
        await self.refresh_storage_usage()
        return result

    async def maintain_domains(self):
        # One tenant's DNS/ACME failure must not skip other tenants or the
        # network reconciler. Active jobs own their pending publication state.
        for tenant in self.store.tenants():
            domains = [d for d in self.store.objects("domains", tenant["n"]) if d["state"] != "deleting"]
            issued = self.store.objects("certificates", tenant["n"])
            if not domains and not issued:
                continue
            try:
                active = {
                    o["id"]
                    for o in self.store.objects("operations", tenant["n"])
                    if o["state"] not in {"succeeded", "failed", "rolled_back", "cleanup_failed"}
                }
                for domain in domains:
                    # Older releases could finish a job while its certificate
                    # remained queued. Keep those legacy routes recoverable.
                    if (
                        domain["state"] in ("queued", "configuring")
                        and domain.get("operation_id") not in active
                        and domain.get("ready_at", 0) <= time.time()
                    ):
                        await self.member(
                            "domain_add",
                            {
                                "machine": str(domain["vmid"]),
                                "sub": domain["sub"],
                                "target_port": domain["target_port"],
                            },
                            {"sub": "system"},
                            tenant,
                        )
                if issued or any(d["state"] == "ready" for d in domains):
                    await self.domains.record(tenant, remove=not domains)
                await self.domains.renew(tenant)
                status = {"state": "ready", "checked_at": time.time()}
            except Waiting as exc:
                status = {"state": "waiting", "ready_at": exc.ready_at, "checked_at": time.time()}
            except (Failure, RuntimeError, OSError, httpx.HTTPError):
                status = {
                    "state": "retrying",
                    "checked_at": time.time(),
                    "error": "DNS or certificate maintenance failed",
                }
            self.store.put("domain_status", str(tenant["n"]), tenant["n"], status)

    async def refresh_storage_usage(self):
        try:
            samples = await self.backend.call(
                {"op": "storage_usage", "machines": self.store.objects("machines")}
            )
            if isinstance(samples, list):
                for sample in samples:
                    self.store.put("storage_usage", sample["tenant_n"], sample["tenant_n"], sample)
        except (RuntimeError, httpx.HTTPError):
            # Accounting is observational; reserved worst-case snapshot budgets
            # continue to enforce limits if a sample is unavailable.
            pass

    async def expire_grants(self):
        for r in self.store.objects("requests"):
            if r["status"] != "approved" or not r.get("until"):
                continue
            if datetime.fromisoformat(r["until"]).replace(tzinfo=UTC).timestamp() > time.time():
                continue
            t = next(t for t in self.store.tenants() if t["n"] == r["tenant_n"])
            t["quota"][r["dimension"]] = r["previous_limit"]
            self.store.db.execute("UPDATE tenants SET quota=? WHERE n=?", (json.dumps(t["quota"]), t["n"]))
            # Expiry restores the ceiling; it does not reclaim allocations.
            # Only growth in an exceeded dimension is blocked. Deletion,
            # shrinking and unrelated repairs remain available.
            r["status"] = "expired"
            self.store.put("requests", r["id"], t["n"], r)
            self.store.log("system", t["n"], "quota_expired", {"request": r["id"]}, "ok")

    def public_machine(self, m, ports):
        safe = {
            k: v
            for k, v in m.items()
            if k not in ("ssh_keys", "runcmd", "mac", "host", "tenant_n", "resize_from", "readiness_token")
        }
        reports = [r for r in self.store.objects("guest_reports", m["tenant_n"]) if r["vmid"] == m["vmid"]]
        report = reports[0] if reports else {}
        if m["kind"] == "ct" and m.get("state") == "ready":
            report = {**report, "initialization_status": "complete", "application_status": "not_checked"}
        safe["readiness"] = {
            "ssh_ready": m.get("ssh_ready", False),
            "initialization_status": report.get("initialization_status", "unknown"),
            "application_status": report.get("application_status", "not_checked"),
            "checks": report.get("checks", []),
            "reported_at": report.get("reported_at"),
            "private_interfaces": report.get("interfaces", []),
            "failed_step": report.get("failed_step"),
        }
        safe["access"] = {
            "inbound": m.get("network_access", "tenant"),
            "private_nics": "not_allowed"
            if m.get("network_access") == "restricted"
            else "unfiltered_experiment_networks",
            "allowed_connections": [
                {
                    "from": p.get("from_machine", p["source"]),
                    "port": p["port"],
                    "protocol": p.get("proto", "tcp"),
                }
                for p in self.store.objects("peers", m["tenant_n"])
                if p.get("target") == m["ip"]
            ],
        }
        ssh = next(
            (p for p in ports if p["vmid"] == m["vmid"] and p["port"] == 22 and p["proto"] == "tcp"), None
        )
        if ssh:
            user = "user" if m["kind"] == "vm" else "root"
            safe["ssh"] = f"ssh -p {ssh['public_port']} {user}@carrel.winlab.tw"
            safe["ssh_config"] = (
                f"Host {m['name']}-carrel\n  HostName carrel.winlab.tw\n  User {user}\n  Port {ssh['public_port']}\n"
            )
        return safe

    async def execute(self, tool, args, who):
        try:
            if self.config.get("background_operations") and tool in ASYNC_TOOLS and not args.get("dry_run"):
                if tool in ADMIN_TOOLS:
                    if not who["admin"]:
                        fail("forbidden", "winlab-admin membership required")
                    t = next((t for t in self.store.tenants() if t["slug"] == args.get("tenant")), None)
                    if not t and tool == "tenant_suspend":
                        fail("not_found", "Tenant not found")
                    if not t:
                        await self.register_tenants(who)
                        t = self.tenant(who)
                else:
                    await self.register_tenants(who, args.get("tenant"))
                    t = self.tenant(who, args.get("tenant"))
                if t["status"] != "active" and tool != "tenant_suspend":
                    fail("forbidden", "Tenant is suspended")
                result = self.operations.submit(tool, args, who, t, args.get("idempotency_key"))
                if tool == "tenant_suspend":
                    self.store.db.execute(
                        "UPDATE tenants SET status='suspending' WHERE n=? AND status='active'", (t["n"],)
                    )
                self.store.log(who["sub"], t["n"], tool, args, "queued")
                return {"ok": True, **result}
        except Failure as e:
            return e.result

        async def dispatch():
            tenant_n = None
            try:
                result, tenant_n = await self._execute(tool, args, who)
                self.store.log(who["sub"], tenant_n, tool, args, "ok")
                return {"ok": True, **result}
            except Failure as e:
                self.store.log(who["sub"], tenant_n, tool, args, e.result["error"]["code"])
                return e.result
            except (RuntimeError, httpx.HTTPError) as e:
                self.store.log(who["sub"], tenant_n, tool, args, "conflict")
                return {"ok": False, "error": {"code": "conflict", "message": str(e)[:200]}}

        if not args.get("dry_run") and tool in (MUTATIONS | ADMIN_MUTATIONS) - {"operation_retry"}:
            async with self.lock:
                return await dispatch()
        return await dispatch()

    async def _execute(self, tool, a, who):
        dry = a.get("dry_run", False)
        if tool == "catalog_get":
            return {"images": IMAGES, "sizes": SIZES, "units": UNITS, "capabilities": CAPABILITIES}, None
        if tool == "images_list":
            return {"images": [i for i in IMAGES if not a.get("kind") or i["kind"] == a["kind"]]}, None
        if tool == "sizes_list":
            return {"sizes": SIZES, "units": UNITS}, None
        if tool == "capacity_get":
            return {"capacity": await self.capacity()}, None
        if tool in ADMIN_TOOLS:
            if not who["admin"]:
                fail("forbidden", "winlab-admin membership required")
            # Admin requests may identify their tenant indirectly by request ID.
            target = a.get("tenant")
            if tool in ("request_approve", "request_reject"):
                r = next((r for r in self.store.objects("requests") if r["id"] == a["id"]), None)
                t = next((t for t in self.store.tenants() if r and t["n"] == r["tenant_n"]), None)
            else:
                t = next((t for t in self.store.tenants() if t["slug"] == target), None)
            before = self.quota(t) if t else None
            result = await self.admin(tool, a, who)
            if before is not None and tool in ADMIN_MUTATIONS:
                result = self.mutation_result(before, result, dry)
            elif tool == "reconcile_run" and dry:
                result.update(state="planned", reserved=False, resource_changes=False)
            return result, t["n"] if t else None
        onboarding = await self.register_tenants(who, a.get("tenant"), overview=tool == "whoami")
        if tool == "whoami":
            return {
                "username": who["username"],
                "admin": who["admin"],
                "default_tenant": (self.store.tenant("user:" + who["sub"]) or {}).get("slug"),
                "onboarding": onboarding,
                "tenants": [
                    {
                        "slug": t["slug"],
                        "kind": "personal" if s.startswith("user:") else "project",
                        "status": t["status"],
                        "quota": self.quota(t),
                    }
                    for s, _ in self.subjects(who)
                    if (t := self.store.tenant(s))
                ],
                "capabilities": CAPABILITIES,
            }, None
        t = self.tenant(who, a.get("tenant"))
        if tool in MUTATIONS | {"deployment_plan"} and t["status"] != "active":
            fail("forbidden", "Tenant is suspended")
        before = self.quota(t)
        result, tenant_n = await self.member(tool, a, who, t)
        if tool in MUTATIONS:
            result = self.mutation_result(before, result, dry)
        return result, tenant_n

    async def member(self, tool, a, who, t):
        dry, n = a.get("dry_run", False), t["n"]
        if tool == "operation_get":
            if a.get("id"):
                self.operations.find(t, a["id"])
                task = self.operations.tasks.get(a["id"])
                if task and a.get("wait_seconds", 20):
                    await asyncio.wait({task}, timeout=a.get("wait_seconds", 20))
            ops = (
                [self.operations.find(t, a["id"])]
                if a.get("id")
                else sorted(self.store.objects("operations", n), key=lambda o: o["created_at"], reverse=True)[
                    :50
                ]
            )
            return {"operations": [self.operations.public(o) for o in ops]}, n
        if tool == "operation_retry":
            if dry:
                return {"operation": self.operations.public(self.operations.find(t, a["id"]))}, n
            return self.operations.retry(t, a["id"], who), n
        if tool == "deployment_apply":
            if dry:
                return await self.deployment_plan(t, a), n
            return await self.deployment_apply(t, a, who), n
        if tool == "deployment_plan":
            return await self.deployment_plan(t, a), n
        if tool == "quota_get":
            return {"quota": self.quota(t), "snapshot_storage": self.snapshot_usage(t)}, n
        if tool == "audit_log":
            rows = self.store.db.execute(
                "SELECT * FROM audit WHERE tenant=? OR (tenant IS NULL AND actor=?) ORDER BY id DESC LIMIT 100",
                (n, who["sub"]),
            )
            return {"entries": [dict(r) for r in rows]}, n
        if tool == "ssh_key_list":
            return {"keys": self.store.objects("keys", n)}, n
        if tool == "ssh_key_add":
            validate_keys([a["key"]])
            import hashlib

            id = hashlib.sha256(a["key"].split()[1].encode()).hexdigest()[:16]
            if not dry:
                self.store.put("keys", f"{n}-{id}", n, {"id": id, "key": a["key"]})
            return {"id": id, "dry_run": dry, "quota_after": self.quota(t)}, n
        if tool == "ssh_key_remove":
            if not dry:
                self.store.remove("keys", f"{n}-{a['id']}")
            return {"dry_run": dry, "quota_after": self.quota(t)}, n
        if tool in ["machine_list", "machine_get"]:
            ms = (
                self.store.objects("machines", n)
                if tool == "machine_list"
                else [self.machine(t, a["machine"])]
            )
            out = []
            for m in ms:
                pub = self.public_machine(m, self.store.objects("ports", n))
                if tool == "machine_get":
                    pub["hypervisor"] = await self.backend.call({"op": "status", "machine": m})
                out.append(pub)
            return {"machines": out}, n
        if tool in ("machine_create", "machine_retry"):
            existing = next(
                (
                    m
                    for m in self.store.objects("machines", n)
                    if m["name"] == a.get("name")
                    and operation_id()
                    and m.get("operation_id") == operation_id()
                ),
                None,
            )
            if tool == "machine_retry" or existing:
                m = existing or self.machine(t, a["machine"])
                if (
                    m["state"] not in ("error", "needs_owner_fix", "provisioning", "initializing")
                    and not existing
                ):
                    fail("conflict", "Only an incomplete allocation can be retried")
                if not dry:
                    await self.provision(m)
                return {
                    "machine": self.public_machine(m, self.store.objects("ports", n)),
                    "quota_after": self.quota(t),
                }, n
            m = self.machine_spec(t, a, dry)
            after = self.quota(t, self.machine_delta(m))
            admission = await self.admission(m["cpu"], m["memory_mb"], m["disk_gb"])
            if dry:
                planned = self.planned_machine(m)
                return {
                    "machine": planned,
                    "quota_after": after,
                    "admission": admission,
                    "requirements": planned["requirements"],
                    "units": UNITS,
                    "connection": {"available_after": "create", "public_ssh": True},
                }, n
            with self.store.transaction():
                m, grant = self.allocate_machine(t, m)
            await self.provision(m)
            return {"machine": self.public_machine(m, [grant]), "quota_after": self.quota(t)}, n
        if tool in ["machine_power", "machine_delete", "machine_resize", "machine_metrics"]:
            m = self.machine(t, a["machine"])
            request = {"op": "action", "machine": m}
            delta = None
            if tool == "machine_metrics":
                return {"metrics": await self.backend.call({"op": "metrics", "machine": m})}, n
            if tool == "machine_delete":
                if a["confirm"] != m["name"]:
                    fail("invalid", "confirm must equal the machine name")
                request.update(action="delete", confirm=a["confirm"])
                delta = {k: -v for k, v in self.machine_delta(m).items()}
                for kind, dim in (
                    ("ports", "public_ports"),
                    ("domains", "domains"),
                    ("snapshots", "snapshots"),
                ):
                    owned = [x for x in self.store.objects(kind, n) if x["vmid"] == m["vmid"]]
                    delta[dim] = -len(owned)
                    if kind == "snapshots":
                        delta["snapshot_gb"] = -sum(x["disk_gb"] for x in owned)
            elif tool == "machine_power":
                request["action"] = a["action"]
                if a["action"] in ("start", "reboot"):
                    self.quota(t, {k: 0 for k in QUOTA_DIMENSIONS})
                # CPU/RAM remain reserved while stopped; starting adds no demand.
            else:
                spec = {k: a.get(k, m[k]) for k in ("cpu", "memory_mb", "disk_gb")}
                if spec["disk_gb"] < m["disk_gb"]:
                    fail("invalid", "Virtual disks cannot shrink")
                shrinking = any(spec[k] < m[k] for k in ("cpu", "memory_mb"))
                if shrinking and not dry:
                    status = await self.backend.call({"op": "status", "machine": m})
                    if status.get("status", status.get("state")) != "stopped":
                        fail("conflict", "Stop the machine before reducing CPU or RAM")
                delta = {
                    "vcpu": spec["cpu"] - m["cpu"],
                    "memory_mb": spec["memory_mb"] - m["memory_mb"],
                    "disk_gb": spec["disk_gb"] - m["disk_gb"],
                }
                self.quota(t, delta)
                if any(value > 0 for value in delta.values()):
                    await self.admission(0, 0, 0, proposed={**m, **spec})
                request.update(action="resize", **spec)
            if not dry:
                if tool == "machine_resize":
                    m.setdefault("resize_from", {k: m[k] for k in spec})
                    m.update({k: max(m[k], value) for k, value in spec.items()})
                    self.store.put("machines", m["vmid"], n, m)
                await self.backend.call(request)
                if tool == "machine_delete":
                    m["state"] = "deleting"
                    self.store.put("machines", m["vmid"], n, m)
                    # Hold IDs/quota until both node and edge have removed grants.
                    await self.reconcile()
                    with self.store.transaction():
                        for kind in ["ports", "domains", "snapshots", "guest_reports"]:
                            for obj in self.store.objects(kind, n):
                                if obj["vmid"] == m["vmid"]:
                                    self.store.remove(kind, obj.get("id", obj["vmid"]))
                        for peer in self.store.objects("peers"):
                            if peer["target"] == m["ip"] or peer["source"] == m["ip"] + "/32":
                                self.store.remove("peers", peer["id"])
                        self.store.remove("machines", m["vmid"])
                elif tool == "machine_resize":
                    m.update(spec)
                    m.pop("resize_from", None)
                    self.store.put("machines", m["vmid"], n, m)
                else:
                    m["state"] = "stopped" if a["action"] in ("stop", "shutdown") else "running"
                    m["power_state"] = m["state"]
                    m["ssh_ready"] = False
                    self.store.put("machines", m["vmid"], n, m)
            result = {"dry_run": dry, "quota_after": self.quota(t, delta if dry else None)}
            if tool == "machine_resize" and dry and shrinking:
                result["requirements"] = ["machine_stopped"]
                result["ready_to_apply"] = m.get("state") == "stopped"
            return result, n
        if tool.startswith("network_"):
            nets = self.store.objects("networks", n)
            if tool == "network_list":
                return {"networks": nets}, n
            if tool == "network_create":
                old = next((x for x in nets if x["name"] == a["name"]), None)
                if old and (not operation_id() or old.get("operation_id") != operation_id()):
                    fail("conflict", "Network name already exists")
                delta = {} if old else {"networks": 1}
                self.quota(t, delta)
                net = old or self.network_spec(t, a)
                if not dry:
                    self.store.put("networks", net["id"], n, net)
                    await self.reconcile()
                else:
                    net = {k: v for k, v in net.items() if k not in ("id", "serial", "tenant_n")}
                    net["state"] = "planned"
            else:
                net = next((v for v in nets if v["name"] == a["network"] or v["id"] == a["network"]), None)
                if not net:
                    fail("not_found", "Network not found")
                delta = {"networks": -1}
                if a["confirm"] != net["name"]:
                    fail("invalid", "confirm must equal the network name")
                if any(
                    nic["network"] == net["id"]
                    for m in self.store.objects("machines", n)
                    for nic in m["nics"]
                ):
                    fail("conflict", "Network still has attached NICs")
                if not dry:
                    net["state"] = "deleting"
                    self.store.put("networks", net["id"], n, net)
                    await self.reconcile()
                    self.store.remove("networks", net["id"])
            return {"network": net, "dry_run": dry, "quota_after": self.quota(t, delta if dry else None)}, n
        if tool in ["machine_nic_attach", "machine_nic_detach"]:
            m = self.machine(t, a["machine"])
            if tool == "machine_nic_attach":
                net = next(
                    (v for v in self.store.objects("networks", n) if a["network"] in (v["id"], v["name"])),
                    None,
                )
                if not net:
                    fail("not_found", "Network not found in this tenant")
                existing = next((nic for nic in m["nics"] if nic["network"] == net["id"]), None)
                if existing and (not operation_id() or existing.get("operation_id") != operation_id()):
                    fail("conflict", "Machine already attached to this network")
                i = (
                    existing["index"]
                    if existing
                    else next((i for i in range(1, 8) if i not in {v["index"] for v in m["nics"]}), None)
                )
                if i is None:
                    fail("quota_exceeded", "Machine already has 8 NICs")
                nic = existing or self.nic_spec(m, net, i)
                req = {"action": "nic_attach", "index": i, "serial": net["serial"], "nic": nic}
                nics = m["nics"] if existing else [*m["nics"], nic]
            else:
                i = a["nic"]
                if i == 0 or i not in {v["index"] for v in m["nics"]}:
                    if operation_id() and i != 0:
                        await self.reconcile()
                        return {"nics": m["nics"], "quota_after": self.quota(t)}, n
                    fail("invalid", "Only attached private NICs can be detached")
                req = {"action": "nic_detach", "index": i}
                nics = [v for v in m["nics"] if v["index"] != i]
            if not dry:
                if tool == "machine_nic_attach":
                    m["nics"] = nics
                    self.store.put("machines", m["vmid"], n, m)
                    await self.reconcile()
                await self.backend.call({"op": "action", "machine": m, **req})
                m["nics"] = nics
                if tool == "machine_nic_attach" and nic.get("ip") and m["kind"] == "vm":
                    m["state"] = "initializing"
                self.store.put("machines", m["vmid"], n, m)
                if tool == "machine_nic_detach":
                    await self.reconcile()
            result = {"nics": nics, "dry_run": dry, "quota_after": self.quota(t)}
            if not dry:
                result["machine"] = self.public_machine(m, self.store.objects("ports", n))
            return result, n
        if tool.startswith("port_"):
            ports = self.store.objects("ports", n)
            if tool == "port_list":
                return {"ports": ports}, n
            if tool == "port_open":
                m = self.machine(t, a["machine"])
                existing = next(
                    (
                        p
                        for p in ports
                        if p["vmid"] == m["vmid"] and p["port"] == a["port"] and p["proto"] == a["proto"]
                    ),
                    None,
                )
                if existing:
                    if not dry:
                        await self.reconcile()
                    return {"port": existing, "quota_after": self.quota(t)}, n
                delta = {"public_ports": 1}
                self.quota(t, delta)
                public = self.allocate_port(t)
                grant = {
                    "id": f"{n}-{public}-{a['proto']}",
                    "tenant_n": n,
                    "vmid": m["vmid"],
                    "ip": m["ip"],
                    "public_port": public,
                    "port": a["port"],
                    "proto": a["proto"],
                }
                if not dry:
                    self.store.put("ports", grant["id"], n, grant)
                    await self.reconcile()
                else:
                    grant = {"machine": m["name"], "port": a["port"], "proto": a["proto"], "state": "planned"}
            else:
                grant = next((p for p in ports if p["id"] == a["id"]), None)
                if not grant:
                    fail("not_found", "Port grant not found")
                delta = {"public_ports": -1}
                if not dry:
                    grant["state"] = "deleting"
                    self.store.put("ports", grant["id"], n, grant)
                    await self.reconcile()
                    self.store.remove("ports", grant["id"])
            return {"port": grant, "dry_run": dry, "quota_after": self.quota(t, delta if dry else None)}, n
        if tool.startswith("domain_"):
            domains = self.store.objects("domains", n)
            if tool == "domain_list":
                return {"domains": domains}, n
            if tool == "domain_add":
                m = self.machine(t, a["machine"])
                name = a["sub"] + "." + t["slug"] + ".winlab.tw"
                old = next((d for d in domains if d["name"] == name), None)
                if old and (old["vmid"] != m["vmid"] or old["target_port"] != a["target_port"]):
                    fail("conflict", "Domain already targets a different service; remove it explicitly first")
                delta = {"domains": 0 if old else 1}
                if not old:
                    self.quota(t, {"domains": 1})
                domain = old or {
                    "id": old["id"] if old else secrets.token_hex(8),
                    "tenant_n": n,
                    "vmid": m["vmid"],
                    "sub": a["sub"],
                    "slug": t["slug"],
                    "name": name,
                    "target_port": a["target_port"],
                    "state": "queued",
                    "ready_at": int(time.time()),
                }
                if not dry:
                    context = current_operation.get()
                    if context and context["record"]["tool"] == "domain_add":
                        op = context["record"]
                        identity = [domain["id"], old.get("operation_id") if old else operation_id()]
                        if op.get("domain_target", identity) != identity:
                            fail("conflict", "Domain was replaced; retry refused")
                        op["domain_target"] = identity
                        self.operations.save(op)
                    # Check retry ownership before saving or touching DNS.
                    self.store.put("domains", domain["id"], n, domain)
                    if domain["state"] not in ("ready", "configuring"):
                        if domain.get("ready_at", 0) > time.time():
                            raise Waiting("waiting_for_certificate", domain["ready_at"])
                        domain.update(await self.domains.ensure(t))
                        if domain["state"] == "ready":
                            domain["state"] = "configuring"
                    self.store.put("domains", domain["id"], n, domain)
                    if domain["state"] not in ("ready", "configuring"):
                        raise Waiting("waiting_for_certificate", domain["ready_at"])
                    await self.domains.record(t)
                    await self.reconcile()
                    domain["state"] = "ready"
                    self.store.put("domains", domain["id"], n, domain)
                else:
                    domain = {
                        "name": name,
                        "machine": m["name"],
                        "target_port": a["target_port"],
                        "state": "planned",
                    }
            else:
                domain = next((d for d in domains if d["name"] == a["name"]), None)
                if not domain:
                    fail("not_found", "Domain not found in this tenant")
                delta = {"domains": -1}
                if not dry:
                    domain["state"] = "deleting"
                    self.store.put("domains", domain["id"], n, domain)
                    await self.reconcile()
                    if not any(d["id"] != domain["id"] and d.get("state") != "deleting" for d in domains):
                        await self.domains.record(t, remove=True)
                    self.store.remove("domains", domain["id"])
            return {"domain": domain, "dry_run": dry, "quota_after": self.quota(t, delta if dry else None)}, n
        if tool.startswith("peer_"):
            if tool == "peer_list":
                return {"peers": self.store.objects("peers", n)}, n
            if tool == "peer_allow":
                m = self.machine(t, a["machine"])
                source = next((x for x in self.store.tenants() if x["slug"] == a["from_tenant"]), None)
                if not source or source["status"] != "active":
                    fail("not_found", "Source tenant not found")
                src = f"10.200.{source['n']}.0/24"
                if a.get("from_machine"):
                    src = self.machine(source, a["from_machine"])["ip"] + "/32"
                old = next(
                    (
                        p
                        for p in self.store.objects("peers", n)
                        if p["source"] == src
                        and p["target"] == m["ip"]
                        and p["port"] == a["port"]
                        and p.get("proto", "tcp") == "tcp"
                    ),
                    None,
                )
                grant = old or {
                    "id": secrets.token_hex(8),
                    "tenant_n": n,
                    "source": src,
                    "target": m["ip"],
                    "port": a["port"],
                    "proto": "tcp",
                }
                if not dry:
                    self.store.put("peers", grant["id"], n, grant)
                    await self.reconcile()
                else:
                    grant = {k: v for k, v in grant.items() if k not in ("id", "tenant_n")}
            else:
                grant = next((p for p in self.store.objects("peers", n) if p["id"] == a["id"]), None)
                if not grant:
                    fail("not_found", "Peer grant not found")
                if not dry:
                    grant["state"] = "deleting"
                    self.store.put("peers", grant["id"], n, grant)
                    await self.reconcile()
                    self.store.remove("peers", grant["id"])
            return {"peer": grant, "dry_run": dry, "quota_after": self.quota(t)}, n
        if tool.startswith("snapshot_"):
            m = self.machine(t, a["machine"])
            if m.get("resize_from") and tool in ("snapshot_create", "snapshot_rollback"):
                fail("conflict", "Finish the pending machine_resize before snapshot operations")
            snapshots = [s for s in self.store.objects("snapshots", n) if s["vmid"] == m["vmid"]]
            if tool == "snapshot_list":
                return {"snapshots": snapshots, "snapshot_storage": self.snapshot_usage(t)}, n
            id = f"{m['vmid']}-{a['name']}"
            snap = next((s for s in snapshots if s["name"] == a["name"]), None)
            delta = None
            if tool == "snapshot_create":
                if snap and (not operation_id() or snap.get("operation_id") != operation_id()):
                    fail("conflict", "Snapshot exists")
                delta = {} if snap else {"snapshots": 1, "snapshot_gb": m["disk_gb"]}
                self.quota(t, delta)
                if not snap:
                    await self.admission(0, 0, m["disk_gb"], snapshot=True)
                snap = snap or {
                    "id": id,
                    "vmid": m["vmid"],
                    "name": a["name"],
                    "disk_gb": m["disk_gb"],
                    "configuration": {k: m[k] for k in ("cpu", "memory_mb", "disk_gb", "nics")},
                }
            elif not snap:
                fail("not_found", "Snapshot not found")
            elif tool == "snapshot_delete":
                delta = {"snapshots": -1, "snapshot_gb": -snap["disk_gb"]}
            if tool == "snapshot_rollback" and snap.get("configuration") != {
                k: m[k] for k in ("cpu", "memory_mb", "disk_gb", "nics")
            }:
                fail(
                    "conflict", "Resources or NICs changed since this snapshot; administrator review required"
                )
            if tool == "snapshot_rollback" and a["confirm"] != a["name"]:
                fail("invalid", "confirm must equal snapshot name")
            effects = {}
            if tool == "snapshot_rollback":
                effects = {"power_state": "restored_to_previous", "downtime_expected": True}
            if not dry:
                if tool == "snapshot_rollback":
                    context = current_operation.get()
                    record = context["record"] if context else {}
                    restore = record.get("rollback_restore")
                    if restore is None:
                        status = await self.backend.call({"op": "status", "machine": m})
                        reports = [
                            r for r in self.store.objects("guest_reports", n) if r["vmid"] == m["vmid"]
                        ]
                        restore = {
                            "running": status.get("status") == "running",
                            "boot_id": reports[0].get("boot_id") if reports else None,
                        }
                        record["rollback_restore"] = restore
                        if context:
                            self.operations.save(record)
                if tool == "snapshot_create":
                    # Keep the disk reservation if the adapter or process dies
                    # after creating the hypervisor snapshot.
                    snap["state"] = "creating"
                    self.store.put("snapshots", id, n, snap)
                action_result = await self.backend.call(
                    {
                        "op": "action",
                        "machine": m,
                        "name": a["name"],
                        "action": {
                            "snapshot_create": "snapshot",
                            "snapshot_delete": "delsnapshot",
                            "snapshot_rollback": "rollback",
                        }[tool],
                    }
                )
                if tool == "snapshot_create":
                    snap["state"] = "ready"
                    self.store.put("snapshots", id, n, snap)
                elif tool == "snapshot_delete":
                    self.store.remove("snapshots", id)
                else:
                    state = action_result.get("state", action_result.get("status"))
                    if restore["running"]:
                        await self.backend.call({"op": "action", "machine": m, "action": "start"})
                        m["state"] = "initializing"
                        self.store.put("machines", m["vmid"], n, m)
                        await self.wait_ready(m, previous_boot=restore["boot_id"])
                        state = "running"
                    else:
                        m["state"] = "stopped"
                        m["ssh_ready"] = False
                        self.store.put("machines", m["vmid"], n, m)
                        state = "stopped"
                    effects = {"power_state": state, "power_state_restored": True}
                await self.refresh_storage_usage()
            if dry and tool == "snapshot_create":
                snap = {
                    "name": snap["name"],
                    "machine": m["name"],
                    "disk_gb": snap["disk_gb"],
                    "state": "planned",
                }
            return {
                "snapshot": snap,
                "snapshot_storage": self.snapshot_usage(t),
                "dry_run": dry,
                "quota_after": self.quota(t, delta if dry else None),
                **effects,
            }, n
        if tool == "quota_request":
            if a["dimension"] not in QUOTA_DIMENSIONS:
                fail("invalid", "Quota dimension is not available")
            if a.get("until"):
                try:
                    if datetime.fromisoformat(a["until"]).replace(tzinfo=UTC).timestamp() <= time.time():
                        fail("invalid", "Expiry must be in the future")
                except ValueError:
                    fail("invalid", "Use an ISO date for until")
            r = {
                "id": secrets.token_hex(8),
                "tenant_n": n,
                "kind": "quota",
                "status": "pending",
                "dimension": a["dimension"],
                "amount": a["amount"],
                "reason": a["reason"],
                "until": a.get("until"),
                "actor": who["sub"],
                "created_at": int(time.time()),
            }
            if not dry:
                self.store.put("requests", r["id"], n, r)
            else:
                r = {k: v for k, v in r.items() if k not in ("id", "tenant_n", "actor", "created_at")}
                r["status"] = "planned"
            return {"request": r, "dry_run": dry, "quota_after": self.quota(t)}, n
        if tool == "request_list":
            return {"requests": self.store.objects("requests", n)}, n
        fail("invalid", "Unknown tool")

    async def deployment_plan(self, t, a):
        """Plan against tenant-scoped symbolic objects; never persist or reserve them."""
        machines, networks, attachments = [], [], []
        existing_m = self.store.objects("machines", t["n"])
        existing_n = self.store.objects("networks", t["n"])
        simulated_n = list(existing_n)
        by_machine = {ref: m for m in existing_m for ref in (m["name"], str(m["vmid"]))}
        by_network = {ref: net for net in existing_n for ref in (net["name"], net["id"])}
        delta = {}
        for requested in a.get("machines", []):
            if requested["name"] in by_machine:
                fail("conflict", "Duplicate or existing machine name", name=requested["name"])
            m = self.machine_spec(t, requested, True)
            machines.append(m)
            by_machine[m["name"]] = m
            for key, value in self.machine_delta(m).items():
                delta[key] = delta.get(key, 0) + value
        for requested in a.get("networks", []):
            if requested["name"] in by_network:
                fail("conflict", "Duplicate or existing network name", name=requested["name"])
            net = self.network_spec(t, requested, simulated_n)
            simulated_n.append(net)
            networks.append(
                {k: v for k, v in net.items() if k not in ("id", "serial", "tenant_n")} | {"state": "planned"}
            )
            by_network[net["name"]] = net
        if networks:
            delta["networks"] = len(networks)
        if not any(a.get(k) for k in ("machines", "networks", "attachments", "connections", "publications")):
            fail("invalid", "Plan must contain machines, networks, connections or publications")
        if len(existing_m) + len(machines) > 100 or len(existing_n) + len(networks) > 99:
            fail("quota_exceeded", "Plan exceeds tenant address slots")
        if len(self.store.objects("ports", t["n"])) + len(machines) > 10:
            fail("quota_exceeded", "Public port block is full", dimension="public_ports")
        # These lists are deserialized copies, so simulating NIC assignment is local only.
        for requested in a.get("attachments", []):
            m = by_machine.get(requested["machine"])
            net = by_network.get(requested["network"])
            if not m or not net:
                fail("not_found", "Attachment must reference this tenant's existing or planned resources")
            if m.get("network_access") == "restricted":
                fail(
                    "invalid",
                    "Restricted machines use declared connections; experiment NICs require network_access=tenant",
                    machine=m["name"],
                )
            network_ref = net.get("id", net["name"])
            if any(nic["network"] == network_ref for nic in m["nics"]):
                fail("conflict", "Machine already attached to this network")
            index = next((i for i in range(1, 8) if i not in {nic["index"] for nic in m["nics"]}), None)
            if index is None:
                fail("quota_exceeded", "Machine already has 8 NICs")
            m["nics"].append({"index": index, "network": network_ref})
            attachments.append(
                {"machine": m["name"], "network": net["name"], "nic": index, "state": "planned"}
            )
        connections, publications, access_delta = self.plan_access(t, a, by_machine)
        for key, value in access_delta.items():
            delta[key] = delta.get(key, 0) + value
        if len(self.store.objects("ports", t["n"])) + delta.get("public_ports", 0) > 10:
            fail("quota_exceeded", "Public port block is full", dimension="public_ports")
        before, after = self.quota(t), self.quota(t, delta or None)
        admission = await self.admission(
            delta.get("vcpu", 0), delta.get("memory_mb", 0), delta.get("disk_gb", 0)
        )
        planned = [self.planned_machine(m) for m in machines]
        requirements = [{"machine": m["name"], "requirement": r} for m in planned for r in m["requirements"]]
        return self.mutation_result(
            before,
            {
                "machines": planned,
                "networks": networks,
                "attachments": attachments,
                "connections": connections,
                "publications": publications,
                "quota_after": after,
                "admission": admission,
                "requirements": requirements,
                "units": UNITS,
                "apply_tool": "deployment_apply",
                "apply_order": [
                    "reserve_all",
                    "network_create",
                    "machine_create",
                    "machine_nic_attach",
                    "readiness_checks",
                ],
                "limitations": [
                    "No IDs, addresses or ports are reserved; apply rechecks capacity and quota.",
                    "Guest boot, package commands and SSH connectivity are checked only after creation.",
                    "Managed networks configure private IPs automatically; raw_l2 requires owner configuration.",
                    "network_access=tenant allows all same-tenant primary traffic. Use restricted and connections for service isolation.",
                    "Publication success confirms routing and TLS configuration; end-to-end application responses require an external check.",
                ],
            },
            True,
        )

    def allocate_port(self, t):
        used = {p["public_port"] for p in self.store.objects("ports", t["n"])}
        base = 20000 + t["n"] * 10
        port = next((i for i in range(base, base + 10) if i not in used), None)
        if port is None:
            fail("quota_exceeded", "Public port block is full", dimension="public_ports")
        return port

    async def admin(self, tool, a, who):
        dry = a.get("dry_run", False)
        if tool == "tenant_list":
            return {"tenants": [{**t, "quota": self.quota(t)} for t in self.store.tenants()]}
        if tool == "node_list":
            return {"inventory": await self.backend.call({"op": "inventory"})}
        if tool == "usage_report":
            return {"tenants": [{"slug": t["slug"], "quota": self.quota(t)} for t in self.store.tenants()]}
        if tool == "reconcile_run":
            return {
                "dry_run": dry,
                "result": {k: len(v) for k, v in self.store.desired().items()}
                if dry
                else await self.reconcile(),
            }
        if tool == "request_list_all":
            return {"requests": self.store.objects("requests")}
        if tool in ["request_approve", "request_reject"]:
            r = next((r for r in self.store.objects("requests") if r["id"] == a["id"]), None)
            if not r:
                fail("not_found", "Request not found")
            if r["status"] != "pending":
                fail("conflict", "Request is already decided")
            t = next(t for t in self.store.tenants() if t["n"] == r["tenant_n"])
            if tool == "request_approve":
                if r["dimension"] not in QUOTA_DIMENSIONS:
                    fail("invalid", "Quota dimension is not available")
                hard = {"public_ports": 10, "networks": 99, "machines": 100, "ips": 100}
                if (
                    r["amount"] > hard.get(r["dimension"], 1000000)
                    or r["amount"] < t["quota"][r["dimension"]]
                ):
                    fail("invalid", "Requested limit must increase quota within the address plan")
                if any(
                    x["status"] == "approved" and x.get("until") and x["dimension"] == r["dimension"]
                    for x in self.store.objects("requests", t["n"])
                ):
                    fail("conflict", "An expiring grant already controls this dimension")
            if not dry:
                if tool == "request_approve":
                    r["previous_limit"] = t["quota"][r["dimension"]]
                    t["quota"][r["dimension"]] = r["amount"]
                    self.store.db.execute(
                        "UPDATE tenants SET quota=? WHERE n=?", (json.dumps(t["quota"]), t["n"])
                    )
                r.update(
                    status="approved" if tool == "request_approve" else "rejected", decided_by=who["sub"]
                )
                self.store.put("requests", r["id"], t["n"], r)
                self.store.log(who["sub"], t["n"], tool, a, "ok")
            else:
                if tool == "request_approve":
                    t["quota"][r["dimension"]] = r["amount"]
                r["status"] = "planned_approval" if tool == "request_approve" else "planned_rejection"
            return {"request": r, "dry_run": dry, "quota_after": self.quota(t)}
        t = next((t for t in self.store.tenants() if t["slug"] == a.get("tenant")), None)
        if not t:
            fail("not_found", "Tenant not found")
        if tool == "quota_set":
            if a["dimension"] not in QUOTA_DIMENSIONS:
                fail("invalid", "Quota dimension is not available")
            if any(
                x["status"] == "approved" and x.get("until") and x["dimension"] == a["dimension"]
                for x in self.store.objects("requests", t["n"])
            ):
                fail("conflict", "An expiring grant controls this dimension")
            limits = {**t["quota"], a["dimension"]: a["amount"]}
            if limits["public_ports"] > 10 or limits["networks"] > 99 or limits["machines"] > 100:
                fail("invalid", "Quota exceeds address plan")
            if limits[a["dimension"]] < self.usage(t)[a["dimension"]]:
                fail("conflict", "New limit is below existing allocations")
            if not dry:
                self.store.db.execute("UPDATE tenants SET quota=? WHERE n=?", (json.dumps(limits), t["n"]))
            t["quota"] = limits
        elif tool == "tenant_suspend":
            if not dry:
                for m in self.store.objects("machines", t["n"]):
                    await self.backend.call({"op": "action", "machine": m, "action": "stop"})
                    m.update(state="stopped", power_state="stopped", ssh_ready=False)
                    self.store.put("machines", m["vmid"], t["n"], m)
                self.store.db.execute("UPDATE tenants SET status='suspended' WHERE n=?", (t["n"],))
        self.store.log(who["sub"], t["n"], tool, a, "dry_run" if dry else "ok")
        return {"dry_run": dry, "quota_after": self.quota(t)}


ADMIN_MUTATIONS = {
    "deployment_apply",
    "operation_retry",
    "quota_set",
    "tenant_suspend",
    "request_approve",
    "request_reject",
    "reconcile_run",
}
ADMIN_TOOLS = {
    "tenant_list",
    "node_list",
    "usage_report",
    "reconcile_run",
    "quota_set",
    "tenant_suspend",
    "request_approve",
    "request_reject",
    "request_list_all",
}
MUTATIONS = {
    "deployment_apply",
    "operation_retry",
    "machine_create",
    "machine_retry",
    "machine_delete",
    "machine_power",
    "machine_resize",
    "network_create",
    "network_delete",
    "domain_add",
    "domain_remove",
    "machine_nic_attach",
    "machine_nic_detach",
    "port_open",
    "port_close",
    "peer_allow",
    "peer_revoke",
    "snapshot_create",
    "snapshot_delete",
    "snapshot_rollback",
    "quota_request",
    "ssh_key_add",
    "ssh_key_remove",
}
