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
from .store import DEFAULT_QUOTA

QUOTA_DIMENSIONS = tuple(k for k in DEFAULT_QUOTA if k != "images_gb")
CAPABILITIES = {
    "deployment_planning": True,
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


class Platform:
    def __init__(self, store, backend, config):
        self.store, self.backend, self.config = store, backend, config
        self.lock = asyncio.Lock()
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

    async def register_tenants(self, who):
        # Identity has already passed Keycloak verification. Registration is
        # automatic on first use, serialized by execute's lock and idempotent.
        missing = [(s, name) for s, name in self.subjects(who) if not self.store.tenant(s)]
        if not missing:
            return
        reserved = await self.reserved()
        reserved.update(t["slug"] for t in self.store.tenants())
        registrations = []
        for subject, name in missing:
            name = slug(name)
            if name in reserved:
                fail("conflict", "Tenant slug is already owned; administrator alias required", slug=name)
            reserved.add(name)
            registrations.append((subject, name))
        for subject, name in registrations:
            t = self.store.register(subject, name)
            self.store.log(who["sub"], t["n"], "tenant_register", {}, "ok")

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
        used["disk_gb"] += sum(s["disk_gb"] for s in self.store.objects("snapshots", t["n"]))
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

    async def capacity(self, proposed=None):
        reservations = self.store.objects("machines")
        if proposed:
            reservations = [m for m in reservations if m["vmid"] != proposed["vmid"]] + [proposed]
        return summarize(await self.backend.call({"op": "inventory"}), reservations)

    async def admission(self, cpu, memory, disk, proposed=None):
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
        if (disk > 0 or proposed) and capacity["policy"]["storage_admission_blocked"]:
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
        if kind == "ct" and (a.get("nested_virt") or a.get("packages") or a.get("runcmd")):
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
            in ("name", "kind", "image", "cpu", "memory_mb", "disk_gb", "swap_mb", "nested_virt", "packages")
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
        for domain in self.store.objects("domains"):
            if domain["state"] == "queued" and domain.get("ready_at", 0) <= time.time():
                t = next(t for t in self.store.tenants() if t["n"] == domain["tenant_n"])
                domain.update(await self.domains.ensure(t))
                self.store.put("domains", domain["id"], t["n"], domain)
        state = self.store.desired()
        ready = {d["tenant_n"] for d in state["domains"] if d["state"] == "ready"}
        issued = {c["tenant_n"] for c in self.store.objects("certificates")}
        for tenant in state["tenants"]:
            if tenant["n"] in ready:
                await self.domains.record(tenant)
            elif tenant["n"] in issued and not any(d["tenant_n"] == tenant["n"] for d in state["domains"]):
                # Also recover a crash between deleting the final route and
                # deleting its owned wildcard DNS record.
                await self.domains.record(tenant, remove=True)
        state["certificates"] = self.domains.bundles(state["domains"])
        return await self.backend.reconcile(state)

    async def expire_grants(self):
        for r in self.store.objects("requests"):
            if r["status"] != "approved" or not r.get("until"):
                continue
            if datetime.fromisoformat(r["until"]).replace(tzinfo=UTC).timestamp() > time.time():
                continue
            t = next(t for t in self.store.tenants() if t["n"] == r["tenant_n"])
            t["quota"][r["dimension"]] = r["previous_limit"]
            self.store.db.execute("UPDATE tenants SET quota=? WHERE n=?", (json.dumps(t["quota"]), t["n"]))
            if self.usage(t)[r["dimension"]] > r["previous_limit"]:
                for m in self.store.objects("machines", t["n"]):
                    await self.backend.call({"op": "action", "machine": m, "action": "stop"})
                    m["state"] = "stopped"
                    self.store.put("machines", m["vmid"], t["n"], m)
            r["status"] = "expired"
            self.store.put("requests", r["id"], t["n"], r)
            self.store.log("system", t["n"], "quota_expired", {"request": r["id"]}, "ok")

    @staticmethod
    def public_machine(m, ports):
        safe = {
            k: v
            for k, v in m.items()
            if k not in ("ssh_keys", "runcmd", "mac", "host", "tenant_n", "resize_from")
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
        # All reservations and external mutations serialize across tenants. A
        # crash leaves a charged allocation, not reusable IDs or leaked quota.
        async with self.lock:
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
        await self.register_tenants(who)
        if tool == "whoami":
            return {
                "username": who["username"],
                "admin": who["admin"],
                "default_tenant": self.tenant(who)["slug"],
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
        if tool == "deployment_plan":
            return await self.deployment_plan(t, a), n
        if tool == "quota_get":
            return {"quota": self.quota(t)}, n
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
        if tool == "machine_retry":
            m = self.machine(t, a["machine"])
            if m["state"] not in ("error", "needs_owner_fix", "provisioning"):
                fail("conflict", "Only an incomplete allocation can be retried")
            if not dry:
                await self.reconcile()
                await self.backend.call({"op": "create", "machine": m})
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    try:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(m["ip"], 22), 3)
                        banner = await asyncio.wait_for(reader.readline(), 3)
                        writer.close()
                        await writer.wait_closed()
                        if banner.startswith(b"SSH-"):
                            m["state"] = "ready"
                            break
                    except (OSError, TimeoutError):
                        pass
                    await asyncio.sleep(2)
                else:
                    m["state"] = "needs_owner_fix"
                self.store.put("machines", m["vmid"], n, m)
            return {
                "machine": self.public_machine(m, self.store.objects("ports", n)),
                "dry_run": dry,
                "quota_after": self.quota(t),
            }, n
        if tool == "machine_create":
            m = self.machine_spec(t, a, dry)
            delta = self.machine_delta(m)
            after = self.quota(t, delta)
            admission = await self.admission(m["cpu"], m["memory_mb"], m["disk_gb"])
            used = {m["vmid"] for m in self.store.objects("machines", n)}
            i = next((i for i in range(100) if 10000 + n * 100 + i not in used), None)
            if i is None:
                fail("quota_exceeded", "No machine slots", dimension="machines")
            vmid = 10000 + n * 100 + i
            port = self.allocate_port(t)
            m.update(
                {
                    "vmid": vmid,
                    "tenant_n": n,
                    "ip": f"10.200.{n}.{10 + i}",
                    "host": 10 + i,
                    "mac": f"02:ca:{n:02x}:{i:02x}:00:01",
                    "state": "provisioning",
                    "created_at": int(time.time()),
                    "nics": [],
                }
            )
            grant = {
                "id": f"{n}-{port}-tcp",
                "tenant_n": n,
                "vmid": vmid,
                "ip": m["ip"],
                "public_port": port,
                "port": 22,
                "proto": "tcp",
            }
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
            self.store.put("machines", vmid, n, m)
            self.store.put("ports", grant["id"], n, grant)
            try:
                await self.reconcile()
                await self.backend.call({"op": "create", "machine": m})
                # A TCP banner is the only guest probe; no administrator login.
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    try:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(m["ip"], 22), 3)
                        banner = await asyncio.wait_for(reader.readline(), 3)
                        writer.close()
                        await writer.wait_closed()
                        if banner.startswith(b"SSH-"):
                            m["state"] = "ready"
                            break
                    except (OSError, TimeoutError):
                        pass
                    await asyncio.sleep(2)
                else:
                    m["state"] = "needs_owner_fix"
                    m["reason"] = "SSH did not become ready within 5 minutes"
            except Exception:
                m["state"] = "error"
                self.store.put("machines", vmid, n, m)
                raise
            self.store.put("machines", vmid, n, m)
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
                        delta["disk_gb"] -= sum(x["disk_gb"] for x in owned)
            elif tool == "machine_power":
                request["action"] = a["action"]
                if a["action"] in ("start", "reboot"):
                    self.quota(t, {})
                if a["action"] == "start":
                    await self.admission(0, 0, 0, proposed={**m, "state": "provisioning"})
            else:
                spec = {k: a.get(k, m[k]) for k in ("cpu", "memory_mb", "disk_gb")}
                if any(spec[k] < m[k] for k in spec):
                    fail("invalid", "Resize only grows resources")
                delta = {
                    "vcpu": spec["cpu"] - m["cpu"],
                    "memory_mb": spec["memory_mb"] - m["memory_mb"],
                    "disk_gb": spec["disk_gb"] - m["disk_gb"],
                }
                self.quota(t, delta)
                await self.admission(0, 0, 0, proposed={**m, **spec})
                request.update(action="resize", **spec)
            if not dry:
                if tool == "machine_resize":
                    m.setdefault("resize_from", {k: m[k] for k in spec})
                    m.update(spec)
                    self.store.put("machines", m["vmid"], n, m)
                await self.backend.call(request)
                if tool == "machine_delete":
                    had_domains = bool(self.store.objects("domains", n))
                    for kind in ["ports", "domains", "snapshots"]:
                        for obj in self.store.objects(kind, n):
                            if obj["vmid"] == m["vmid"]:
                                self.store.remove(kind, obj["id"])
                    for peer in self.store.objects("peers"):
                        if peer["target"] == m["ip"] or peer["source"] == m["ip"] + "/32":
                            self.store.remove("peers", peer["id"])
                    self.store.remove("machines", m["vmid"])
                    await self.reconcile()
                    if had_domains and not self.store.objects("domains", n):
                        await self.domains.record(t, remove=True)
                elif tool == "machine_resize":
                    m.pop("resize_from", None)
                    self.store.put("machines", m["vmid"], n, m)
                else:
                    m["state"] = "stopped" if a["action"] in ("stop", "shutdown") else "running"
                    self.store.put("machines", m["vmid"], n, m)
            return {"dry_run": dry, "quota_after": self.quota(t, delta if dry else None)}, n
        if tool.startswith("network_"):
            nets = self.store.objects("networks", n)
            if tool == "network_list":
                return {"networks": nets}, n
            if tool == "network_create":
                if any(x["name"] == a["name"] for x in nets):
                    fail("conflict", "Network name already exists")
                delta = {"networks": 1}
                self.quota(t, delta)
                self.validate_network(a)
                k = next((k for k in range(1, 100) if k not in {v["serial"] for v in nets}), None)
                if k is None:
                    fail("quota_exceeded", "No network slots", dimension="networks")
                net = {
                    "id": f"p{n:03d}{k:02d}",
                    "tenant_n": n,
                    "serial": k,
                    "name": a["name"],
                    "cidr": a.get("cidr"),
                    "mtu": 1450,
                }
                if not dry:
                    self.store.put("networks", net["id"], n, net)
                    await self.reconcile()
                else:
                    net = {"name": net["name"], "cidr": net["cidr"], "mtu": 1450, "state": "planned"}
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
                    self.store.remove("networks", net["id"])
                    await self.reconcile()
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
                if any(nic["network"] == net["id"] for nic in m["nics"]):
                    fail("conflict", "Machine already attached to this network")
                i = next((i for i in range(1, 8) if i not in {v["index"] for v in m["nics"]}), None)
                if i is None:
                    fail("quota_exceeded", "Machine already has 8 NICs")
                req = {"action": "nic_attach", "index": i, "serial": net["serial"]}
                nics = [*m["nics"], {"index": i, "network": net["id"]}]
            else:
                i = a["nic"]
                if i == 0 or i not in {v["index"] for v in m["nics"]}:
                    fail("invalid", "Only attached private NICs can be detached")
                req = {"action": "nic_detach", "index": i}
                nics = [v for v in m["nics"] if v["index"] != i]
            if not dry:
                await self.backend.call({"op": "action", "machine": m, **req})
                m["nics"] = nics
                self.store.put("machines", m["vmid"], n, m)
            return {"nics": nics, "dry_run": dry, "quota_after": self.quota(t)}, n
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
                    self.store.remove("ports", grant["id"])
                    await self.reconcile()
            return {"port": grant, "dry_run": dry, "quota_after": self.quota(t, delta if dry else None)}, n
        if tool.startswith("domain_"):
            domains = self.store.objects("domains", n)
            if tool == "domain_list":
                return {"domains": domains}, n
            if tool == "domain_add":
                m = self.machine(t, a["machine"])
                name = a["sub"] + "." + t["slug"] + ".winlab.tw"
                old = next((d for d in domains if d["name"] == name), None)
                delta = {"domains": 0 if old else 1}
                if not old:
                    self.quota(t, {"domains": 1})
                domain = {
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
                    # Persist first; a crash cannot leave an unowned DNS record.
                    self.store.put("domains", domain["id"], n, domain)
                    domain.update(await self.domains.ensure(t))
                    self.store.put("domains", domain["id"], n, domain)
                    await self.reconcile()
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
                    self.store.remove("domains", domain["id"])
                    await self.reconcile()
                    if not self.store.objects("domains", n):
                        await self.domains.record(t, remove=True)
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
                grant = {
                    "id": secrets.token_hex(8),
                    "tenant_n": n,
                    "source": src,
                    "target": m["ip"],
                    "port": a["port"],
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
                    self.store.remove("peers", grant["id"])
                    await self.reconcile()
            return {"peer": grant, "dry_run": dry, "quota_after": self.quota(t)}, n
        if tool.startswith("snapshot_"):
            m = self.machine(t, a["machine"])
            if m.get("resize_from") and tool in ("snapshot_create", "snapshot_rollback"):
                fail("conflict", "Finish the pending machine_resize before snapshot operations")
            snapshots = [s for s in self.store.objects("snapshots", n) if s["vmid"] == m["vmid"]]
            if tool == "snapshot_list":
                return {"snapshots": snapshots}, n
            id = f"{m['vmid']}-{a['name']}"
            snap = next((s for s in snapshots if s["name"] == a["name"]), None)
            delta = None
            if tool == "snapshot_create":
                if snap:
                    fail("conflict", "Snapshot exists")
                delta = {"snapshots": 1, "disk_gb": m["disk_gb"]}
                self.quota(t, delta)
                snap = {
                    "id": id,
                    "vmid": m["vmid"],
                    "name": a["name"],
                    "disk_gb": m["disk_gb"],
                    "configuration": {k: m[k] for k in ("cpu", "memory_mb", "disk_gb", "nics")},
                }
            elif not snap:
                fail("not_found", "Snapshot not found")
            elif tool == "snapshot_delete":
                delta = {"snapshots": -1, "disk_gb": -snap["disk_gb"]}
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
                effects = {"power_state": "may_stop", "restart_tool": "machine_power"}
            if not dry:
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
                    # Disk-only rollback can leave a previously running VM stopped.
                    state = action_result.get("state", action_result.get("status"))
                    if state not in ("running", "stopped"):
                        fail("conflict", "Rollback completed but power state is unknown; use machine_get")
                    m["state"] = state
                    self.store.put("machines", m["vmid"], n, m)
                    effects = {"power_state": state}
                    if state == "stopped":
                        effects["next_action"] = {
                            "tool": "machine_power",
                            "arguments": {"tenant": t["slug"], "machine": m["name"], "action": "start"},
                        }
            if dry and tool == "snapshot_create":
                snap = {
                    "name": snap["name"],
                    "machine": m["name"],
                    "disk_gb": snap["disk_gb"],
                    "state": "planned",
                }
            return {
                "snapshot": snap,
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
            self.validate_network(requested)
            net = {"name": requested["name"], "cidr": requested.get("cidr"), "mtu": 1450, "state": "planned"}
            networks.append(net)
            by_network[net["name"]] = net
        if networks:
            delta["networks"] = len(networks)
        if not machines and not networks and not a.get("attachments"):
            fail("invalid", "Plan must contain a machine, network or attachment")
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
                "quota_after": after,
                "admission": admission,
                "requirements": requirements,
                "units": UNITS,
                "apply_order": ["network_create", "machine_create", "machine_nic_attach"],
                "limitations": [
                    "No IDs, addresses or ports are reserved; apply rechecks capacity and quota.",
                    "Guest boot, package commands and SSH connectivity are checked only after creation.",
                    "Private L2 NICs require guest IP configuration; no DHCP or gateway.",
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
                self.store.db.execute("UPDATE tenants SET status='suspended' WHERE n=?", (t["n"],))
        self.store.log(who["sub"], t["n"], tool, a, "dry_run" if dry else "ok")
        return {"dry_run": dry, "quota_after": self.quota(t)}


ADMIN_MUTATIONS = {"quota_set", "tenant_suspend", "request_approve", "request_reject", "reconcile_run"}
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
