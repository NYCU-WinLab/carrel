"""Tenant-scoped connectivity and publication specifications for deployment jobs."""

import secrets
import time

from .operations import operation_id


def fail(*args, **kwargs):
    from .platform import fail as failure

    failure(*args, **kwargs)


class Intent:
    def plan_access(self, t, a, machines):
        connections, publications = [], []
        seen = set()
        delta = {"public_ports": 0, "domains": 0}

        def machine(ref):
            m = machines.get(ref)
            if not m:
                fail(
                    "not_found",
                    "Connection or publication must reference a machine in this tenant",
                    machine=ref,
                )
            return m

        for request in a.get("connections", []):
            source, target = machine(request["from"]), machine(request["to"])
            if source["name"] == target["name"]:
                fail("invalid", "Connection source and destination must differ")
            if target.get("network_access", "tenant") != "restricted":
                fail(
                    "invalid",
                    "Use network_access=restricted on the destination to enforce declared connections",
                    machine=target["name"],
                )
            proto = request.get("protocol", "tcp")
            key = (source["name"], target["name"], request["port"], proto)
            if key in seen:
                fail("conflict", "Duplicate connection")
            seen.add(key)
            connections.append(
                {"from": source["name"], "to": target["name"], "port": request["port"], "protocol": proto}
            )

        seen.clear()
        for request in a.get("publications", []):
            m = machine(request["machine"])
            proto, port = request["protocol"], request["port"]
            pub = {"machine": m["name"], "protocol": proto, "port": port}
            if proto == "https":
                if not request.get("sub"):
                    fail("invalid", "HTTPS publication requires sub")
                name = request["sub"] + "." + t["slug"] + ".winlab.tw"
                key = ("https", name)
                old = next((d for d in self.store.objects("domains", t["n"]) if d["name"] == name), None)
                if old and (
                    old["vmid"] != m.get("vmid") or old["target_port"] != port or old["state"] != "ready"
                ):
                    fail("conflict", "Domain already belongs to another or incomplete publication", name=name)
                pub.update(sub=request["sub"], url="https://" + name, reused=bool(old))
                delta["domains"] += not old
            else:
                if request.get("sub"):
                    fail("invalid", "sub is only valid for HTTPS")
                key = (m["name"], proto, port)
                old = next(
                    (
                        p
                        for p in self.store.objects("ports", t["n"])
                        if p["vmid"] == m.get("vmid") and p["port"] == port and p["proto"] == proto
                    ),
                    None,
                )
                # Every new machine already reserves its SSH entry.
                reused = bool(old) or (not m.get("vmid") and proto == "tcp" and port == 22)
                pub["reused"] = reused
                delta["public_ports"] += not reused
            if key in seen:
                fail("conflict", "Duplicate publication")
            seen.add(key)
            publications.append(pub)
        return connections, publications, {k: v for k, v in delta.items() if v}

    def reserve_access(self, t, plan):
        created = {"ports": [], "domains": [], "peers": []}
        bindings = {}
        references = []

        def machine(name):
            m = self.machine(t, name)
            bindings[str(m["vmid"])] = [m.get("allocation_id"), m.get("created_at"), m.get("operation_id")]
            return m

        for c in plan["connections"]:
            source, target = machine(c["from"]), machine(c["to"])
            existing = next(
                (
                    p
                    for p in self.store.objects("peers", t["n"])
                    if p["source"] == source["ip"] + "/32"
                    and p["target"] == target["ip"]
                    and p["port"] == c["port"]
                    and p.get("proto", "tcp") == c["protocol"]
                ),
                None,
            )
            if existing:
                references.append(["peers", existing["id"], existing.get("operation_id")])
                continue
            id = secrets.token_hex(8)
            self.store.put(
                "peers",
                id,
                t["n"],
                {
                    "id": id,
                    "tenant_n": t["n"],
                    "source": source["ip"] + "/32",
                    "target": target["ip"],
                    "port": c["port"],
                    "proto": c["protocol"],
                    "from_machine": source["name"],
                    "machine": target["name"],
                },
            )
            created["peers"].append(id)
        for p in plan["publications"]:
            m = machine(p["machine"])
            if p["reused"]:
                kind = "domains" if p["protocol"] == "https" else "ports"
                existing = next(
                    g
                    for g in self.store.objects(kind, t["n"])
                    if g["vmid"] == m["vmid"]
                    and (
                        g["name"] == p["sub"] + "." + t["slug"] + ".winlab.tw"
                        if kind == "domains"
                        else g["port"] == p["port"] and g["proto"] == p["protocol"]
                    )
                )
                references.append([kind, existing["id"], existing.get("operation_id")])
                continue
            if p["protocol"] == "https":
                id = secrets.token_hex(8)
                self.store.put(
                    "domains",
                    id,
                    t["n"],
                    {
                        "id": id,
                        "tenant_n": t["n"],
                        "vmid": m["vmid"],
                        "slug": t["slug"],
                        "sub": p["sub"],
                        "name": p["sub"] + "." + t["slug"] + ".winlab.tw",
                        "target_port": p["port"],
                        "state": "queued",
                        "ready_at": int(time.time()),
                    },
                )
                created["domains"].append(id)
            else:
                port = self.allocate_port(t)
                id = f"{t['n']}-{port}-{p['protocol']}"
                self.store.put(
                    "ports",
                    id,
                    t["n"],
                    {
                        "id": id,
                        "tenant_n": t["n"],
                        "vmid": m["vmid"],
                        "ip": m["ip"],
                        "public_port": port,
                        "port": p["port"],
                        "proto": p["protocol"],
                    },
                )
                created["ports"].append(id)
        return created, bindings, references

    def check_bindings(self, t, deployment):
        for vmid, identity in deployment.get("bindings", {}).items():
            m = self.machine(t, vmid)
            if [m.get("allocation_id"), m.get("created_at"), m.get("operation_id")] != identity:
                fail("conflict", "A referenced machine was replaced; retry refused")
        for id, owner in deployment.get("network_bindings", {}).items():
            net = next((net for net in self.store.objects("networks", t["n"]) if net["id"] == id), None)
            if not net or net.get("operation_id") != owner:
                fail("conflict", "A referenced network was removed or replaced; retry refused")
        for kind, ids in deployment.get("grants", {}).items():
            for id in ids:
                obj = next((o for o in self.store.objects(kind, t["n"]) if o["id"] == id), None)
                if not obj or obj.get("operation_id") != operation_id():
                    fail("conflict", "A deployment grant was removed or replaced; retry refused")
        for kind, id, owner in deployment.get("references", []):
            obj = next((o for o in self.store.objects(kind, t["n"]) if o["id"] == id), None)
            if not obj or obj.get("operation_id") != owner:
                fail("conflict", "A reused permission or publication was removed or replaced; retry refused")

    def access_result(self, t, a):
        endpoints = []
        for p in a.get("publications", []):
            m = self.machine(t, p["machine"])
            if p["protocol"] == "https":
                name = p["sub"] + "." + t["slug"] + ".winlab.tw"
                d = next(d for d in self.store.objects("domains", t["n"]) if d["name"] == name)
                endpoints.append(
                    {
                        "machine": m["name"],
                        "url": "https://" + name,
                        "state": d["state"],
                        "verification": "routing_configured",
                    }
                )
            else:
                grant = next(
                    g
                    for g in self.store.objects("ports", t["n"])
                    if g["vmid"] == m["vmid"] and g["port"] == p["port"] and g["proto"] == p["protocol"]
                )
                endpoints.append(
                    {
                        "machine": m["name"],
                        "host": "carrel.winlab.tw",
                        "port": grant["public_port"],
                        "protocol": grant["proto"],
                        "verification": "routing_configured",
                    }
                )
        return {"connections": a.get("connections", []), "endpoints": endpoints}
