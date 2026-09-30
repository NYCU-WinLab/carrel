"""Allocation, guest readiness and recoverable multi-resource deployments."""

import asyncio
import ipaddress
import secrets
import time

from .operations import current_operation, operation_id


def fail(*args, **kwargs):
    from .platform import fail as failure

    failure(*args, **kwargs)


class Lifecycle:
    def allocate_machine(self, t, spec):
        n = t["n"]
        used = {m["vmid"] for m in self.store.objects("machines", n)}
        slot = next((i for i in range(100) if 10000 + n * 100 + i not in used), None)
        if slot is None:
            fail("quota_exceeded", "No machine address slots remain")
        vmid, port = 10000 + n * 100 + slot, self.allocate_port(t)
        m = {
            **spec,
            "vmid": vmid,
            "tenant_n": n,
            "ip": f"10.200.{n}.{10 + slot}",
            "host": 10 + slot,
            "mac": f"02:ca:{n:02x}:{slot:02x}:00:01",
            "state": "provisioning",
            "created_at": int(time.time()),
            "allocation_id": secrets.token_hex(16),
            "nics": [],
            "operation_id": operation_id(),
        }
        grant = {
            "id": f"{n}-{port}-tcp",
            "tenant_n": n,
            "vmid": vmid,
            "ip": m["ip"],
            "public_port": port,
            "port": 22,
            "proto": "tcp",
        }
        self.store.put("machines", vmid, n, m)
        self.store.put("ports", grant["id"], n, grant)
        if current_operation.get():
            op = current_operation.get()["record"]
            op.update(reserved=True, resource_changes=True, phase="provisioning")
            self.operations.save(op)
        return m, grant

    def network_spec(self, t, a, existing=None):
        nets = self.store.objects("networks", t["n"]) if existing is None else existing
        serial = next((i for i in range(1, 100) if i not in {v["serial"] for v in nets}), None)
        if serial is None:
            fail("quota_exceeded", "No network slots remain")
        mode = a.get("mode", "managed")
        cidr = a.get("cidr")
        if mode == "managed":
            address = int(ipaddress.IPv4Address("10.64.0.0")) + ((t["n"] - 1) * 128 + serial - 1) * 128
            cidr = cidr or str(ipaddress.IPv4Network((address, 25)))
            try:
                subnet = ipaddress.IPv4Network(cidr)
            except ValueError:
                fail("invalid", "Invalid private network CIDR")
            ranges = [ipaddress.IPv4Network(v) for v in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
            if subnet.prefixlen not in (24, 25) or not any(subnet.subnet_of(r) for r in ranges):
                fail("invalid", "Managed private networks require an RFC1918 /24 or /25")
            forbidden = ["10.200.0.0/16", "10.254.0.0/16", "192.168.13.0/24", "172.31.255.0/24"]
            if any(subnet.overlaps(ipaddress.IPv4Network(x)) for x in forbidden):
                fail("invalid", "Private subnet overlaps infrastructure")
            if any(
                v.get("cidr")
                and v.get("mode") == "managed"
                and subnet.overlaps(ipaddress.IPv4Network(v["cidr"]))
                for v in nets
            ):
                fail("conflict", "Private subnet overlaps another managed network in this tenant")
        else:
            self.validate_network(a)
        return {
            "id": f"p{t['n']:03d}{serial:02d}",
            "tenant_n": t["n"],
            "serial": serial,
            "name": a["name"],
            "mode": mode,
            "cidr": cidr,
            "mtu": 1450,
            "gateway": None,
            "dhcp": mode == "managed",
        }

    def nic_spec(self, m, net, index):
        managed = net.get("mode") == "managed"
        if managed and m["kind"] == "vm" and not m.get("guest_management"):
            fail("conflict", "This older VM lacks automatic private networking; use raw_l2 or a new VM")
        slot = m["vmid"] - 10000 - m["tenant_n"] * 100
        nic = {
            "index": index,
            "network": net["id"],
            "mode": net.get("mode", "raw_l2"),
            "mac": f"02:{'cb' if managed else 'cc'}:{m['tenant_n']:02x}:{slot:02x}:{index:02x}:01",
            "mtu": 1450,
            "operation_id": operation_id(),
        }
        if managed:
            subnet = ipaddress.IPv4Network(net["cidr"])
            nic.update(ip=str(subnet.network_address + 10 + slot), prefix=subnet.prefixlen)
        return nic

    async def provision(self, m, *, reconciled=False):
        if current_operation.get():
            op = current_operation.get()["record"]
            op.update(phase="provisioning", current_resource=m["name"])
            self.operations.save(op)
        try:
            if not reconciled:
                await self.reconcile()
            await self.backend.call({"op": "create", "machine": m})
            m["state"] = "initializing"
            self.store.put("machines", m["vmid"], m["tenant_n"], m)
            if not operation_id():
                await self.wait_ready(m)
        except Exception:
            m["state"] = "error"
            self.store.put("machines", m["vmid"], m["tenant_n"], m)
            raise

    async def wait_ready(self, m, previous_boot=None):
        timeout = self.config.get("guest_ready_timeout", 900)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ssh = False
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(m["ip"], 22), 3)
                try:
                    ssh = (await asyncio.wait_for(reader.readline(), 3)).startswith(b"SSH-")
                finally:
                    writer.close()
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                pass
            reports = [
                r for r in self.store.objects("guest_reports", m["tenant_n"]) if r["vmid"] == m["vmid"]
            ]
            report = reports[0] if reports else {}
            current = report.get("reported_at", 0) > time.time() - 120 and (
                not previous_boot or report.get("boot_id") != previous_boot
            )
            init = report.get("initialization_status") if current else None
            app = report.get("application_status") if current else None
            if m["kind"] == "ct":
                init, app = "complete", "not_checked"
            m["ssh_ready"] = ssh
            if init == "failed" or app == "failed":
                m.update(
                    state="needs_owner_fix", reason="Guest initialization or an application check failed"
                )
                self.store.put("machines", m["vmid"], m["tenant_n"], m)
                fail(
                    "guest_not_ready",
                    m["reason"],
                    machine=m["name"],
                    initialization_status=init,
                    application_status=app,
                    checks=report.get("checks", []),
                    failed_step=report.get("failed_step"),
                )
            expected = {(nic["mac"], nic["ip"], 1450) for nic in m["nics"] if nic.get("ip")}
            reported = {(nic["mac"], nic["ip"], nic["mtu"]) for nic in report.get("interfaces", [])}
            network_ready = not expected or (current and expected <= reported) or m["kind"] == "ct"
            if ssh and init == "complete" and app in ("healthy", "not_checked") and network_ready:
                m.update(state="ready", power_state="running")
                m.pop("reason", None)
                self.store.put("machines", m["vmid"], m["tenant_n"], m)
                return
            self.store.put("machines", m["vmid"], m["tenant_n"], m)
            await asyncio.sleep(self.config.get("guest_poll_interval", 3))
        m.update(
            state="needs_owner_fix", reason="Timed out waiting for guest initialization and health checks"
        )
        self.store.put("machines", m["vmid"], m["tenant_n"], m)
        fail("guest_not_ready", m["reason"], machine=m["name"])

    def guest_report(self, body, source):
        m = next((m for m in self.store.objects("machines") if m["vmid"] == body.get("vmid")), None)
        if (
            not m
            or source != m["ip"]
            or not m.get("readiness_token")
            or not secrets.compare_digest(str(body.get("token", "")), m["readiness_token"])
        ):
            fail("forbidden", "Invalid guest report")
        init, app = body.get("initialization_status"), body.get("application_status")
        if init not in ("running", "complete", "failed") or app not in (
            "pending",
            "healthy",
            "failed",
            "not_checked",
        ):
            fail("invalid", "Invalid guest status")
        checks = body.get("checks", [])
        if not isinstance(checks, list) or len(checks) > 20:
            fail("invalid", "Invalid health checks")
        safe = [
            {"index": i, "status": c.get("status", "failed")}
            for i, c in enumerate(checks)
            if isinstance(c, dict) and c.get("status") in ("healthy", "failed")
        ]
        boot_id = str(body.get("boot_id", ""))
        if len(boot_id) != 36:
            fail("invalid", "Invalid boot ID")
        failed_step = body.get("failed_step")
        if failed_step is not None and (type(failed_step) is not int or not 0 <= failed_step < 100):
            fail("invalid", "Invalid failed step")
        interfaces = body.get("interfaces", [])
        if not isinstance(interfaces, list) or len(interfaces) > 7:
            fail("invalid", "Invalid guest interface report")
        interfaces = [
            {"mac": i["mac"], "ip": i["ip"], "mtu": i["mtu"]}
            for i in interfaces
            if isinstance(i, dict)
            and any(i.get("mac") == nic.get("mac") and i.get("ip") == nic.get("ip") for nic in m["nics"])
            and i.get("mtu") == 1450
        ]
        self.store.put(
            "guest_reports",
            m["vmid"],
            m["tenant_n"],
            {
                "vmid": m["vmid"],
                "initialization_status": init,
                "application_status": app,
                "checks": safe,
                "interfaces": interfaces,
                "failed_step": failed_step,
                "boot_id": boot_id,
                "reported_at": time.time(),
            },
        )

    async def deployment_apply(self, t, a, who):
        context = current_operation.get()
        if not context:
            fail("invalid", "Deployment apply requires the background operation worker")
        op = context["record"]
        if not op.get("deployment"):
            plan = await self.deployment_plan(t, a)
            if not plan["ready_to_apply"]:
                fail("invalid", "Deployment requires SSH public keys", requirements=plan["requirements"])
            # No await inside this transaction. All quota, IDs and NICs are
            # committed together before touching the hypervisor.
            with self.store.transaction():
                created_m, created_n, added_nics = [], [], []
                for requested in a.get("networks", []):
                    net = self.network_spec(t, requested)
                    self.store.put("networks", net["id"], t["n"], net)
                    created_n.append(net["id"])
                for requested in a.get("machines", []):
                    m, _ = self.allocate_machine(t, self.machine_spec(t, requested, False))
                    created_m.append(m["vmid"])
                for requested in a.get("attachments", []):
                    m = self.machine(t, requested["machine"])
                    net = next(
                        n
                        for n in self.store.objects("networks", t["n"])
                        if requested["network"] in (n["id"], n["name"])
                    )
                    index = next(i for i in range(1, 8) if i not in {n["index"] for n in m["nics"]})
                    nic = self.nic_spec(m, net, index)
                    m["nics"].append(nic)
                    self.store.put("machines", m["vmid"], t["n"], m)
                    added_nics.append({"vmid": m["vmid"], "index": index, "network": net["id"]})
                op["deployment"] = {"machines": created_m, "networks": created_n, "nics": added_nics}
                op.update(reserved=True, resource_changes=True, phase="resources_reserved")
                self.operations.save(op)
        await self.reconcile()
        deployment = op["deployment"]
        for vmid in deployment["machines"]:
            m = self.machine(t, str(vmid))
            await self.provision(m, reconciled=True)
        for attachment in deployment["nics"]:
            if attachment["vmid"] in deployment["machines"]:
                continue
            m = self.machine(t, str(attachment["vmid"]))
            nic = next(n for n in m["nics"] if n["index"] == attachment["index"])
            net = next(n for n in self.store.objects("networks", t["n"]) if n["id"] == nic["network"])
            await self.backend.call(
                {
                    "op": "action",
                    "action": "nic_attach",
                    "machine": m,
                    "index": nic["index"],
                    "serial": net["serial"],
                    "nic": nic,
                }
            )
            if nic.get("ip") and m["kind"] == "vm":
                m["state"] = "initializing"
                self.store.put("machines", m["vmid"], t["n"], m)
                await self.wait_ready(m)
        return {"deployment": deployment, "quota_after": self.quota(t)}

    async def cleanup_deployment(self, op, who):
        t = next(t for t in self.store.tenants() if t["n"] == op["tenant_n"])
        failures = []
        for m in self.store.objects("machines", t["n"]):
            if m.get("operation_id") == op["id"]:
                try:
                    await self.member("machine_delete", {"machine": m["name"], "confirm": m["name"]}, who, t)
                except Exception:  # noqa: BLE001 - leave failed deletions charged and report each residue
                    failures.append({"kind": "machine", "name": m["name"]})
            else:
                for nic in list(m["nics"]):
                    if nic.get("operation_id") == op["id"]:
                        try:
                            await self.member(
                                "machine_nic_detach", {"machine": m["name"], "nic": nic["index"]}, who, t
                            )
                        except Exception:  # noqa: BLE001 - continue cleanup of independent resources
                            failures.append({"kind": "nic", "machine": m["name"], "nic": nic["index"]})
        for net in self.store.objects("networks", t["n"]):
            if net.get("operation_id") == op["id"]:
                try:
                    await self.member(
                        "network_delete", {"network": net["id"], "confirm": net["name"]}, who, t
                    )
                except Exception:  # noqa: BLE001 - retain network for an explicit cleanup retry
                    failures.append({"kind": "network", "name": net["name"]})
        return failures
