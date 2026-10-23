package carrel

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (p *Platform) Execute(ctx context.Context, tool string, a, w D) (result D) {
	e := p.execution(ctx)
	defer func() {
		if r := recover(); r != nil {
			result = failureResult(r)
			_ = attempt(func() { e.S.Log(str(w["sub"]), nil, tool, a, str(obj(result["error"])["code"])) })
		}
	}()
	validateBootstrapArguments(tool, a)
	if named("async_tools", tool) && !boolean(a["dry_run"]) {
		var t D
		if named("admin_tools", tool) {
			if !boolean(w["admin"]) {
				fail("forbidden", "winlab-admin membership required")
			}
			t = find(e.S.Tenants(), func(t D) bool { return t["slug"] == a["tenant"] })
			if t == nil && (tool == "tenant_suspend" || tool == "machine_migrate") {
				fail("not_found", "Tenant not found")
			}
			if t == nil {
				e.Register(w, "", false)
				t = e.Tenant(w, "")
			}
		} else {
			e.Register(w, str(a["tenant"]), false)
			t = e.Tenant(w, str(a["tenant"]))
		}
		if t["status"] != "active" && tool != "tenant_suspend" {
			fail("forbidden", "Tenant is suspended")
		}
		p.writer.Lock()
		var op D
		err := attempt(func() {
			op = p.Operations.Submit(tool, a, w, t)
			if tool == "tenant_suspend" {
				e.S.Exec("UPDATE tenants SET status='suspending' WHERE n=? AND status='active'", t["n"])
			}
			e.S.Log(str(w["sub"]), t["n"], tool, a, "queued")
		})
		p.writer.Unlock()
		if err != nil {
			panic(err)
		}
		if !named("admin_tools", tool) || tool == "machine_migrate" {
			op = p.Operations.Wait(ctx, t, str(op["id"]), intAt(a, "wait_seconds", 55))
		}
		return D{"ok": true, "operation": op}
	}
	if named("mutations", tool) && !boolean(a["dry_run"]) && tool != "operation_retry" {
		p.writer.Lock()
		defer p.writer.Unlock()
	}
	r, n := e.Dispatch(tool, a, w)
	e.S.Log(str(w["sub"]), n, tool, a, "ok")
	return merge(D{"ok": true}, r)
}
func (e *Execution) Dispatch(tool string, a, w D) (D, any) {
	dry := boolean(a["dry_run"])
	switch tool {
	case "catalog_get":
		return D{"service": D{"name": "carrel", "version": Version}, "images": Contract["images"], "vm_environment": fallback(e.P.Config, "vm_environment", D{}), "sizes": Contract["sizes"], "units": Units, "capabilities": e.capabilities(), "machine_kinds": D{"vm": "Supports packages, runcmd, health_checks and nested virtualization; use for Docker, Mininet and databases.", "ct": "Lightweight container; packages, runcmd, health_checks and nested virtualization are unsupported. Configure applications over SSH after creation."}}, nil
	case "capacity_get":
		return D{"capacity": e.Capacity(nil, true)}, nil
	}
	if named("admin_tools", tool) {
		if !boolean(w["admin"]) {
			fail("forbidden", "winlab-admin membership required")
		}
		t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == a["tenant"] })
		if tool == "request_approve" || tool == "request_reject" {
			r := e.S.Get("requests", str(a["id"]))
			if r != nil {
				t = e.S.TenantN(integer(r["tenant_n"]))
			}
		}
		var before D
		var n any
		if t != nil {
			before = e.Quota(t)
			n = t["n"]
		}
		r := e.Admin(tool, a, w)
		if before != nil && named("mutations", tool) {
			r = mutationResult(before, r, dry)
		} else if tool == "reconcile_run" && dry {
			r = merge(r, D{"state": "planned", "reserved": false, "resource_changes": false})
		}
		return r, n
	}
	if tool == "operation_get" && boolean(w["admin"]) && a["id"] != nil {
		// Admin jobs such as machine_migrate run in the machine's tenant.
		if op := e.S.Get("operations", str(a["id"])); op != nil && a["tenant"] == nil {
			t := e.S.TenantN(integer(op["tenant_n"]))
			e.P.Operations.Wait(e.Ctx, t, str(a["id"]), intAt(a, "wait_seconds", 55))
			return D{"operations": []D{publicOperation(e.P.Operations.Find(t, str(a["id"])))}}, t["n"]
		}
	}
	onboarding := e.Register(w, str(a["tenant"]), tool == "whoami")
	if tool == "whoami" {
		ts := []D{}
		for _, s := range subjects(w) {
			if t := e.S.Tenant(s[0]); t != nil {
				kind := "project"
				if strings.HasPrefix(s[0], "user:") {
					kind = "personal"
				}
				ts = append(ts, D{"slug": t["slug"], "kind": kind, "status": t["status"], "quota": e.Quota(t)})
			}
		}
		return D{"service": D{"name": "carrel", "version": Version}, "username": w["username"], "admin": w["admin"], "default_tenant": obj(e.S.Tenant("user:" + str(w["sub"])))["slug"], "onboarding": onboarding, "tenants": ts, "capabilities": e.capabilities()}, nil
	}
	t := e.Tenant(w, str(a["tenant"]))
	if (named("mutations", tool) || tool == "deployment_plan") && t["status"] != "active" {
		fail("forbidden", "Tenant is suspended")
	}
	before := e.Quota(t)
	r := e.Member(tool, a, w, t)
	if named("mutations", tool) {
		r = mutationResult(before, r, dry)
	}
	return r, t["n"]
}
func (e *Execution) Member(tool string, a, w, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	switch tool {
	case "operation_get":
		var ops []D
		if a["id"] != nil {
			e.P.Operations.Wait(e.Ctx, t, str(a["id"]), intAt(a, "wait_seconds", 55))
			ops = []D{e.P.Operations.Find(t, str(a["id"]))}
		} else {
			ops = e.S.RecentOperations(n, 50)
		}
		out := []D{}
		for _, o := range ops {
			out = append(out, publicOperation(o))
		}
		return D{"operations": out}
	case "operation_retry":
		if dry {
			return D{"operation": publicOperation(e.P.Operations.Find(t, str(a["id"])))}
		}
		r := e.P.Operations.Retry(t, str(a["id"]), w)
		r["operation"] = e.P.Operations.Wait(e.Ctx, t, str(a["id"]), intAt(a, "wait_seconds", 55))
		return r
	case "deployment_plan":
		return e.DeploymentPlan(t, a)
	case "deployment_apply":
		return e.DeploymentApply(t, a, w)
	case "quota_get":
		return D{"quota": e.Quota(t), "snapshot_storage": e.SnapshotUsage(t)}
	case "audit_log":
		return D{"entries": e.S.Rows("SELECT * FROM audit WHERE tenant=? OR (tenant IS NULL AND actor=?) ORDER BY id DESC LIMIT 100", n, w["sub"])}
	case "ssh_key_list":
		return D{"keys": rowsOf[sshKey](e.S, "keys", n)}
	case "ssh_key_add":
		validateKeys([]any{a["key"]})
		id := digest(strings.Fields(str(a["key"]))[1])[:16]
		if e.S.Get("keys", fmt.Sprintf("%d-%s", n, id)) == nil && len(rowsOf[sshKey](e.S, "keys", n)) >= maxSavedKeys {
			fail("quota_exceeded", fmt.Sprintf("A tenant saves at most %d keys", maxSavedKeys), D{"recovery": "revise_request"})
		}
		if !dry {
			e.Put("keys", fmt.Sprintf("%d-%s", n, id), n, D{"id": id, "key": a["key"]})
			e.syncJumpNow()
		}
		return D{"id": id, "dry_run": dry, "quota_after": e.Quota(t)}
	case "ssh_key_remove":
		if !dry {
			e.S.Remove("keys", fmt.Sprintf("%d-%s", n, str(a["id"])))
			e.syncJumpNow()
		}
		return D{"dry_run": dry, "quota_after": e.Quota(t)}
	case "machine_list", "machine_get":
		ms := e.S.Objects("machines", n)
		if tool == "machine_get" {
			ms = []D{e.Machine(t, a["machine"])}
		}
		out := []D{}
		for _, m := range ms {
			pub := e.PublicMachine(m, e.ports(n))
			if tool == "machine_get" {
				status := obj(e.Call(D{"op": "status", "machine": m}))
				observePower(pub, status)
				e.ObserveSSH(pub)
			}
			out = append(out, pub)
		}
		return D{"machines": out}
	case "machine_create":
		// A resumed creation finds the allocation its operation already made.
		if m := find(e.S.Objects("machines", n), func(m D) bool { return m["name"] == a["name"] && e.Op != nil && m["operation_id"] == e.Op["id"] }); m != nil {
			e.Provision(m, false)
			return D{"machine": e.PublicMachine(m, e.ports(n)), "quota_after": e.Quota(t)}
		}
		m := e.MachineSpec(t, a, dry)
		after := e.Quota(t, machineDelta(m))
		node, admission := e.Place(num(m["cpu"]), num(m["memory_mb"]), num(m["disk_gb"]))
		m = node.record(m)
		if dry {
			planned := plannedMachine(m)
			return D{"machine": planned, "quota_after": after, "admission": admission, "requirements": planned["requirements"], "units": Units, "connection": D{"available_after": "create", "public_ssh": m["public_ssh"] != false}}
		}
		var grant portGrant
		e.Transaction(func(tx *Execution) {
			m, grant = tx.AllocateMachine(t, m)
			if e.Op != nil {
				e.Op["reserved"] = true
				e.Op["resource_changes"] = true
				e.Op["phase"] = "provisioning"
				tx.S.Put("operations", e.Op["id"], n, e.Op)
			}
		})
		e.P.invalidateInventory()
		e.Provision(m, false)
		return D{"machine": e.PublicMachine(m, []portGrant{grant}), "quota_after": e.Quota(t)}
	case "machine_power", "machine_delete", "machine_resize", "machine_metrics":
		return e.MachineAction(tool, a, t)
	case "machine_media":
		return e.Media(e.Machine(t, a["machine"]), a, t)
	case "machine_rename":
		return e.RenameMachine(a, t)
	case "machine_console_url":
		return e.ConsoleURL(a, w, t)
	case "network_create", "network_list", "network_delete", "machine_nic_attach", "machine_nic_detach", "port_open", "port_list", "port_close", "peer_allow", "peer_list", "peer_revoke", "vip_add", "vip_list", "vip_remove":
		return e.NetworkAction(tool, a, t)
	case "domain_add", "domain_list", "domain_remove":
		return e.DomainAction(tool, a, t)
	case "vpn_client_add", "vpn_client_list", "vpn_client_remove":
		return e.VPNAction(tool, a, t)
	case "iso_import", "image_import":
		return e.PlanImport(tool, a, t)
	case "image_list", "image_delete":
		return e.ImageAction(tool, a, t)
	case "snapshot_create", "snapshot_list", "snapshot_delete", "snapshot_rollback":
		return e.SnapshotAction(tool, a, t)
	case "request_list":
		return D{"requests": publicRequests(e.S.Objects("requests", n))}
	case "quota_request":
		return e.QuotaRequest(a, w, t)
	case "domain_request":
		return e.DomainRequest(a, w, t)
	case "port_request":
		return e.PortRequest(a, w, t)
	case "app_link", "app_list", "app_get", "app_deploy", "app_rollback", "app_unlink":
		return e.AppTool(tool, a, t)
	}
	fail("invalid", "Unknown tool")
	return nil
}

func (e *Execution) MachineAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	m := e.Machine(t, a["machine"])
	request := D{"op": "action", "machine": m}
	if tool == "machine_metrics" {
		return D{"metrics": e.Call(D{"op": "metrics", "machine": m})}
	}
	var delta, spec D
	shrinking := false
	switch tool {
	case "machine_delete":
		if a["confirm"] != m["name"] {
			fail("invalid", "confirm must equal the machine name")
		}
		request["action"] = "delete"
		request["confirm"] = a["confirm"]
		delta = machineDelta(m)
		for k, v := range delta {
			delta[k] = -num(v)
		}
		for kind, dim := range map[string]string{"ports": "public_ports", "domains": "domains", "snapshots": "snapshots"} {
			owned := filter(e.S.Objects(kind, n), func(x D) bool { return integer(x["vmid"]) == integer(m["vmid"]) })
			delta[dim] = -len(owned)
			if kind == "snapshots" {
				sum := 0.0
				for _, x := range owned {
					sum += num(x["disk_gb"])
				}
				delta["snapshot_gb"] = -sum
			}
		}
	case "machine_power":
		return e.PowerMachine(m, a, t)
	case "machine_resize":
		spec = merge(pick(m, "cpu", "memory_mb", "disk_gb"), pick(a, "cpu", "memory_mb", "disk_gb"))
		if num(spec["disk_gb"]) < num(m["disk_gb"]) {
			fail("invalid", "Virtual disks cannot shrink")
		}
		shrinking = num(spec["cpu"]) < num(m["cpu"]) || num(spec["memory_mb"]) < num(m["memory_mb"])
		if shrinking && !dry {
			status := obj(e.Call(D{"op": "status", "machine": m}))
			if fallback(status, "status", status["state"]) != "stopped" {
				fail("conflict", "Stop the machine before reducing CPU or RAM", D{"recovery": "resolve_prerequisite"})
			}
		}
		delta = D{"vcpu": num(spec["cpu"]) - num(m["cpu"]), "memory_mb": num(spec["memory_mb"]) - num(m["memory_mb"]), "disk_gb": num(spec["disk_gb"]) - num(m["disk_gb"])}
		e.Quota(t, delta)
		for _, v := range delta {
			if num(v) > 0 {
				e.Admission(e.P.nodeOf(m), 0, 0, 0, merge(m, spec), false)
				break
			}
		}
		request = merge(request, spec, D{"action": "resize"})
	}
	if !dry {
		if tool == "machine_resize" {
			m["resize_from"] = fallback(m, "resize_from", pick(m, "cpu", "memory_mb", "disk_gb"))
			for k, v := range spec {
				m[k] = max(num(m[k]), num(v))
			}
			e.Put("machines", m["vmid"], n, m)
		}
		e.Call(request)
		e.P.invalidateInventory()
		switch tool {
		case "machine_delete":
			m["state"] = "deleting"
			e.Put("machines", m["vmid"], n, m)
			e.Reconcile()
			e.removeApps(filter(e.S.Objects("apps", n), func(a D) bool { return integer(a["vmid"]) == integer(m["vmid"]) }))
			e.Transaction(func(tx *Execution) {
				for _, kind := range []string{"ports", "domains", "snapshots", "guest_reports", "cloud_init"} {
					for _, o := range tx.S.Objects(kind, n) {
						if integer(o["vmid"]) == integer(m["vmid"]) {
							tx.S.Remove(kind, fallback(o, "id", o["vmid"]))
						}
					}
				}
				for _, p := range tx.peers() {
					if p.Target == m["ip"] || p.Source == str(m["ip"])+"/32" {
						tx.S.Remove("peers", p.ID)
					}
				}
				// The address stays reserved for the tenant; only this holder goes.
				for _, v := range tx.vips(n) {
					holders := []int{}
					for _, id := range v.VMIDs {
						if id != integer(m["vmid"]) {
							holders = append(holders, id)
						}
					}
					if len(holders) != len(v.VMIDs) {
						v.VMIDs = holders
						tx.Put("vips", v.ID, n, v)
					}
				}
				tx.S.Remove("machines", m["vmid"])
			})
		case "machine_resize":
			previous := obj(m["resize_from"])
			m["resize"] = resizeCompletion(m, previous, spec)
			m = merge(m, spec)
			delete(m, "resize_from")
			e.Put("machines", m["vmid"], n, m)
		}
	}
	q := e.Quota(t)
	if dry {
		q = e.Quota(t, delta)
	}
	r := D{"dry_run": dry, "quota_after": q}
	if !dry {
		if tool == "machine_delete" {
			r["deleted"] = D{"name": m["name"], "state": "deleted"}
		} else if tool == "machine_resize" {
			r["machine"] = e.PublicMachine(m, e.ports(n))
			r["configuration"] = "allocated; see machine.resize for guest verification and required owner actions"
		}
	}
	if dry && shrinking {
		r["requirements"] = []string{"machine_stopped"}
		r["ready_to_apply"] = m["state"] == "stopped"
	}
	return r
}
func parseExpiry(v string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, e := time.Parse(layout, v); e == nil {
			return t
		}
	}
	fail("invalid", "Use an ISO date for until")
	return time.Time{}
}

// capabilities is the contract's list with what this site turns on:
// imports need the fetch container (PLAN 7.8).
func (e *Execution) capabilities() D {
	c := clone(obj(Contract["capabilities"]))
	c["custom_image_import"] = boolean(e.P.Config["fetch"])
	return c
}
