package carrel

import (
	"context"
	"fmt"
	"sort"
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
	if named("async_tools", tool) && !boolean(a["dry_run"]) {
		var t D
		if named("admin_tools", tool) {
			if !boolean(w["admin"]) {
				fail("forbidden", "winlab-admin membership required")
			}
			t = find(e.S.Tenants(), func(t D) bool { return t["slug"] == a["tenant"] })
			if t == nil && tool == "tenant_suspend" {
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
		if tool == "machine_create" || tool == "deployment_apply" {
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
		return D{"service": D{"name": "carrel", "version": Version}, "images": Contract["images"], "vm_environment": fallback(e.P.Config, "vm_environment", D{}), "sizes": Contract["sizes"], "units": Units, "capabilities": Contract["capabilities"], "machine_kinds": D{"vm": "Supports packages, runcmd, health_checks and nested virtualization; use for Docker, Mininet and databases.", "ct": "Lightweight container; packages, runcmd, health_checks and nested virtualization are unsupported. Configure applications over SSH after creation."}}, nil
	case "images_list":
		return D{"images": filter(dicts(Contract["images"]), func(i D) bool { return a["kind"] == nil || a["kind"] == i["kind"] })}, nil
	case "sizes_list":
		return D{"sizes": Contract["sizes"], "units": Units}, nil
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
		return D{"service": D{"name": "carrel", "version": Version}, "username": w["username"], "admin": w["admin"], "default_tenant": obj(e.S.Tenant("user:" + str(w["sub"])))["slug"], "onboarding": onboarding, "tenants": ts, "capabilities": Contract["capabilities"]}, nil
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
		ops := e.S.Objects("operations", n)
		if a["id"] != nil {
			e.P.Operations.Wait(e.Ctx, t, str(a["id"]), intAt(a, "wait_seconds", 55))
			ops = []D{e.P.Operations.Find(t, str(a["id"]))}
		} else {
			sort.Slice(ops, func(i, j int) bool { return num(ops[i]["created_at"]) > num(ops[j]["created_at"]) })
			if len(ops) > 50 {
				ops = ops[:50]
			}
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
		return e.P.Operations.Retry(t, str(a["id"]), w)
	case "deployment_plan":
		return e.DeploymentPlan(t, a)
	case "deployment_apply":
		if dry {
			return e.DeploymentPlan(t, a)
		}
		return e.DeploymentApply(t, a, w)
	case "quota_get":
		return D{"quota": e.Quota(t), "snapshot_storage": e.SnapshotUsage(t)}
	case "audit_log":
		return D{"entries": e.S.Rows("SELECT * FROM audit WHERE tenant=? OR (tenant IS NULL AND actor=?) ORDER BY id DESC LIMIT 100", n, w["sub"])}
	case "ssh_key_list":
		return D{"keys": e.S.Objects("keys", n)}
	case "ssh_key_add":
		validateKeys([]any{a["key"]})
		id := digest(strings.Fields(str(a["key"]))[1])[:16]
		if !dry {
			e.Put("keys", fmt.Sprintf("%d-%s", n, id), n, D{"id": id, "key": a["key"]})
		}
		return D{"id": id, "dry_run": dry, "quota_after": e.Quota(t)}
	case "ssh_key_remove":
		if !dry {
			e.S.Remove("keys", fmt.Sprintf("%d-%s", n, str(a["id"])))
		}
		return D{"dry_run": dry, "quota_after": e.Quota(t)}
	case "machine_list", "machine_get":
		ms := e.S.Objects("machines", n)
		if tool == "machine_get" {
			ms = []D{e.Machine(t, a["machine"])}
		}
		out := []D{}
		for _, m := range ms {
			pub := e.PublicMachine(m, e.S.Objects("ports", n))
			if tool == "machine_get" {
				status := obj(e.Call(D{"op": "status", "machine": m}))
				pub["runtime"] = D{"power_state": fallback(status, "status", fallback(status, "state", "unknown")), "uptime_seconds": status["uptime"], "observed_at": stamp()}
			}
			out = append(out, pub)
		}
		return D{"machines": out}
	case "machine_create", "machine_retry":
		existing := find(e.S.Objects("machines", n), func(m D) bool { return m["name"] == a["name"] && e.Op != nil && m["operation_id"] == e.Op["id"] })
		if tool == "machine_retry" || existing != nil {
			m := existing
			if m == nil {
				m = e.Machine(t, a["machine"])
			}
			if !contains([]string{"error", "needs_owner_fix", "provisioning", "initializing"}, m["state"]) && existing == nil {
				fail("conflict", "Only an incomplete allocation can be retried")
			}
			if !dry {
				e.Provision(m, false)
			}
			return D{"machine": e.PublicMachine(m, e.S.Objects("ports", n)), "quota_after": e.Quota(t)}
		}
		m := e.MachineSpec(t, a, dry)
		after := e.Quota(t, machineDelta(m))
		admission := e.Admission(num(m["cpu"]), num(m["memory_mb"]), num(m["disk_gb"]), nil, false)
		if dry {
			planned := plannedMachine(m)
			return D{"machine": planned, "quota_after": after, "admission": admission, "requirements": planned["requirements"], "units": Units, "connection": D{"available_after": "create", "public_ssh": true}}
		}
		var grant D
		e.Transaction(func(tx *Execution) {
			m, grant = tx.AllocateMachine(t, m)
			if e.Op != nil {
				e.Op["reserved"] = true
				e.Op["resource_changes"] = true
				e.Op["phase"] = "provisioning"
				tx.S.Put("operations", e.Op["id"], n, e.Op)
			}
		})
		e.P.inventory.Invalidate()
		e.Provision(m, false)
		return D{"machine": e.PublicMachine(m, []D{grant}), "quota_after": e.Quota(t)}
	case "machine_power", "machine_delete", "machine_resize", "machine_metrics":
		return e.MachineAction(tool, a, t)
	case "network_create", "network_list", "network_delete", "machine_nic_attach", "machine_nic_detach", "port_open", "port_list", "port_close", "peer_allow", "peer_list", "peer_revoke":
		return e.NetworkAction(tool, a, t)
	case "domain_add", "domain_list", "domain_remove":
		return e.DomainAction(tool, a, t)
	case "snapshot_create", "snapshot_list", "snapshot_delete", "snapshot_rollback":
		return e.SnapshotAction(tool, a, t)
	case "request_list":
		return D{"requests": e.S.Objects("requests", n)}
	case "quota_request":
		dim := str(a["dimension"])
		if _, ok := DefaultQuota[dim]; !ok || dim == "images_gb" {
			fail("invalid", "Quota dimension is not available")
		}
		if a["until"] != nil {
			if !parseExpiry(str(a["until"])).After(time.Now()) {
				fail("invalid", "Expiry must be in the future")
			}
		}
		r := D{"id": randomID()[:16], "tenant_n": n, "kind": "quota", "status": "pending", "dimension": dim, "amount": a["amount"], "reason": a["reason"], "until": a["until"], "actor": w["sub"], "created_at": time.Now().Unix()}
		if !dry {
			e.Put("requests", r["id"], n, r)
		} else {
			r = without(r, "id", "tenant_n", "actor", "created_at")
			r["status"] = "planned"
		}
		return D{"request": r, "dry_run": dry, "quota_after": e.Quota(t)}
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
		request["action"] = a["action"]
		if a["action"] == "start" || a["action"] == "reboot" {
			zeros := D{}
			for k := range without(DefaultQuota, "images_gb") {
				zeros[k] = 0
			}
			e.Quota(t, zeros)
		}
	case "machine_resize":
		spec = merge(pick(m, "cpu", "memory_mb", "disk_gb"), pick(a, "cpu", "memory_mb", "disk_gb"))
		if num(spec["disk_gb"]) < num(m["disk_gb"]) {
			fail("invalid", "Virtual disks cannot shrink")
		}
		shrinking = num(spec["cpu"]) < num(m["cpu"]) || num(spec["memory_mb"]) < num(m["memory_mb"])
		if shrinking && !dry {
			status := obj(e.Call(D{"op": "status", "machine": m}))
			if fallback(status, "status", status["state"]) != "stopped" {
				fail("conflict", "Stop the machine before reducing CPU or RAM")
			}
		}
		delta = D{"vcpu": num(spec["cpu"]) - num(m["cpu"]), "memory_mb": num(spec["memory_mb"]) - num(m["memory_mb"]), "disk_gb": num(spec["disk_gb"]) - num(m["disk_gb"])}
		e.Quota(t, delta)
		for _, v := range delta {
			if num(v) > 0 {
				e.Admission(0, 0, 0, merge(m, spec), false)
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
		e.P.inventory.Invalidate()
		switch tool {
		case "machine_delete":
			m["state"] = "deleting"
			e.Put("machines", m["vmid"], n, m)
			e.Reconcile()
			e.Transaction(func(tx *Execution) {
				for _, kind := range []string{"ports", "domains", "snapshots", "guest_reports"} {
					for _, o := range tx.S.Objects(kind, n) {
						if integer(o["vmid"]) == integer(m["vmid"]) {
							tx.S.Remove(kind, fallback(o, "id", o["vmid"]))
						}
					}
				}
				for _, p := range tx.S.Objects("peers") {
					if p["target"] == m["ip"] || p["source"] == str(m["ip"])+"/32" {
						tx.S.Remove("peers", p["id"])
					}
				}
				tx.S.Remove("machines", m["vmid"])
			})
		case "machine_resize":
			m = merge(m, spec)
			delete(m, "resize_from")
			e.Put("machines", m["vmid"], n, m)
		default:
			state := "running"
			if a["action"] == "stop" || a["action"] == "shutdown" {
				state = "stopped"
			}
			m = merge(m, D{"state": state, "power_state": state, "ssh_ready": false})
			e.Put("machines", m["vmid"], n, m)
		}
	}
	q := e.Quota(t)
	if dry {
		q = e.Quota(t, delta)
	}
	r := D{"dry_run": dry, "quota_after": q}
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
