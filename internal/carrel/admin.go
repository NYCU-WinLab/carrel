package carrel

import (
	"log/slog"
	"time"
)

func (e *Execution) Admin(tool string, a, w D) D {
	dry := boolean(a["dry_run"])
	switch tool {
	case "tenant_list", "usage_report":
		out := []D{}
		for _, t := range e.S.Tenants() {
			if tool == "tenant_list" {
				out = append(out, merge(t, D{"quota": e.Quota(t)}))
			} else {
				out = append(out, D{"slug": t["slug"], "quota": e.Quota(t)})
			}
		}
		return D{"tenants": out}
	case "node_list":
		nodes := []D{}
		for _, n := range e.P.Nodes() {
			nodes = append(nodes, D{"name": n.Name, "target": n.Target, "drained": e.drained(n.Name), "inventory": e.Call(D{"op": "inventory"}, n.Target)})
		}
		if len(nodes) == 1 {
			return D{"inventory": nodes[0]["inventory"]}
		}
		return D{"inventory": nodes[0]["inventory"], "nodes": nodes}
	case "machine_migrate":
		return e.PlanMigration(a)
	case "node_drain", "node_undrain":
		return e.DrainNode(tool, a, w)
	case "platform_power":
		return e.PlatformPower(a, w)
	case "reconcile_run":
		if dry {
			counts := D{}
			for k, v := range e.S.Desired() {
				counts[k] = len(arr(v))
			}
			return D{"dry_run": true, "result": counts}
		}
		r := e.Reconcile()
		e.RefreshStorage()
		out := D{"dry_run": false, "result": r, "cloud_init_collected": e.CollectCloudInit(), "disk_volumes_collected": e.CollectDiskVolumes()}
		if swept := e.SweepBackups(); swept != nil {
			out["backups_swept"] = swept
		}
		return out
	case "zone_add", "zone_list", "zone_remove":
		return e.ZoneAction(tool, a, w)
	case "domain_proxy":
		return e.DomainProxy(a, w)
	case "domain_transfer":
		return e.DomainTransfer(a, w)
	case "request_list_all":
		return D{"requests": publicRequests(e.S.Objects("requests"))}
	case "request_approve", "request_reject":
		r := e.S.Get("requests", str(a["id"]))
		if r == nil {
			fail("not_found", "Request not found")
		}
		if r["status"] != "pending" {
			fail("conflict", "Request is already decided")
		}
		t := e.S.TenantN(integer(r["tenant_n"]))
		if r["kind"] == "domain" {
			return e.approveDomain(tool, a, w, r, t)
		}
		if r["kind"] == "public_ip" {
			if boolean(a["adopt"]) {
				fail("invalid", "adopt applies only to domain requests", D{"recovery": "revise_request"})
			}
			return e.approvePublicIP(tool, a, w, r, t)
		}
		if r["kind"] == "port" {
			if boolean(a["adopt"]) {
				fail("invalid", "adopt applies only to domain requests", D{"recovery": "revise_request"})
			}
			return e.approvePort(tool, a, w, r, t)
		}
		if boolean(a["adopt"]) {
			fail("invalid", "adopt applies only to domain requests", D{"recovery": "revise_request"})
		}
		limits := obj(t["quota"])
		dim := str(r["dimension"])
		if tool == "request_approve" {
			validateQuotaLimit(t, dim, r["amount"], true)
			validateGrantExpiry(r["until"])
			e.checkExpiring(t, dim)
		}
		if !dry {
			e.Transaction(func(tx *Execution) {
				if tool == "request_approve" {
					r["previous_limit"] = limits[dim]
					limits[dim] = r["amount"]
					tx.S.Exec("UPDATE tenants SET quota=? WHERE n=?", string(encoded(limits)), t["n"])
					r["status"] = "approved"
				} else {
					r["status"] = "rejected"
				}
				r["decided_by"] = w["sub"]
				tx.Put("requests", r["id"], integer(t["n"]), r)
			})
		} else if tool == "request_approve" {
			limits[dim] = r["amount"]
			r["status"] = "planned_approval"
		} else {
			r["status"] = "planned_rejection"
		}
		return D{"request": without(r, "idempotency_key", "fingerprint"), "dry_run": dry, "quota_after": e.Quota(t)}
	}
	t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == a["tenant"] })
	if t == nil {
		fail("not_found", "Tenant not found")
	}
	switch tool {
	case "quota_set":
		dim := str(a["dimension"])
		validateQuotaLimit(t, dim, a["amount"], false)
		e.checkExpiring(t, dim)
		limits := merge(obj(t["quota"]), D{dim: a["amount"]})
		if num(limits["public_ports"]) > 10 || num(limits["networks"]) > 99 || num(limits["machines"]) > 100 {
			fail("invalid", "Quota exceeds address plan")
		}
		if num(limits[dim]) < num(e.Usage(t)[dim]) {
			fail("conflict", "New limit is below existing allocations")
		}
		if !dry {
			e.S.Exec("UPDATE tenants SET quota=? WHERE n=?", string(encoded(limits)), t["n"])
		}
		t["quota"] = limits
	case "tenant_suspend":
		if !dry {
			for _, m := range e.S.Objects("machines", integer(t["n"])) {
				e.Call(D{"op": "action", "machine": m, "action": "stop"})
				m = merge(m, D{"state": "stopped", "power_state": "stopped", "onboot": false, "ssh_ready": false})
				e.Put("machines", m["vmid"], integer(t["n"]), m)
				e.P.notifyReport(integer(m["vmid"]))
			}
			e.S.Exec("UPDATE tenants SET status='suspended' WHERE n=?", t["n"])
			e.P.invalidateInventory()
			// The gateway answers delegated names it knows itself (#166):
			// it must forget the suspended tenant's names now. The suspension
			// stands if it is unreachable; the maintenance pass retries.
			if err := attempt(func() { e.Reconcile() }); err != nil {
				slog.Warn("suspend_reconcile_failed", "tenant", t["n"], "error", describe(err))
			}
		}
	}
	return D{"dry_run": dry, "quota_after": e.Quota(t)}
}
func validateDimension(dim string) {
	if _, ok := DefaultQuota[dim]; !ok {
		fail("invalid", "Quota dimension is not available")
	}
}
func (e *Execution) checkExpiring(t D, dim string) {
	if find(e.S.Objects("requests", integer(t["n"])), func(r D) bool { return r["status"] == "approved" && str(r["until"]) != "" && r["dimension"] == dim }) != nil {
		fail("conflict", "An expiring grant controls this dimension")
	}
}
func (e *Execution) ExpireGrants() {
	for _, r := range e.S.Objects("requests") {
		if r["status"] != "approved" || str(r["until"]) == "" || parseExpiry(str(r["until"])).After(time.Now()) {
			continue
		}
		t := e.S.TenantN(integer(r["tenant_n"]))
		obj(t["quota"])[str(r["dimension"])] = r["previous_limit"]
		e.Transaction(func(tx *Execution) {
			tx.S.Exec("UPDATE tenants SET quota=? WHERE n=?", string(encoded(t["quota"])), t["n"])
			r["status"] = "expired"
			tx.Put("requests", r["id"], integer(t["n"]), r)
		})
		e.S.Log("system", t["n"], "quota_expired", D{"request": r["id"]}, "ok")
	}
}
