package carrel

// Moving machines between nodes (PLAN 7.10). Validation and the plan run
// under the writer lock; the copy runs outside it, like certificate
// preparation, because it takes minutes; the record changes node at the end.

func (e *Execution) nodeNamed(name string) (nodeRef, bool) {
	for _, n := range e.P.Nodes() {
		if n.Name == name {
			return n, true
		}
	}
	return nodeRef{}, false
}

func (e *Execution) PlanMigration(a D) D {
	t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == a["tenant"] })
	if t == nil {
		fail("not_found", "Tenant not found")
	}
	m := e.Machine(t, a["machine"])
	target, ok := e.nodeNamed(str(a["node"]))
	if !ok {
		fail("invalid", "Unknown node", D{"recovery": "revise_request"})
	}
	from := e.P.nodeOf(m)
	if plan := obj(obj(e.Op)["migration"]); plan["to"] == target.Name {
		// A retried job keeps its plan, wherever the machine is by now.
		return D{"machine": m["name"], "from": plan["from"], "to": plan["to"], "state": "migrating"}
	}
	if from.Name == target.Name {
		fail("conflict", "The machine is already on that node", D{"recovery": "revise_request"})
	}
	if !contains([]string{"ready", "running", "stopped"}, m["state"]) {
		fail("conflict", "Only a ready or stopped machine can move", D{"recovery": "resolve_prerequisite"})
	}
	for _, s := range e.snapshots(integer(t["n"])) {
		if s.VMID == integer(m["vmid"]) {
			fail("conflict", "Delete the machine's snapshots before moving it", D{"recovery": "resolve_prerequisite"})
		}
	}
	if obj(e.Call(D{"op": "inventory"}, target.Target))["tenant_route"] == false {
		fail("conflict", "The target node has no tenant route", D{"recovery": "retry_infrastructure"})
	}
	e.Admission(target, 0, 0, 0, merge(m, D{"node": target.Name}), false)
	if m["kind"] == "vm" && e.cloudInitFiles(m) == nil {
		e.keepCloudInit(m, obj(e.Call(D{"op": "cloud_init_read", "machine": m}))["cloud_init"])
		if e.cloudInitFiles(m) == nil {
			fail("conflict", "The VM's cloud-init files are unknown; moving it would run cloud-init again", D{"recovery": "retry_infrastructure"})
		}
	}
	plan := D{"vmid": m["vmid"], "from": from.Name, "to": target.Name}
	if boolean(a["dry_run"]) {
		return merge(D{"dry_run": true, "machine": m["name"]}, without(plan, "vmid"))
	}
	if e.Op != nil {
		e.Op["migration"] = plan
		e.P.Operations.Save(e.Op)
	}
	return D{"machine": m["name"], "from": from.Name, "to": target.Name, "state": "migrating"}
}

// PerformMigration copies the machine without the writer lock. Each step
// on a node is idempotent, so a job that restarts runs them again.
func (e *Execution) PerformMigration() {
	if e.Op["tool"] != "machine_migrate" {
		return
	}
	plan := obj(e.Op["migration"])
	m := e.S.Get("machines", str(plan["vmid"]))
	if m == nil {
		fail("not_found", "The machine was deleted while moving")
	}
	from, ok1 := e.nodeNamed(str(plan["from"]))
	to, ok2 := e.nodeNamed(str(plan["to"]))
	if !ok1 || !ok2 {
		fail("conflict", "A node of this move is no longer configured")
	}
	bw := intAt(e.P.Config, "migration_bwlimit_kib", 51200)
	e.Call(D{"op": "migrate_prepare", "machine": m, "cloud_init": e.cloudInitFiles(m)}, to.Target)
	e.Call(D{"op": "migrate", "machine": m, "target": to.Name, "bwlimit": bw}, from.Target)
	e.Call(D{"op": "migrate_finish", "machine": m, "bwlimit": bw}, to.Target)
}

// FinishMigration records the new node under the writer lock.
func (e *Execution) FinishMigration(t D) D {
	plan := obj(e.Op["migration"])
	m := e.S.Get("machines", str(plan["vmid"]))
	if m == nil {
		fail("not_found", "The machine was deleted while moving")
	}
	from, _ := e.nodeNamed(str(plan["from"]))
	m["node"] = plan["to"]
	e.Put("machines", m["vmid"], integer(t["n"]), m)
	e.P.invalidateInventory()
	e.Reconcile()
	// The files on the old node are a copy: best effort, collected again by
	// the next move from there.
	_ = attempt(func() { e.Call(D{"op": "cloud_init_remove", "machine": m}, from.Target) })
	return D{"machine": e.PublicMachine(m, e.ports(integer(t["n"]))), "from": plan["from"], "to": plan["to"]}
}
