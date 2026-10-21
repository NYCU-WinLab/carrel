package carrel

import "sort"

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
	from := e.P.nodeOf(m)
	if a["from"] != nil && from.Name != str(a["from"]) && obj(obj(e.Op)["migration"])["to"] == nil {
		// A drain's move for a machine that already left that node.
		return D{"machine": m["name"], "from": a["from"], "to": from.Name, "state": "moved"}
	}
	if plan := obj(obj(e.Op)["migration"]); plan["to"] != nil {
		// A retried job keeps its plan, wherever the machine is by now.
		return D{"machine": m["name"], "from": plan["from"], "to": plan["to"], "state": "migrating"}
	}
	// One move at a time: the copies share the nodes' one link with corosync.
	if e.Op != nil {
		for _, other := range e.S.ActiveOperations() {
			if other["id"] != e.Op["id"] && other["tool"] == "machine_migrate" && other["migration"] != nil {
				panic(Waiting{"waiting_for_migration_slot", now() + num(fallback(e.P.Config, "migration_slot_retry_seconds", 15))})
			}
		}
	}
	var target nodeRef
	if a["node"] == nil {
		target, _ = e.Place(num(m["cpu"]), num(m["memory_mb"]), num(m["disk_gb"]), from.Name)
	} else {
		var ok bool
		if target, ok = e.nodeNamed(str(a["node"])); !ok {
			fail("invalid", "Unknown node", D{"recovery": "revise_request"})
		}
		if e.drained(target.Name) {
			fail("conflict", "The target node is drained", D{"recovery": "revise_request"})
		}
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
	// A drain's move for a machine that already left has no plan.
	if e.Op["tool"] != "machine_migrate" || e.Op["migration"] == nil {
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
	func() {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		e.Op["phase"] = "moving_machine"
		e.P.Operations.Save(e.Op)
	}()
	bw := intAt(e.P.Config, "migration_bwlimit_kib", 51200)
	e.Call(D{"op": "migrate_prepare", "machine": m, "cloud_init": e.cloudInitFiles(m)}, to.Target)
	e.Call(D{"op": "migrate", "machine": m, "target": to.Name, "bwlimit": bw}, from.Target)
	// The machine runs on the target now: record it before the disk goes
	// back to local storage, so a failure there leaves the record right.
	func() {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		if current := e.S.Get("machines", str(plan["vmid"])); current != nil {
			current["node"] = to.Name
			e.Put("machines", current["vmid"], integer(current["tenant_n"]), current)
			e.P.invalidateInventory()
		}
	}()
	e.Call(D{"op": "migrate_finish", "machine": merge(m, D{"node": to.Name}), "bwlimit": bw}, to.Target)
}

// FinishMigration records the new node under the writer lock.
func (e *Execution) FinishMigration(t D) D {
	if e.Op["migration"] == nil {
		return D{}
	}
	plan := obj(e.Op["migration"])
	m := e.S.Get("machines", str(plan["vmid"]))
	if m == nil {
		fail("not_found", "The machine was deleted while moving")
	}
	from, _ := e.nodeNamed(str(plan["from"]))
	e.Reconcile()
	// The files on the old node are a copy: best effort, collected again by
	// the next move from there.
	_ = attempt(func() { e.Call(D{"op": "cloud_init_remove", "machine": m}, from.Target) })
	return D{"machine": e.PublicMachine(m, e.ports(integer(t["n"]))), "from": plan["from"], "to": plan["to"], "state": "moved"}
}

// DrainNode takes a node out of placement and queues a move for each of its
// machines; the moves run one at a time. Undrain only reopens placement.
func (e *Execution) DrainNode(tool string, a, w D) D {
	node, ok := e.nodeNamed(str(a["node"]))
	if !ok {
		fail("invalid", "Unknown node", D{"recovery": "revise_request"})
	}
	if tool == "node_undrain" {
		if !boolean(a["dry_run"]) {
			e.S.SitePut("node", node.Name, D{"drained": false})
		}
		return D{"node": node.Name, "drained": false, "dry_run": boolean(a["dry_run"])}
	}
	open := 0
	for _, n := range e.P.Nodes() {
		if n.Name != node.Name && !e.drained(n.Name) {
			open++
		}
	}
	if open == 0 {
		fail("conflict", "Draining this node would leave no node for machines", D{"recovery": "revise_request"})
	}
	dry := boolean(a["dry_run"])
	if !dry {
		// Marked first: a drain that stops halfway is resumed by running it again.
		e.S.SitePut("node", node.Name, D{"drained": true})
	}
	moving := map[int]any{}
	for _, op := range e.S.ActiveOperations() {
		if op["tool"] == "machine_migrate" {
			moving[integer(obj(op["machine_target"])["vmid"])] = op["id"]
		}
	}
	machines := filter(e.S.Objects("machines"), func(m D) bool { return m["node"] == node.Name && m["state"] != "deleting" })
	sort.Slice(machines, func(i, j int) bool { return integer(machines[i]["vmid"]) < integer(machines[j]["vmid"]) })
	moves, staying := []D{}, []D{}
	for _, m := range machines {
		t := e.S.TenantN(integer(m["tenant_n"]))
		move := D{"tenant": t["slug"], "machine": m["name"]}
		reason := ""
		switch {
		case t["status"] != "active":
			reason = "tenant_suspended"
		case !contains([]string{"ready", "running", "stopped"}, m["state"]):
			reason = "machine_" + str(m["state"])
		case len(filter(e.snapshotRows(integer(t["n"])), func(s D) bool { return integer(s["vmid"]) == integer(m["vmid"]) })) > 0:
			reason = "has_snapshots"
		}
		if reason != "" {
			staying = append(staying, merge(move, D{"reason": reason}))
			continue
		}
		if id, ok := moving[integer(m["vmid"])]; ok {
			// Running the drain again does not move a machine twice.
			moves = append(moves, merge(move, D{"operation": id}))
			continue
		}
		if !dry {
			op := e.P.Operations.Submit("machine_migrate", merge(move, D{"from": node.Name}), w, t)
			move["operation"] = op["id"]
		}
		moves = append(moves, move)
	}
	return D{"node": node.Name, "drained": true, "moves": moves, "staying": staying, "dry_run": dry}
}

func (e *Execution) snapshotRows(n int) []D { return e.S.Objects("snapshots", n) }
