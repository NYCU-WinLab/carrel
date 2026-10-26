package carrel

import (
	"fmt"
	"regexp"
	"time"
)

// Freeze and thaw (issue #190): a stopped machine is backed up to the PVE
// storage that fronts the Proxmox Backup Server and removed from the cluster.
// Its row moves from "machines" to "frozen", so nothing that walks the live
// machines sees it, while its VMID, name and internal address stay taken.
// Only the frozen quota and the address are charged until it is thawed or
// deleted.

// freezeReleasable names the resources a machine may hold that freeze can
// require released first; the site's freeze_release list picks among them.
var freezeReleasable = []string{"public_ips", "special_ports", "special_domains"}

var backupVolume = regexp.MustCompile(`^[a-z][a-z0-9_.-]*:backup/[A-Za-z0-9_./:+-]+$`)

// forgetMachine removes everything of a machine that hangs off its VMID.
func (tx *Execution) forgetMachine(n int, m D) {
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
	// A public address stays the tenant's, unbound (issue #91): a
	// later machine with this VMID must not inherit it.
	for _, b := range tx.publicIPs(n) {
		if b.VMID == integer(m["vmid"]) {
			b.VMID, b.Ports, b.BoundAt = 0, nil, 0
			tx.Put("public_ips", b.ID, n, b)
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
}

// frozenMachine finds a frozen machine of the tenant by name or VMID.
func (e *Execution) frozenMachine(t D, ref any) D {
	return find(e.S.Objects("frozen", integer(t["n"])), func(f D) bool { return str(f["vmid"]) == str(ref) || str(f["name"]) == str(ref) })
}

// frozenDisks is the configured disk size of the tenant's frozen machines.
func frozenDisks(frozen []D) float64 {
	sum := 0.0
	for _, f := range frozen {
		sum += num(f["disk_gb"])
	}
	return sum
}

// PublicFrozen is a frozen machine as machine_list shows it.
func (e *Execution) PublicFrozen(f D) D {
	r := pick(f, "name", "kind", "image", "cpu", "memory_mb", "disk_gb", "swap_mb", "ip", "frozen_at")
	r["state"] = "frozen"
	if f["thaw_node"] != nil {
		r["state"] = "thawing"
	}
	r["backup"] = D{"size_bytes": f["backup_bytes"]}
	r["quota"] = D{"frozen_gb": f["disk_gb"], "ips": 1}
	return r
}

func (e *Execution) backupStorage() string {
	storage := str(e.P.Config["backup_storage"])
	if storage == "" {
		fail("backend_unavailable", "Freezing machines is not set up on this site", D{"recovery": "contact_administrator"})
	}
	return storage
}

// freezeRelease is the site's list of resource kinds a machine must have
// released before it freezes.
func (e *Execution) freezeRelease() []string {
	list := freezeReleasable
	if v, ok := e.P.Config["freeze_release"]; ok {
		list = nil
		for _, k := range arr(v) {
			if !contains(freezeReleasable, str(k)) {
				fail("invalid", "freeze_release names an unknown resource kind", D{"resource": k})
			}
			list = append(list, str(k))
		}
	}
	return list
}

// freezeHeld lists what the machine holds of the resources that must go
// first, each named for the member.
func (e *Execution) freezeHeld(n int, m D) []D {
	vmid, held := integer(m["vmid"]), []D{}
	for _, kind := range e.freezeRelease() {
		switch kind {
		case "public_ips":
			for _, b := range e.publicIPs(n) {
				if b.VMID == vmid {
					held = append(held, D{"resource": "public_ip", "name": b.Address, "release_with": "public_ip_release"})
				}
			}
		case "special_ports":
			for _, g := range e.ports(n) {
				if g.VMID == vmid && g.Special {
					held = append(held, D{"resource": "special_port", "name": fmt.Sprintf("%d/%s", g.PublicPort, g.Proto), "release_with": "port_close"})
				}
			}
		case "special_domains":
			for _, d := range rowsOf[domainRecord](e.S, "domains", n) {
				if d.VMID == vmid && d.Grant != "" {
					held = append(held, D{"resource": "special_domain", "name": d.Name, "release_with": "domain_remove"})
				}
			}
		}
	}
	return held
}

// freezeDelta is what a freeze changes in the quota: the machine's compute
// is released, its address and public ports stay, its disk size is charged
// to the frozen quota.
func freezeDelta(m D) D {
	d := machineDelta(m)
	delete(d, "ips")
	delete(d, "public_ports")
	for k, v := range d {
		d[k] = -num(v)
	}
	d["frozen_gb"] = m["disk_gb"]
	return d
}

// thawDelta is the reverse: the normal quota is checked as for a creation.
func thawDelta(f D) D {
	d := machineDelta(f)
	delete(d, "ips")
	delete(d, "public_ports")
	d["frozen_gb"] = -num(f["disk_gb"])
	return d
}

// A freeze or a thaw runs in three parts, like a migration: the request is
// checked and planned under the writer lock (FreezeMachine, ThawMachine),
// the backup or the restore runs outside it (PerformFreeze, PerformThaw),
// and the records change under it again (FinishFreeze, FinishThaw). Every
// step on a node is idempotent, so a job that restarts runs them again.

// freezeWait is how long the agent waits for the backup server to verify the
// new backup.
func (e *Execution) freezeWait() int { return intAt(e.P.Config, "freeze_verify_wait", 1800) }

// freezeCommitted reports that this operation already wrote its frozen row:
// the backup it names is the machine's only copy and must not be touched.
func (e *Execution) freezeCommitted(vmid any) bool {
	f := e.S.Get("frozen", str(vmid))
	return f != nil && e.Op != nil && f["frozen_by"] == e.Op["id"]
}

func (e *Execution) FreezeMachine(a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	storage := e.backupStorage()
	if f := e.frozenMachine(t, a["machine"]); f != nil && e.S.Get("machines", str(f["vmid"])) == nil {
		fail("conflict", "The machine is already frozen", D{"recovery": "resolve_prerequisite"})
	}
	m := e.Machine(t, a["machine"])
	if a["confirm"] != m["name"] {
		fail("invalid", "confirm must equal the machine name")
	}
	// A freeze that stopped after the backup: the machine row is all that is left to remove.
	resumed := e.S.Get("frozen", str(m["vmid"])) != nil && (m["state"] == "deleting" || e.freezeCommitted(m["vmid"]))
	if !resumed {
		e.freezeChecks(n, m)
	}
	delta := freezeDelta(m)
	if !resumed {
		e.Quota(t, delta)
	}
	if dry {
		return D{"machine": D{"name": m["name"], "state": "frozen_planned"}, "dry_run": true, "quota_after": e.Quota(t, delta), "requirements": []string{"machine_stopped"}, "ready_to_apply": true}
	}
	if e.Op == nil {
		fail("internal", "A freeze runs as an operation")
	}
	// The operation's id names the backup: a retry finds the one it made,
	// and the agent keeps it only while the machine has not run since.
	e.Op["freeze"] = D{"vmid": m["vmid"], "storage": storage, "freeze_id": e.Op["id"], "resumed": resumed}
	e.P.Operations.Save(e.Op)
	return D{"machine": D{"name": m["name"], "state": "freezing"}, "dry_run": false, "quota_after": e.Quota(t, delta)}
}

// freezeChecks is what a machine must satisfy to be backed up and removed;
// it runs again before the machine goes, since the backup takes a while.
func (e *Execution) freezeChecks(n int, m D) {
	if state := str(m["state"]); contains([]string{"provisioning", "deleting", "migrating", "needs_owner_fix"}, state) || m["resize_from"] != nil {
		fail("conflict", "The machine is "+state+"; freeze it once that has finished", D{"recovery": "resolve_prerequisite"})
	}
	if e.machineBusy(n, m) && e.Op == nil {
		fail("conflict", "An operation on this machine is queued or running; freeze it once that has finished", D{"recovery": "resolve_prerequisite"})
	}
	if status := obj(e.Call(D{"op": "status", "machine": m})); powerState(status) != "stopped" {
		fail("conflict", "Shut the machine down with machine_power before freezing it", D{"recovery": "resolve_prerequisite", "requirements": []string{"machine_stopped"}})
	}
	if snaps := filter(toDicts(e.snapshots(n)), func(s D) bool { return integer(s["vmid"]) == integer(m["vmid"]) }); len(snaps) > 0 {
		fail("conflict", "Delete the machine's disk snapshots first; they are not part of the backup", D{"recovery": "resolve_prerequisite", "snapshots": len(snaps)})
	}
	if held := e.freezeHeld(n, m); len(held) > 0 {
		fail("conflict", "Release "+str(held[0]["name"])+" first: it is a shared resource that a frozen machine cannot keep", D{"recovery": "resolve_prerequisite", "held": held})
	}
}

// PerformFreeze takes the backup without the writer lock. The machine stays
// as it is: a failure, or a backup the backup server did not verify, leaves it.
func (e *Execution) PerformFreeze() {
	if e.Op["tool"] != "machine_freeze" || e.Op["freeze"] == nil {
		return
	}
	plan := obj(e.Op["freeze"])
	if boolean(plan["resumed"]) || e.freezeCommitted(plan["vmid"]) {
		return
	}
	m := e.S.Get("machines", str(plan["vmid"]))
	if m == nil {
		fail("not_found", "The machine was deleted while freezing")
	}
	func() {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		e.Op["phase"] = "freezing_machine"
		e.P.Operations.Save(e.Op)
	}()
	backup := obj(e.Call(D{"op": "freeze", "machine": m, "storage": plan["storage"], "freeze_id": plan["freeze_id"], "verify_wait": e.freezeWait()}))
	// An explicit verification, not just the absence of a failed one.
	if !backupVolume.MatchString(str(backup["volid"])) || num(backup["size"]) <= 0 || backup["verification"] != "ok" || str(backup["note"]) == "" {
		fail("backend_unavailable", "The backup could not be verified; the machine is unchanged", D{"recovery": "retry_infrastructure"})
	}
	e.P.writer.Lock()
	defer e.P.writer.Unlock()
	plan["backup"] = backup
	e.Op["freeze"] = plan
	e.P.Operations.Save(e.Op)
}

// FinishFreeze removes the machine once its backup is verified, under the
// writer lock, after checking again that nothing changed meanwhile.
func (e *Execution) FinishFreeze(t D) D {
	if e.Op["tool"] != "machine_freeze" || e.Op["freeze"] == nil {
		return D{}
	}
	plan, n := obj(e.Op["freeze"]), integer(t["n"])
	committed := e.freezeCommitted(plan["vmid"])
	m := e.S.Get("machines", str(plan["vmid"]))
	if m == nil {
		if committed {
			return D{"machine": e.PublicFrozen(e.S.Get("frozen", str(plan["vmid"]))), "dry_run": false, "quota_after": e.Quota(t)}
		}
		fail("not_found", "The machine was deleted while freezing")
	}
	if !boolean(plan["resumed"]) && !committed {
		backup := obj(plan["backup"])
		// The backup is unwanted if the machine can no longer go: drop it, so
		// no protected copy is left without a record.
		if problem := attempt(func() {
			e.freezeChecks(n, m)
			e.Quota(t, freezeDelta(m))
		}); problem != nil {
			_ = attempt(func() {
				e.Call(D{"op": "backup_remove", "machine": m, "volid": backup["volid"], "note": backup["note"]})
			})
			panic(problem)
		}
		frozen := merge(without(m, "state", "power_state", "ssh_ready", "onboot", "resize", "readiness"), D{"state": "frozen", "frozen_at": time.Now().Unix(), "backup_volid": backup["volid"], "backup_storage": plan["storage"], "backup_bytes": backup["size"], "backup_note": backup["note"], "frozen_by": e.Op["id"]})
		e.Transaction(func(tx *Execution) {
			tx.Put("frozen", m["vmid"], n, frozen)
			m["state"] = "deleting"
			tx.Put("machines", m["vmid"], n, m)
		})
	}
	e.Call(D{"op": "action", "machine": m, "action": "delete", "confirm": m["name"]})
	e.P.invalidateInventory()
	e.Reconcile()
	e.Transaction(func(tx *Execution) {
		tx.S.Remove("guest_reports", m["vmid"])
		tx.S.Remove("machines", m["vmid"])
	})
	return D{"machine": e.PublicFrozen(e.S.Get("frozen", str(m["vmid"]))), "dry_run": false, "quota_after": e.Quota(t)}
}

func toDicts[T any](rows []T) []D {
	out := []D{}
	for _, r := range rows {
		out = append(out, decode(string(encoded(r))))
	}
	return out
}

// thawRecord is the machine a frozen one becomes on the node.
func thawRecord(f D, node nodeRef) D {
	m := node.record(without(f, "state", "frozen_at", "frozen_by", "backup_volid", "backup_storage", "backup_bytes", "backup_note", "thaw_node"))
	m["state"], m["power_state"], m["ssh_ready"], m["onboot"] = "stopped", "stopped", false, false
	return m
}

func (e *Execution) ThawMachine(a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	f := e.frozenMachine(t, a["machine"])
	if f == nil {
		// A thaw that restored the machine but could not remove its backup.
		if m := find(e.S.Objects("machines", n), func(m D) bool {
			return m["thaw_backup"] != nil && (str(m["vmid"]) == str(a["machine"]) || str(m["name"]) == str(a["machine"]))
		}); m != nil && !dry {
			e.Op["thaw"] = D{"vmid": m["vmid"], "cleanup": true}
			e.P.Operations.Save(e.Op)
			return D{"machine": D{"name": m["name"], "state": "thawing"}, "dry_run": false}
		}
		fail("not_found", "No frozen machine of this name in this tenant")
	}
	after := e.Quota(t, thawDelta(f))
	var node nodeRef
	var admission D
	if name := str(f["thaw_node"]); name != "" {
		// An interrupted thaw may have restored the machine there: only that node can finish it.
		ref, ok := e.nodeNamed(name)
		if !ok {
			fail("conflict", "The node of this machine's thaw is no longer configured", D{"recovery": "contact_administrator"})
		}
		node = ref
	} else {
		node, admission = e.Place(num(f["cpu"]), num(f["memory_mb"]), num(f["disk_gb"]))
	}
	if dry {
		return D{"machine": D{"name": f["name"], "state": "thaw_planned"}, "dry_run": true, "quota_after": after, "admission": admission}
	}
	if e.Op == nil {
		fail("internal", "A thaw runs as an operation")
	}
	// Written before the restore: from here a node may hold the machine, and
	// a retry or a delete must look there.
	f["thaw_node"] = node.Name
	e.Put("frozen", f["vmid"], n, f)
	e.Op["thaw"] = D{"vmid": f["vmid"]}
	e.P.Operations.Save(e.Op)
	return D{"machine": D{"name": f["name"], "state": "thawing"}, "dry_run": false, "quota_after": after}
}

// PerformThaw restores the machine without the writer lock.
func (e *Execution) PerformThaw() {
	if e.Op["tool"] != "machine_thaw" || e.Op["thaw"] == nil || boolean(obj(e.Op["thaw"])["cleanup"]) {
		return
	}
	f := e.S.Get("frozen", str(obj(e.Op["thaw"])["vmid"]))
	if f == nil {
		fail("not_found", "The frozen machine was deleted while thawing")
	}
	node, _ := e.nodeNamed(str(f["thaw_node"]))
	m := thawRecord(f, node)
	func() {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		e.Op["phase"] = "restoring_machine"
		e.P.Operations.Save(e.Op)
	}()
	e.Call(D{"op": "thaw", "machine": m, "volid": f["backup_volid"], "storage": f["backup_storage"]})
}

// FinishThaw records the restored machine, and only then removes the backup:
// until the live row is committed the backup is the only copy.
func (e *Execution) FinishThaw(t D) D {
	if e.Op["tool"] != "machine_thaw" || e.Op["thaw"] == nil {
		return D{}
	}
	plan, n := obj(e.Op["thaw"]), integer(t["n"])
	var m D
	if boolean(plan["cleanup"]) {
		m = e.S.Get("machines", str(plan["vmid"]))
		if m == nil {
			fail("not_found", "The machine was deleted while thawing")
		}
	} else {
		f := e.S.Get("frozen", str(plan["vmid"]))
		if f == nil {
			fail("not_found", "The frozen machine was deleted while thawing")
		}
		node, _ := e.nodeNamed(str(f["thaw_node"]))
		m = thawRecord(f, node)
		m["thaw_backup"] = D{"volid": f["backup_volid"], "note": f["backup_note"]}
		e.Transaction(func(tx *Execution) {
			tx.S.Remove("frozen", f["vmid"])
			tx.Put("machines", m["vmid"], n, m)
		})
		e.P.invalidateInventory()
	}
	backup := obj(m["thaw_backup"])
	e.Call(D{"op": "backup_remove", "machine": m, "volid": backup["volid"], "note": backup["note"]})
	delete(m, "thaw_backup")
	e.Put("machines", m["vmid"], n, m)
	e.Reconcile()
	return D{"machine": e.PublicMachine(m, e.ports(n)), "dry_run": false, "quota_after": e.Quota(t)}
}

// DeleteFrozen removes a frozen machine and its backup.
func (e *Execution) DeleteFrozen(f D, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	if a["confirm"] != f["name"] {
		fail("invalid", "confirm must equal the machine name")
	}
	delta := D{"ips": -1, "frozen_gb": -num(f["disk_gb"]), "public_ports": -len(filter(toDicts(e.ports(n)), func(p D) bool { return integer(p["vmid"]) == integer(f["vmid"]) }))}
	if !dry {
		if name := str(f["thaw_node"]); name != "" {
			// A thaw was begun: the machine may be restored there, wholly or in part.
			node, ok := e.nodeNamed(name)
			if !ok {
				fail("conflict", "The node of this machine's thaw is no longer configured", D{"recovery": "contact_administrator"})
			}
			e.Call(D{"op": "thaw", "machine": thawRecord(f, node), "volid": f["backup_volid"], "storage": f["backup_storage"], "discard": true})
			e.P.invalidateInventory()
		}
		e.Call(D{"op": "backup_remove", "machine": f, "volid": f["backup_volid"], "note": f["backup_note"]})
		e.removeApps(filter(e.S.Objects("apps", n), func(x D) bool { return integer(x["vmid"]) == integer(f["vmid"]) }))
		e.Transaction(func(tx *Execution) {
			tx.forgetMachine(n, f)
			tx.S.Remove("frozen", f["vmid"])
		})
		e.Reconcile()
	}
	q := e.Quota(t)
	if dry {
		q = e.Quota(t, delta)
	}
	r := D{"dry_run": dry, "quota_after": q}
	if !dry {
		r["deleted"] = D{"name": f["name"], "state": "deleted"}
	}
	return r
}
